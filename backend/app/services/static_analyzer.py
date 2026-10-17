import hashlib, math, re, ipaddress, mimetypes
from collections import Counter
from pathlib import Path
from app.core.config import settings
from app.services.ml_service import predict

URL_RE = re.compile(rb"https?://[^\s\"'<>]{4,}", re.I)
IP_RE = re.compile(rb"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
STR_RE = re.compile(rb"[\x20-\x7e]{5,}")
SUSPICIOUS_APIS = {"VirtualAlloc","VirtualAllocEx","WriteProcessMemory","CreateRemoteThread","WinExec","ShellExecuteA","ShellExecuteW","URLDownloadToFileA","InternetOpenA","InternetConnectA","CryptUnprotectData"}

def entropy(data):
    if not data: return 0.0
    counts = Counter(data); n = len(data)
    return -sum((v/n)*math.log2(v/n) for v in counts.values())

def yara_scan(data):
    folder = Path(settings.yara_rules_dir)
    if not folder.is_absolute(): folder = Path.cwd()/folder
    rulefiles = sorted([p for p in folder.rglob('*') if p.is_file() and p.suffix.lower() in {'.yar', '.yara'}]) if folder.exists() else []
    if not rulefiles: return [], "No YARA rule files found", {"rule_files_found":0,"rules_evaluated":0,"rules_matched":0,"match_rate_percent":0.0,"status":"no_rules"}
    try: import yara
    except Exception as exc: return [], f"YARA engine unavailable: {exc}", {"rule_files_found":len(rulefiles),"rules_evaluated":0,"rules_matched":0,"match_rate_percent":0.0,"status":"engine_unavailable"}
    matches=[]; errors=[]; evaluated=0; compiled_files=0
    for rf in rulefiles:
        try:
            rules = yara.compile(filepath=str(rf)); compiled_files += 1
            try: evaluated += len(rules.rules)
            except Exception: pass
            for m in rules.match(data=data, timeout=5):
                strings=[]
                for st in (getattr(m, "strings", []) or [])[:40]:
                    try:
                        identifier = getattr(st, "identifier", None)
                        if identifier:
                            strings.append({"identifier": identifier, "instances": []})
                            # yara-python >= 4.3 exposes StringMatch.instances; older versions may expose tuples.
                            try:
                                instances = []
                                for inst in (getattr(st, "instances", []) or [])[:10]:
                                    raw = getattr(inst, "matched_data", b"") or b""
                                    instances.append({"offset": getattr(inst, "offset", None), "length": getattr(inst, "matched_length", len(raw)), "matched_data_preview": raw[:80].decode("utf-8", "replace")})
                                strings[-1]["instances"] = instances
                            except Exception:
                                pass
                        else:
                            strings.append({"identifier": str(st), "instances": []})
                    except Exception:
                        pass
                matches.append({"rule":m.rule,"namespace":getattr(m,"namespace",""),"tags":list(getattr(m,"tags",[]) or []),"meta":dict(getattr(m,"meta",{}) or {}),"strings":strings,"source_file":str(rf.relative_to(folder)).replace('\\','/')})
        except Exception as exc: errors.append(f"{rf.name}: {exc}")
    # A matched-rule rate is descriptive coverage, not a malware probability.
    unique_matches=len({(m['source_file'],m['namespace'],m['rule']) for m in matches})
    rate=round((unique_matches/evaluated)*100,2) if evaluated else 0.0
    summary={"rule_files_found":len(rulefiles),"rule_files_compiled":compiled_files,"rules_evaluated":evaluated,"rules_matched":unique_matches,"match_rate_percent":rate,"match_rate_definition":"unique matched (source, namespace, rule) identities / total rule definitions evaluated; descriptive coverage only, not malware probability","status":"partial_errors" if errors else "completed"}
    return matches, "; ".join(errors) if errors else None, summary

def parse_pe(data):
    out={"is_pe":data[:2]==b"MZ","machine":None,"timestamp":None,"subsystem":None,"sections":[],"imports":[]}
    if not out["is_pe"]: return out
    try:
        import pefile
        pe=pefile.PE(data=data, fast_load=False)
        out["machine"]=hex(pe.FILE_HEADER.Machine); out["timestamp"]=int(pe.FILE_HEADER.TimeDateStamp)
        try: out["subsystem"]=int(pe.OPTIONAL_HEADER.Subsystem)
        except Exception: pass
        for sec in pe.sections:
            out["sections"].append({"name":sec.Name.rstrip(b"\x00").decode("ascii","replace"),"virtual_size":int(sec.Misc_VirtualSize),"raw_size":int(sec.SizeOfRawData),"entropy":round(float(sec.get_entropy()),4)})
        for entry in getattr(pe,"DIRECTORY_ENTRY_IMPORT",[])[:100]:
            dll=entry.dll.decode("utf-8","replace") if entry.dll else ""
            for imp in entry.imports[:100]:
                name=imp.name.decode("utf-8","replace") if imp.name else f"ordinal_{imp.ordinal}"
                out["imports"].append({"dll":dll,"name":name})
    except Exception as exc: out["parse_error"]=str(exc)
    return out

def extract_pe_model_features(data):
    """Extract measured PE-header/section/import features used by the supplied 72-feature schema.

    Behavioral/registry/network telemetry is deliberately not synthesized here. If a different
    training schema requires those fields, predict() will report them missing and skip inference.
    """
    try:
        import pefile
        pe=pefile.PE(data=data, fast_load=False)
    except Exception:
        return {}
    out={}
    dos=pe.DOS_HEADER; fh=pe.FILE_HEADER; oh=pe.OPTIONAL_HEADER
    for name in ["e_magic","e_cblp","e_cp","e_crlc","e_cparhdr","e_minalloc","e_maxalloc","e_ss","e_sp","e_csum","e_ip","e_cs","e_lfarlc","e_ovno","e_oemid","e_oeminfo","e_lfanew"]:
        if hasattr(dos,name): out[name]=int(getattr(dos,name))
    for name in ["Machine","NumberOfSections","TimeDateStamp","PointerToSymbolTable","NumberOfSymbols","SizeOfOptionalHeader","Characteristics"]:
        if hasattr(fh,name): out[name]=int(getattr(fh,name))
    for name in ["Magic","MajorLinkerVersion","MinorLinkerVersion","SizeOfCode","SizeOfInitializedData","SizeOfUninitializedData","AddressOfEntryPoint","BaseOfCode","ImageBase","SectionAlignment","FileAlignment","MajorOperatingSystemVersion","MinorOperatingSystemVersion","MajorImageVersion","MinorImageVersion","MajorSubsystemVersion","MinorSubsystemVersion","SizeOfHeaders","CheckSum","SizeOfImage","Subsystem","DllCharacteristics","SizeOfStackReserve","SizeOfStackCommit","SizeOfHeapReserve","SizeOfHeapCommit","LoaderFlags","NumberOfRvaAndSizes"]:
        if hasattr(oh,name): out[name]=int(getattr(oh,name))
    imports=[]
    for entry in getattr(pe,"DIRECTORY_ENTRY_IMPORT",[]) or []:
        for imp in getattr(entry,"imports",[]) or []:
            imports.append((imp.name or b"").decode("utf-8","replace"))
    suspicious={"VirtualAlloc","VirtualProtect","VirtualProtectEx","WriteProcessMemory","CreateRemoteThread","NtWriteVirtualMemory","NtCreateThreadEx","WinExec","ShellExecuteA","ShellExecuteW","URLDownloadToFileA","URLDownloadToFileW","InternetOpenA","InternetOpenW","InternetConnectA","InternetConnectW","WinHttpOpen","WinHttpConnect","LoadLibraryA","LoadLibraryW","GetProcAddress","CreateProcessA","CreateProcessW","OpenProcess","RegSetValueA","RegSetValueW","RegCreateKeyA","RegCreateKeyW"}
    out["SuspiciousImportFunctions"]=sum(1 for x in imports if x in suspicious)
    sections=list(getattr(pe,"sections",[]) or [])
    names=[s.Name.rstrip(b"\x00").decode("ascii","replace").lower() for s in sections]
    packers=("upx","pack","themida","vmp","aspack","enigma")
    out["SuspiciousNameSection"]=int(any(n in {"upx0","upx1","upx2",".upx",".packed",".aspack",".adata",".themida",".vmp0",".vmp1",".vmp2",".enigma1",".enigma2"} or any(t in n for t in packers) for n in names))
    entropy_values=[float(s.get_entropy()) for s in sections]; raw=[int(s.SizeOfRawData) for s in sections]; virt=[int(s.Misc_VirtualSize) for s in sections]; physical=[int(getattr(s,"Misc_PhysicalAddress",0)) for s in sections]; virtual=[int(s.VirtualAddress) for s in sections]; pointers=[int(s.PointerToRawData) for s in sections]; chars=[int(s.Characteristics) for s in sections]
    def min_or_zero(v): return min(v) if v else 0
    def max_or_zero(v): return max(v) if v else 0
    out.update({"SectionsLength":len(sections),"SectionMinEntropy":min_or_zero(entropy_values),"SectionMaxEntropy":max_or_zero(entropy_values),"SectionMinRawsize":min_or_zero(raw),"SectionMaxRawsize":max_or_zero(raw),"SectionMinVirtualsize":min_or_zero(virt),"SectionMaxVirtualsize":max_or_zero(virt),"SectionMaxPhysical":max_or_zero(physical),"SectionMinPhysical":min_or_zero(physical),"SectionMaxVirtual":max_or_zero(virtual),"SectionMinVirtual":min_or_zero(virtual),"SectionMaxPointerData":max_or_zero(pointers),"SectionMinPointerData":min_or_zero(pointers),"SectionMaxChar":max_or_zero(chars),"SectionMainChar":chars[0] if chars else 0})
    dirs=list(getattr(oh,"DATA_DIRECTORY",[]) or [])
    def dir_size(i): return int(dirs[i].Size) if i<len(dirs) else 0
    def dir_rva(i): return int(dirs[i].VirtualAddress) if i<len(dirs) else 0
    import_dlls=len(getattr(pe,"DIRECTORY_ENTRY_IMPORT",[]) or [])
    export_count=len(getattr(getattr(pe,"DIRECTORY_ENTRY_EXPORT",None),"symbols",[]) or [])
    out["DirectoryEntryImport"]=import_dlls
    try:
        out["DirectoryEntryImportSize"]=dir_size(pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"])
        out["ImageDirectoryEntryExport"]=dir_rva(pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"])
        out["ImageDirectoryEntryImport"]=dir_rva(pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"])
        out["ImageDirectoryEntryResource"]=dir_rva(pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_RESOURCE"])
        out["ImageDirectoryEntryException"]=dir_rva(pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXCEPTION"])
        out["ImageDirectoryEntrySecurity"]=dir_rva(pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"])
    except Exception: pass
    out["DirectoryEntryExport"]=export_count

    # Adapter for static columns in the supplied 72-feature training schema.
    # Runtime registry/network/process/file telemetry is intentionally omitted.
    dos_map = {
        "EntryPoint": "e_ip", "magic_number": "e_magic", "bytes_on_last_page": "e_cblp",
        "pages_in_file": "e_cp", "relocations": "e_crlc", "size_of_header": "e_cparhdr",
        "min_extra_paragraphs": "e_minalloc", "max_extra_paragraphs": "e_maxalloc",
        "init_ss_value": "e_ss", "init_sp_value": "e_sp", "init_ip_value": "e_ip",
        "init_cs_value": "e_cs", "over_lay_number": "e_ovno", "oem_identifier": "e_oemid",
        "address_of_ne_header": "e_lfanew",
    }
    for target, source in dos_map.items():
        if hasattr(dos, source): out[target] = int(getattr(dos, source))
    out["file_extension"] = "pe"
    out["MachineType"] = int(fh.Machine)
    pe_magic=int(getattr(oh, "Magic", 0))
    out["PEType"] = "PE32+" if pe_magic == 0x20B else "PE32" if pe_magic == 0x10B else f"Unknown (0x{pe_magic:x})"
    entry_rva=int(getattr(oh, "AddressOfEntryPoint", 0))
    try:
        entry_section=pe.get_section_by_rva(entry_rva)
        section_label=entry_section.Name.rstrip(b"\x00").decode("ascii","replace") if entry_section else "?"
    except Exception:
        section_label="?"
    # The fitted categorical encoder was trained on this annotated RVA string form.
    out["AddressOfEntryPoint"]=f"0x{entry_rva:016x} (Section: {section_label})"
    out["OperatingSystemVersion"] = f"{int(getattr(oh, 'MajorOperatingSystemVersion', 0))}.{int(getattr(oh, 'MinorOperatingSystemVersion', 0))}"
    out["ImageVersion"] = f"{int(getattr(oh, 'MajorImageVersion', 0))}.{int(getattr(oh, 'MinorImageVersion', 0))}"
    # Preserve the exact casing used by feature_schema.json.
    aliases = {
        "Checksum": "CheckSum", "SizeofStackReserve": "SizeOfStackReserve",
        "SizeofStackCommit": "SizeOfStackCommit", "SizeofHeapCommit": "SizeOfHeapCommit",
        "SizeofHeapReserve": "SizeOfHeapReserve",
    }
    for target, source in aliases.items():
        if hasattr(oh, source): out[target] = int(getattr(oh, source))
    if hasattr(oh, "BaseOfData"): out["BaseOfData"] = int(oh.BaseOfData)
    section_by_name = {s.Name.rstrip(b"\x00").decode("ascii", "replace").strip().lower(): s for s in sections}
    for prefix, aliases in (("text", {".text", "text"}), ("rdata", {".rdata", "rdata"})):
        sec = next((section_by_name[name] for name in aliases if name in section_by_name), None)
        if sec is None: continue
        values = {
            "VirtualSize": int(sec.Misc_VirtualSize), "VirtualAddress": int(sec.VirtualAddress),
            "SizeOfRawData": int(sec.SizeOfRawData), "PointerToRawData": int(sec.PointerToRawData),
            "PointerToRelocations": int(sec.PointerToRelocations), "PointerToLineNumbers": int(sec.PointerToLinenumbers),
            "Characteristics": int(sec.Characteristics),
        }
        for suffix, value in values.items(): out[f"{prefix}_{suffix}"] = value
    out["dlls_calls"] = len(getattr(pe, "DIRECTORY_ENTRY_IMPORT", []) or [])
    out["apis"] = len(imports)
    return out

def analyze_file(filename, data):
    sha=hashlib.sha256(data).hexdigest(); md5=hashlib.md5(data).hexdigest()
    urls=sorted({x.decode("ascii","ignore")[:400] for x in URL_RE.findall(data)})[:100]
    ips=set()
    for raw in IP_RE.findall(data):
        try: ips.add(str(ipaddress.ip_address(raw.decode("ascii"))))
        except ValueError: pass
    strings=[x.group(0).decode("ascii","ignore") for x in STR_RE.finditer(data)][:250]
    pe=parse_pe(data); ym,yerr,ysummary=yara_scan(data)
    imports=pe.get("imports",[]); api_names=[x.get("name","") for x in imports]
    features={"file_size":len(data),"entropy":round(entropy(data),5),"is_pe":int(pe["is_pe"]),"section_count":len(pe["sections"]),"import_count":len(imports),"string_count":len(strings),"url_count":len(urls),"ip_count":len(ips),"suspicious_api_count":sum(x in SUSPICIOUS_APIS for x in api_names),"has_mz_header":int(data[:2]==b"MZ"),"has_pe_header_marker":int(b"PE\x00\x00" in data[:4096])}
    if pe["is_pe"]:
        features.update(extract_pe_model_features(data))
    # Extension is a static file property; unavailable runtime telemetry is never fabricated.
    features["file_extension"] = Path(filename).suffix.lower().lstrip(".") or "unknown"
    ml=predict(features)
    reasons=[]
    components={"entropy":0,"suspicious_apis":0,"network_indicators":0,"yara_evidence":0,"ml_evidence":0}
    if features["entropy"]>=7.2: components["entropy"]=15; reasons.append("High byte entropy (heuristic; compression can also cause this)")
    elif features["entropy"]>=6.7: components["entropy"]=7; reasons.append("Elevated byte entropy")
    if features["suspicious_api_count"]>=2: components["suspicious_apis"]=12; reasons.append("Multiple APIs from a heuristic suspicious-API list")
    elif features["suspicious_api_count"]==1: components["suspicious_apis"]=5; reasons.append("One API from a heuristic suspicious-API list")
    components["network_indicators"]=min(10, min(6,len(urls)*2)+min(4,len(ips)*2))
    if urls: reasons.append(f"{len(urls)} embedded URL indicator(s) observed")
    if ips: reasons.append(f"{len(ips)} IPv4 indicator(s) observed")
    # Deduplicate by source + namespace + rule before scoring so duplicate discovery paths do not multiply one rule.
    unique_matches={ (m.get("source_file"),m.get("namespace"),m.get("rule")):m for m in ym }
    yara_points=0
    for match in unique_matches.values():
        sev=str((match.get("meta") or {}).get("severity","medium")).lower()
        yara_points += 10 if sev in {"critical","high"} else 6 if sev=="medium" else 3
        reasons.append("YARA rule matched: "+str(match.get("rule","unknown")))
    components["yara_evidence"]=min(30,yara_points)
    if ml.get("available") and (ml.get("input_coverage") or {}).get("partial"):
        cov=ml["input_coverage"]
        reasons.append(f"Random Forest used partial static inputs ({cov.get('observed',0)}/{cov.get('expected',72)} observed); missing fields were filled by training-time imputers")
    if ml.get("available") and str(ml.get("label","" )).lower()=="malware":
        partial=bool((ml.get("input_coverage") or {}).get("partial"))
        components["ml_evidence"]=8 if partial else 15
        reasons.append("Random Forest predicted Malware (partial-input ML evidence is down-weighted; score is not calibrated or proof of malware)" if partial else "Random Forest predicted Malware (score is not calibrated and is not proof of malware)")
    risk=min(100,sum(components.values()))
    severity="critical" if risk>=80 else "high" if risk>=60 else "medium" if risk>=30 else "low"
    verdict="malicious_suspected" if risk>=60 else "suspicious" if risk>=30 else "no_strong_indicators"
    demo_evidence = {
        "mode": "display_only_simulation",
        "title": "Simulated threat indicators for UI demonstration",
        "notice": "The following strings are synthetic demonstration content. They were NOT extracted from the uploaded file, are NOT YARA matches, do NOT affect the risk score, and were never executed.",
        "indicators": [
            {"name": "Encoded-command marker", "value": "powershell.exe -EncodedCommand <REDACTED-DEMO>", "severity": "high"},
            {"name": "Persistence-like registry path", "value": r"HKCU\Software\DemoVendor\RunOnce", "severity": "medium"},
            {"name": "Network indicator placeholder", "value": "https://example.invalid/demo-beacon", "severity": "medium"},
        ],
        "code_preview": "\n".join([
            "// THREATLENS DISPLAY-ONLY DEMO — NOT EXECUTABLE",
            "// Simulated indicator: encoded command argument detected",
            "// Simulated behavior label: persistence-like registry reference",
            "// Simulated network marker: https://example.invalid/demo-beacon",
            "// No payload, persistence action, network request, or system change is performed.",
        ])
    }
    return {"filename":Path(filename).name,"sha256":sha,"md5":md5,"file_size":len(data),"file_type":mimetypes.guess_type(filename)[0] or ("windows-pe" if pe["is_pe"] else "unknown"),"verdict":verdict,"severity":severity,"risk_score":float(risk),"risk_components":components,"risk_method":"Capped additive static-triage heuristic; evidence can be correlated and score is not a calibrated probability","features":features,"ml_prediction":ml,"yara_matches":ym,"yara_error":yerr,"yara_summary":ysummary,"pe_analysis":pe,"indicators":{"urls":urls,"ips":sorted(ips)[:100],"strings":strings},"demo_evidence":demo_evidence,"reasons":reasons,"disclaimer":"Static triage only. Low risk does not prove safety; a heuristic or YARA match is not proof of malware."}
