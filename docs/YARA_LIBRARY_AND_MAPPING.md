# YARA Library, Rule Management, Live Scanning, and Risk Mapping

## Engine vs ruleset
YARA is a matching engine and rule language; it does not include a universal up-to-date malware database. The production rules directory is empty by default. Test-only rules are isolated under `backend/tests/fixtures/rules/` and are not installed in the runtime image. The official engine/documentation and the community rule repository are separate projects:
- Engine: https://github.com/VirusTotal/yara
- Rule-writing reference: https://yara.readthedocs.io/en/latest/writingrules.html
- Community collection (review source/license before use): https://github.com/Yara-Rules/rules

## Scan path
Every accepted upload is passed as raw bytes to the local YARA scan. The backend recursively discovers `.yar` and `.yara` files, compiles them individually, attempts to match with a timeout, and records rule name, namespace, tags, metadata, source file and matched-string identifiers/instances when exposed by the installed YARA version. Compilation and matching errors are returned separately. `rules_evaluated` is the count of compiled rule definitions that the runtime exposes; it may be incomplete if compilation fails or a runtime version does not expose counts.

## Rule syntax example
```yara
rule Example_Suspicious_Combination : demo
{
  meta:
    description = "Illustrative pattern, not proof of malware"
    severity = "medium"
    source = "local test rule"
    version = "1.0"
    license = "internal test"
  strings:
    $a = "VirtualAlloc" ascii
    $b = "WriteProcessMemory" ascii
    $c = "CreateRemoteThread" ascii
  condition:
    2 of them
}
```
- `rule` declares the rule identifier; tags after `:` aid filtering.
- `meta` documents provenance and intended meaning. Metadata does not change matching.
- `strings` declares byte/string patterns; modifiers affect encoding/case behavior.
- `condition` determines when the rule matches. More complex conditions can combine byte offsets, sizes, file types, string counts and boolean operators.

## Add/update rules safely
Administrator → Rule Updates can upload a `.yar`/`.yara` file or a ZIP ruleset. Single files are limited to 1 MB. ZIP imports are limited to 20 MB compressed, 50 MB expanded and 500 rule files; paths are checked against traversal and all included rules are compiled before any files are written. A manifest records source, version/revision, license, import time, file hashes and rule counts. Rule removal is restricted to files inside the local rules directory; rules can be removed by administrators. No upstream repository is automatically fetched. Maintain a reviewed ruleset manifest with upstream URL, revision/commit, license, retrieval date, reviewer, test fixtures and expected match results. Avoid mixing sources with incompatible licenses or unknown provenance.

## Worked interpretation
No signature matches are possible until a ruleset is installed. Review provenance, licensing, rule behavior and false-positive rates before production use. A match is evidence for triage, not proof of execution or family attribution; no match does not establish safety.

## Match rate and risk mapping
The reported rate is unique matched rule identities divided by successfully counted rule definitions, multiplied by 100. It is a descriptive ruleset match ratio, **not a malware probability**, detection rate, recall, or accuracy. A large collection of irrelevant rules can lower this ratio; overlapping rules can create multiple hits for one underlying behavior.

ThreatLens keeps raw YARA evidence and ML output in separate result fields. The risk engine deduplicates matched rule identities and caps the YARA component at 30 points. Severity metadata affects the component weights. The final score is a capped additive heuristic; YARA, suspicious strings, PE imports and ML predictions can be correlated, so it is not a calibrated probability. The result exposes component values and the scoring method.

## Test requirements
The automated suite tests the engine with a harmless rule fixture stored only under `backend/tests/fixtures/rules/`. For operations, test your installed ruleset against its approved harmless positive and negative fixtures. Record the SHA-256 of each fixture, YARA version, rule source/version, expected rule names, actual match names and compile errors. Do not use live malware on a regular workstation.
