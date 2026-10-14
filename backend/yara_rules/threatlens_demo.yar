rule ThreatLens_Demo_Suspicious_API_Strings
{
    meta:
        description = "Illustrative rule only; generic API strings are not proof of malware"
        severity = "low"
        confidence = "low"
    strings:
        $a = "VirtualAlloc" ascii
        $b = "WriteProcessMemory" ascii
        $c = "CreateRemoteThread" ascii
    condition:
        2 of them
}
