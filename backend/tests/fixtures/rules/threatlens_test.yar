rule ThreatLens_Test_Suspicious_API_Strings
{
    meta:
        description = "Test-only harmless string matching fixture; not a production detection rule"
        severity = "low"
    strings:
        $a = "VirtualAlloc" ascii
        $b = "WriteProcessMemory" ascii
        $c = "CreateRemoteThread" ascii
    condition:
        2 of them
}
