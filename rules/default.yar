// Default threat-scanner rules.
// String patterns are hex/escaped on purpose: the scanner embeds this file, and
// plaintext signatures would make the scanner (and this file) detect itself.
// Required meta: threat (display name), category (malware | pup | hacktool | suspicious).

rule EICAR_Test_File
{
    meta:
        threat = "EICAR-Test-File"
        category = "malware"
        description = "Industry-standard harmless antivirus test file"
    strings:
        $eicar = { 58 35 4F 21 50 25 40 41 50 5B 34 5C 50 5A 58 35 34 28 50 5E 29 37 43 43 29 37 7D 24 45 49 43 41 52 2D 53 54 41 4E 44 41 52 44 2D 41 4E 54 49 56 49 52 55 53 2D 54 45 53 54 2D 46 49 4C 45 21 24 48 2B 48 2A }
    condition:
        $eicar at 0 and filesize < 256
}

rule ThreatScanner_Test_Marker
{
    meta:
        threat = "Test.ThreatScanner.Marker"
        category = "malware"
        description = "Harmless marker for testing this scanner end to end"
    strings:
        $marker = /\x54\x48\x52\x45\x41\x54\x2D\x53\x43\x41\x4E\x4E\x45\x52\x2D\x54\x45\x53\x54\x2D\x4D\x41\x52\x4B\x45\x52\x2D\x37\x46\x33\x41/
    condition:
        $marker
}

rule HackTool_Mimikatz
{
    meta:
        threat = "HackTool.Mimikatz"
        category = "hacktool"
        description = "Credential-dumping tool strings"
    strings:
        $cmd    = /\x73\x65\x6B\x75\x72\x6C\x73\x61\x3A\x3A\x6C\x6F\x67\x6F\x6E\x70\x61\x73\x73\x77\x6F\x72\x64\x73/ ascii wide nocase
        $author = /\x67\x65\x6E\x74\x69\x6C\x6B\x69\x77\x69/ ascii wide nocase
        $name   = /\x6D\x69\x6D\x69\x6B\x61\x74\x7A/ ascii wide nocase
    condition:
        2 of them
}

rule Suspicious_PowerShell_Downloader
{
    meta:
        threat = "Suspicious.PowerShell.Downloader"
        category = "suspicious"
        description = "Script that downloads and executes code in memory"
    strings:
        $download = /\x44\x6F\x77\x6E\x6C\x6F\x61\x64\x53\x74\x72\x69\x6E\x67/ ascii wide nocase
        $webclient = /\x4E\x65\x74\x2E\x57\x65\x62\x43\x6C\x69\x65\x6E\x74/ ascii wide nocase
        $invoke = /\x49\x6E\x76\x6F\x6B\x65\x2D\x45\x78\x70\x72\x65\x73\x73\x69\x6F\x6E/ ascii wide nocase
        $encoded = /\x2D\x45\x6E\x63\x6F\x64\x65\x64\x43\x6F\x6D\x6D\x61\x6E\x64/ ascii wide nocase
        $base64 = /\x46\x72\x6F\x6D\x42\x61\x73\x65\x36\x34\x53\x74\x72\x69\x6E\x67/ ascii wide nocase
    condition:
        filesize < 5MB and
        ((($download or $webclient) and $invoke) or ($encoded and $base64))
}

rule Ransom_Generic_Strings
{
    meta:
        threat = "Ransom.Generic.Strings"
        category = "malware"
        description = "Shadow-copy/backup destruction combined with a ransom note"
    strings:
        $vss = /\x76\x73\x73\x61\x64\x6D\x69\x6E\x20\x64\x65\x6C\x65\x74\x65\x20\x73\x68\x61\x64\x6F\x77\x73/ ascii wide nocase
        $wbadmin = /\x77\x62\x61\x64\x6D\x69\x6E\x20\x64\x65\x6C\x65\x74\x65\x20\x63\x61\x74\x61\x6C\x6F\x67/ ascii wide nocase
        $bcdedit = /\x72\x65\x63\x6F\x76\x65\x72\x79\x65\x6E\x61\x62\x6C\x65\x64\x20\x6E\x6F/ ascii wide nocase
        $note = /\x59\x4F\x55\x52\x20\x46\x49\x4C\x45\x53\x20\x48\x41\x56\x45\x20\x42\x45\x45\x4E\x20\x45\x4E\x43\x52\x59\x50\x54\x45\x44/ ascii wide nocase
    condition:
        ($note and any of ($vss, $wbadmin, $bcdedit)) or all of ($vss, $wbadmin, $bcdedit)
}

rule RiskWare_CoinMiner
{
    meta:
        threat = "RiskWare.CoinMiner"
        category = "pup"
        description = "Cryptocurrency miner configuration strings"
    strings:
        $pool = /\x73\x74\x72\x61\x74\x75\x6D\x2B\x74\x63\x70\x3A\x2F\x2F/ ascii wide nocase
        $miner = /\x78\x6D\x72\x69\x67/ ascii wide nocase
    condition:
        $pool and $miner
}
