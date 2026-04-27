---
name: defensive-shellcode
description: "Shellcode detection: YARA for NOP sleds, Metasploit prologs, Cobalt Strike beacon markers, process hollowing API patterns. Sigma for VirtualAlloc injection chain and PowerShell shellcode loaders. KQL for MDE remote thread creation and non-image-backed execution. Use for memory forensics, SOC triage, and DFIR."
---

# SKILL: Shellcode Detection

## Metadata
- **Skill Name**: defensive-shellcode
- **Folder**: Skills/defensive-shellcode
- **Source**: sources/defensive-checklist/shellcode.md
- **Mirrors**: offensive-shellcode

## Trigger Phrases
Use this skill when the conversation involves any of:
`shellcode detection, YARA shellcode, Cobalt Strike detection, beacon detection, NOP sled YARA, process injection shellcode, VirtualAlloc detection, PowerShell shellcode loader, fileless detection, non-image-backed execution`

## Instructions for Claude

When this skill is active:
1. YARA is the primary detection mechanism — provide rules for NOP sleds, CS beacon, process hollowing
2. Memory dump the target process immediately (volatile evidence)
3. KQL for MDE CreateRemoteThread and PowerShell-based VirtualAlloc calls
4. Check network connections from injected process — C2 beacon indicator
5. Block C2 IP/domain at perimeter before remediation

---

## Full Methodology

# Shellcode Detection

## Shortcut

- YARA scan running process memory for NOP sleds, CS beacon markers, and shellcode prologs.
- PowerShell + `VirtualAlloc` + `CreateThread` in same script = shellcode loader.
- Non-image-backed executable memory = fileless shellcode execution.
- Remote thread creation in `notepad.exe`, `explorer.exe`, `svchost.exe` = injection.

---

## YARA (Key Rules)

```yara
rule Shellcode_NOP_Sled {
    meta:
        description = "NOP sled preceding shellcode"
    strings:
        $nop_sled = { 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 }
    condition:
        $nop_sled
}

rule Metasploit_Payload_Marker {
    meta:
        description = "Metasploit x86 reverse shell prolog"
    strings:
        $msf1 = { FC E8 89 00 00 00 60 89 E5 }
        $msf2 = "EXITFUNC=thread" ascii
    condition:
        any of them
}

rule Cobalt_Strike_Beacon_Marker {
    meta:
        description = "Cobalt Strike beacon memory markers"
    strings:
        $cs1 = { 69 68 69 68 69 6B }
        $cs2 = { 2E 2E 2E 00 00 00 }
    condition:
        2 of ($cs*)
}

rule Process_Hollowing_Markers {
    meta:
        description = "Process hollowing API strings"
    strings:
        $s1 = "NtUnmapViewOfSection" ascii
        $s2 = "ZwUnmapViewOfSection" ascii
        $s3 = "SetThreadContext" ascii
        $s4 = "ResumeThread" ascii
    condition:
        3 of them
}
```

---

## KQL — MDE

### Remote Thread Creation in Common Targets

```kusto
DeviceEvents
| where ActionType == "CreateRemoteThreadApiCall"
| extend TargetProcess = tostring(parse_json(AdditionalFields).TargetProcessName)
| where TargetProcess in~ ("notepad.exe", "explorer.exe", "svchost.exe", "lsass.exe")
| project TimeGenerated, DeviceName, InitiatingProcessFileName, TargetProcess,
          InitiatingProcessCommandLine
| order by TimeGenerated desc
```

### PowerShell Shellcode Loader (VirtualAlloc + CreateThread)

```kusto
DeviceEvents
| where ActionType == "PowerShellCommand"
| where AdditionalFields has "VirtualAlloc" and AdditionalFields has "CreateThread"
| project TimeGenerated, DeviceName, AccountName, AdditionalFields
| order by TimeGenerated desc
```

---

## Response Checklist

| Step | Action |
|---|---|
| 1 | Memory dump target process (volatile evidence) |
| 2 | YARA scan all process memory |
| 3 | Identify loader: VirtualAlloc → Write → Execute chain |
| 4 | Check network: C2 beacon from injected process |
| 5 | Block C2 IP/domain at perimeter |
| 6 | Isolate endpoint; engage IR team |

---

## MITRE ATT&CK

| Technique | ID | Coverage |
|---|---|---|
| Process Injection | T1055 | Shellcode injection |
| Process Hollowing | T1055.012 | Hollow + shellcode |
| PowerShell | T1059.001 | PS shellcode loader |
