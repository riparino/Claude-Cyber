# Shellcode Detection

## Shortcut

- YARA: scan process memory for NOP sleds, common shellcode prologs, and known payload markers.
- MDE: alert on executable memory allocations followed by thread creation in the allocated region.
- Process executing from memory regions not backed by a file on disk (non-image-backed execution).
- Common shellcode loaders: `VirtualAlloc` → `WriteProcessMemory` → `CreateThread` / `CreateRemoteThread`.
- Detect encoded shellcode delivery: base64/XOR blob decoded in PowerShell before execution.

---

## Detection Scope

| Technique | What to Detect |
|---|---|
| Shellcode injection | VirtualAlloc + Write + Execute chain |
| Process hollowing | Suspended process, unmapped + rewritten memory |
| NOP sled | Classic 0x90 NOP sled before payload |
| Staged shellcode | Stager downloading second stage from C2 |
| Shellcode in macro | VBA calling VirtualAlloc or CreateThread via WinAPI |
| Fileless shellcode | Executed from memory; no disk artifact |

---

## YARA — Shellcode Artifacts

```yara
rule Shellcode_NOP_Sled {
    meta:
        description = "NOP sled preceding shellcode"
    strings:
        $nop_sled = { 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 }
    condition:
        $nop_sled
}

rule Shellcode_Common_Prologs {
    meta:
        description = "Common shellcode prologs for x86/x64"
    strings:
        $x86_prolog1 = { FC E8 ?? 00 00 00 }   // common GetPC prolog
        $x86_prolog2 = { 6A 00 6A 00 68 }       // push push push
        $x64_prolog  = { 48 31 C9 48 81 E9 }    // xor rcx,rcx; sub rcx,imm
        $getpc       = { E8 00 00 00 00 5? }     // call $+5; pop reg
    condition:
        2 of them
}

rule Metasploit_Payload_Marker {
    meta:
        description = "Metasploit-style reverse shell markers"
        author = "claude-blue"
    strings:
        $msf1 = { FC E8 89 00 00 00 60 89 E5 }  // Metasploit x86 prolog
        $msf2 = "EXITFUNC=thread" ascii
        $msf3 = { 64 A1 30 00 00 00 }            // FS:[0x30] PEB access
    condition:
        any of them
}

rule Process_Hollowing_Markers {
    meta:
        description = "Process hollowing API strings in memory"
    strings:
        $s1 = "NtUnmapViewOfSection" ascii
        $s2 = "ZwUnmapViewOfSection" ascii
        $s3 = "SetThreadContext" ascii
        $s4 = "ResumeThread" ascii
    condition:
        3 of them
}

rule Cobalt_Strike_Beacon_Marker {
    meta:
        description = "Cobalt Strike beacon memory markers"
        reference = "CS beacon config parsing"
    strings:
        $cs1 = { 69 68 69 68 69 6B }   // ihi hikhi beacon marker
        $cs2 = { 2E 2E 2E 00 00 00 }   // default CS watermark
        $cs3 = "MZ" ascii
        $cfg = { 00 00 00 00 00 00 00 00 00 01 00 00 00 00 00 00 }  // CS config block start
    condition:
        2 of ($cs*, $cfg)
}
```

---

## Sigma Rules

### VirtualAlloc → WriteProcessMemory → CreateThread Injection Chain

```yaml
title: Classic Shellcode Injection Chain via Windows API
id: a8b9c0d1-e2f3-4567-abcd-890123456046
status: experimental
description: >
  Detects VirtualAlloc + WriteProcessMemory + CreateRemoteThread chain
  used for shellcode injection. Requires Sysmon or API call monitoring.
author: claude-blue
date: 2026-04-27
logsource:
  product: windows
  service: sysmon
detection:
  selection_alloc:
    EventID: 10     # ProcessAccess
    CallTrace|contains: 'VirtualAlloc'
  # Pair with EventID 8 (CreateRemoteThread) from same source process
  condition: selection_alloc
falsepositives:
  - Some legitimate applications and security tools
level: high
tags:
  - attack.t1055.001
```

### PowerShell Shellcode Delivery (Base64 + Memory Execution)

```yaml
title: PowerShell Loading Shellcode from Base64 String
id: b9c0d1e2-f3a4-5678-bcde-901234567047
status: experimental
description: >
  Detects PowerShell loading shellcode via base64 decode followed by
  memory allocation and execution using WinAPI calls.
author: claude-blue
date: 2026-04-27
logsource:
  product: windows
  service: powershell
  definition: Script Block Logging enabled
detection:
  selection:
    EventID: 4104
    ScriptBlockText|contains:
      - 'VirtualAlloc'
      - 'VirtualAllocEx'
  selection_shellcode:
    ScriptBlockText|contains:
      - 'FromBase64String'
      - '[Convert]::'
  condition: selection and selection_shellcode
falsepositives:
  - None expected in production
level: critical
tags:
  - attack.t1059.001
  - attack.t1055.001
```

---

## KQL — MDE

### Non-Image-Backed Process Execution (Fileless)

```kusto
DeviceEvents
| where ActionType == "ProcessCreatedUsingWmiQuery"
    or ActionType == "CreateRemoteThreadApiCall"
    or ActionType == "ShellcodeWrite"
| project TimeGenerated, DeviceName, AccountName, InitiatingProcessFileName,
          InitiatingProcessCommandLine, ActionType, AdditionalFields
| order by TimeGenerated desc
```

### PowerShell Allocating Executable Memory

```kusto
DeviceEvents
| where ActionType == "PowerShellCommand"
| where AdditionalFields has "VirtualAlloc"
    or AdditionalFields has "CreateThread"
    or AdditionalFields has "WriteProcessMemory"
| project TimeGenerated, DeviceName, AccountName, AdditionalFields
| order by TimeGenerated desc
```

### MDE: Remote Thread Creation in Common Targets

```kusto
DeviceEvents
| where ActionType == "CreateRemoteThreadApiCall"
| extend TargetProcess = tostring(parse_json(AdditionalFields).TargetProcessName)
| where TargetProcess in~ ("notepad.exe", "explorer.exe", "svchost.exe",
                             "lsass.exe", "RuntimeBroker.exe")
| project TimeGenerated, DeviceName, InitiatingProcessFileName, TargetProcess,
          InitiatingProcessCommandLine
| order by TimeGenerated desc
```

---

## Response Checklist

| Step | Action |
|---|---|
| 1 | Memory dump the target process immediately (volatile evidence) |
| 2 | YARA scan all running process memory for shellcode signatures |
| 3 | Identify the loader: document VirtualAlloc → Write → Execute chain |
| 4 | Check network connections from the injected process (C2 beacon) |
| 5 | Block C2 IP/domain at network perimeter |
| 6 | Collect full memory dump of system before shutdown |
| 7 | Isolate endpoint; escalate to IR team |

---

## MITRE ATT&CK

| Technique | ID | Coverage |
|---|---|---|
| Process Injection | T1055 | Shellcode injection into remote process |
| Process Hollowing | T1055.012 | Hollowing + shellcode |
| PowerShell | T1059.001 | Shellcode via PowerShell loader |
| Reflective DLL | T1055.001 | Reflective shellcode loading |
