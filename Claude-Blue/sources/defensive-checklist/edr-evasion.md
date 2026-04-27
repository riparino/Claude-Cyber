# EDR Evasion Detection

## Shortcut

- Detect direct syscall patterns: PE with `NtAllocateVirtualMemory`/`NtWriteVirtualMemory` not going through `ntdll.dll` exports.
- PPID spoofing: process whose parent process ID does not match the actual parent image.
- AMSI bypass: PowerShell disabling AMSI via `amsiInitFailed` or patching `amsi.dll`.
- ETW patching: process writing to known ETW provider GUIDs.
- Reflective DLL injection: PE header in non-image-backed memory.
- `unhooking`: process reading `ntdll.dll` from disk to overwrite in-memory hooks.

---

## Detection Scope

| Technique | What to Detect |
|---|---|
| Direct syscalls | Syscall stubs outside `ntdll.dll` |
| PPID spoofing | Parent PID doesn't match parent image at process creation |
| AMSI bypass | `amsiInitFailed` in PowerShell, `amsi.dll` writes |
| ETW patching | Process modifying ETW provider |
| Unhooking | `ntdll.dll` read from disk into target process |
| Process injection | Memory allocation + write + execute in remote process |
| Reflective injection | PE in non-backed memory |

---

## Log Sources

| Source | Content | Platform |
|---|---|---|
| MDE DeviceEvents | Injection, AMSI, ETW events | MDE |
| MDE DeviceProcessEvents | PPID anomalies, process creation | MDE |
| Sysmon EventID 1, 8, 10 | Process create, CreateRemoteThread, ReadProcessMemory | Windows |
| PowerShell Script Block Logging | Obfuscated PowerShell, AMSI bypass code | Windows |
| Windows Security EventID 4688 | Process creation (parent/child) | Windows |

---

## Sigma Rules

### PPID Spoofing Detection

```yaml
title: PPID Spoofing - Process Created with Unexpected Parent
id: d5e6f7a8-b9c0-1234-defa-567890123043
status: experimental
description: >
  Detects processes with a PPID that doesn't correspond to a legitimate parent
  for that child binary — PPID spoofing is used to bypass parent-child process
  chain behavioral detections.
author: claude-blue
date: 2026-04-27
logsource:
  product: windows
  category: process_creation
detection:
  # High-fidelity combos: common PPID spoofing patterns
  selection_spoofed_1:
    Image|endswith: '\powershell.exe'
    ParentImage|endswith:
      - '\svchost.exe'  # Spoofing svchost as parent
      - '\lsass.exe'
  selection_spoofed_2:
    Image|endswith: '\cmd.exe'
    ParentImage|endswith:
      - '\lsass.exe'
      - '\smss.exe'
  condition: 1 of selection_spoofed_*
falsepositives:
  - Specific automation tools that use process spawning APIs (baseline)
level: high
tags:
  - attack.t1134.004
  - attack.defense_evasion
```

### AMSI Bypass in PowerShell Script Block

```yaml
title: AMSI Bypass Pattern in PowerShell Script Block
id: e6f7a8b9-c0d1-2345-efab-678901234044
status: experimental
description: >
  Detects AMSI bypass techniques in PowerShell script blocks including
  amsiInitFailed manipulation and DLL patching approaches.
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
      - 'amsiInitFailed'
      - 'AmsiScanBuffer'
      - 'amsi.dll'
      - '[Ref].Assembly.GetType'
      - 'NonPublic,Static'
  condition: selection
falsepositives:
  - Security tool testing scripts (allowlist)
level: high
tags:
  - attack.t1562.001
  - attack.defense_evasion
```

### Process Injection: CreateRemoteThread (Sysmon EventID 8)

```yaml
title: CreateRemoteThread into Non-System Process
id: f7a8b9c0-d1e2-3456-fabc-789012345045
status: experimental
description: >
  Detects CreateRemoteThread targeting non-system processes — classic
  DLL injection and shellcode injection technique.
author: claude-blue
date: 2026-04-27
logsource:
  product: windows
  service: sysmon
  definition: Sysmon EventID 8 (CreateRemoteThread) enabled
detection:
  selection:
    EventID: 8
    TargetImage|contains:
      - '\notepad.exe'
      - '\explorer.exe'
      - '\svchost.exe'
  filter_known_tools:
    SourceImage|endswith:
      - '\AcroRd32.exe'  # Allowlist legitimate cross-process tooling
  condition: selection and not filter_known_tools
falsepositives:
  - Some AV and endpoint monitoring tools (allowlist)
level: high
tags:
  - attack.t1055
  - attack.defense_evasion
```

---

## YARA — EDR Evasion Artifacts

```yara
rule Direct_Syscall_Stub {
    meta:
        description = "Direct syscall stub - syscall instruction with system call number load"
    strings:
        $syscall = { 4C 8B D1 B8 ?? 00 00 00 0F 05 }  // mov r10, rcx; mov eax, <num>; syscall
        $syscall2 = { B8 ?? 00 00 00 4C 8B D1 0F 05 }
    condition:
        any of them
}

rule AMSI_Patch_Artifact {
    meta:
        description = "AMSI patch — patching AmsiScanBuffer return value"
    strings:
        $patch1 = { B8 57 00 07 80 C3 }  // mov eax, 0x80070057; ret (AMSI_E_INVALIDARG)
        $patch2 = { 31 C0 C3 }            // xor eax, eax; ret (return 0)
        $amsi   = "amsi.dll" nocase ascii wide
    condition:
        $amsi and 1 of ($patch*)
}

rule Reflective_DLL_Injection {
    meta:
        description = "Reflective DLL injection - ReflectiveDLLInjection marker"
    strings:
        $marker = "ReflectiveLoader" ascii
        $mz     = { 4D 5A }
    condition:
        $marker and $mz
}

rule NtDll_Unhooking {
    meta:
        description = "ntdll.dll being read from disk for unhooking"
    strings:
        $ntdll  = "\\ntdll.dll" wide ascii
        $read   = "NtReadFile" ascii
        $open   = "\\KnownDlls\\ntdll.dll" wide
    condition:
        ($ntdll or $open) and $read
}
```

---

## KQL — MDE

### AMSI Bypass: PowerShell Disabling Scan Buffer

```kusto
DeviceEvents
| where ActionType == "PowerShellCommand"
| where AdditionalFields has_any (
    "amsiInitFailed", "AmsiScanBuffer", "amsi.dll",
    "[Ref].Assembly.GetType"
  )
| project TimeGenerated, DeviceName, AccountName, AdditionalFields
| order by TimeGenerated desc
```

### Process Injection via CreateRemoteThread

```kusto
DeviceEvents
| where ActionType == "CreateRemoteThreadApiCall"
| where not(InitiatingProcessFileName in~ ("MsMpEng.exe", "mssense.exe"))
| project TimeGenerated, DeviceName, InitiatingProcessFileName,
          InitiatingProcessCommandLine, AdditionalFields
| order by TimeGenerated desc
```

### PPID Spoofing: Process with Unexpected Parent

```kusto
DeviceProcessEvents
| where FileName =~ "powershell.exe" or FileName =~ "cmd.exe"
| where InitiatingProcessFileName in~ ("lsass.exe", "smss.exe", "csrss.exe")
| project TimeGenerated, DeviceName, FileName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessId
| order by TimeGenerated desc
```

---

## Response Checklist

| Step | Action |
|---|---|
| 1 | AMSI bypass: collect script block logs; identify payload that followed |
| 2 | Process injection: memory dump of target process immediately |
| 3 | PPID spoof: trace actual process lineage via MDE process tree |
| 4 | Check for persistence installed post-evasion |
| 5 | Escalate: EDR evasion + injection = likely advanced threat |
| 6 | Enable all available MDE behavioral sensors; increase telemetry level |

---

## MITRE ATT&CK

| Technique | ID | Coverage |
|---|---|---|
| Process Injection | T1055 | Remote thread, reflective DLL |
| Impersonate Token | T1134.004 | PPID spoofing |
| Disable Security Tools | T1562.001 | AMSI/ETW bypass |
| Obfuscated Files | T1027 | Encoded payloads |
