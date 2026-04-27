---
name: defensive-edr-evasion
description: "EDR evasion detection: PPID spoofing, AMSI bypass in PowerShell, CreateRemoteThread process injection, ETW patching, direct syscalls, ntdll unhooking. YARA for syscall stubs, AMSI patches, reflective DLL, unhooking artifacts. KQL for MDE process injection and AMSI events. Use for SOC triage and detection engineering."
---

# SKILL: EDR Evasion Detection

## Metadata
- **Skill Name**: defensive-edr-evasion
- **Folder**: Skills/defensive-edr-evasion
- **Source**: sources/defensive-checklist/edr-evasion.md
- **Mirrors**: offensive-edr-evasion

## Trigger Phrases
Use this skill when the conversation involves any of:
`EDR evasion detection, PPID spoofing detection, AMSI bypass detection, process injection detection, CreateRemoteThread Sigma, direct syscall YARA, ntdll unhooking detection, ETW patch detection, reflective DLL YARA`

## Instructions for Claude

When this skill is active:
1. AMSI bypass detected = escalate; unknown payload followed; collect script block logs immediately
2. CreateRemoteThread from non-security process = process injection; memory dump target process
3. PPID spoofing: process lineage doesn't match — trace real parent via MDE process tree
4. YARA primary for direct syscall stubs, AMSI patches, reflective DLL, ntdll unhooking
5. Escalate: EDR evasion + injection is an advanced threat indicator (APT, ransomware pre-stage)

---

## Full Methodology

# EDR Evasion Detection

## Shortcut

- AMSI bypass: `amsiInitFailed` or `AmsiScanBuffer` in PowerShell Event 4104.
- CreateRemoteThread into `explorer.exe`, `notepad.exe`, `svchost.exe` = injection.
- PPID spoof: `cmd.exe` or `powershell.exe` with parent `lsass.exe` or `smss.exe`.
- YARA scan process memory for syscall stubs, AMSI patch patterns, ReflectiveLoader.

---

## YARA (Key Rules)

```yara
rule AMSI_Patch_Artifact {
    meta:
        description = "AMSI patch — patching AmsiScanBuffer return value"
    strings:
        $patch1 = { B8 57 00 07 80 C3 }
        $patch2 = { 31 C0 C3 }
        $amsi   = "amsi.dll" nocase ascii wide
    condition:
        $amsi and 1 of ($patch*)
}

rule Reflective_DLL_Injection {
    meta:
        description = "ReflectiveDLLInjection marker"
    strings:
        $marker = "ReflectiveLoader" ascii
        $mz     = { 4D 5A }
    condition:
        $marker and $mz
}

rule Direct_Syscall_Stub {
    meta:
        description = "Direct syscall instruction with system call number load"
    strings:
        $syscall  = { 4C 8B D1 B8 ?? 00 00 00 0F 05 }
        $syscall2 = { B8 ?? 00 00 00 4C 8B D1 0F 05 }
    condition:
        any of them
}
```

---

## KQL — MDE

### AMSI Bypass in PowerShell

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

### CreateRemoteThread Injection

```kusto
DeviceEvents
| where ActionType == "CreateRemoteThreadApiCall"
| where not(InitiatingProcessFileName in~ ("MsMpEng.exe", "mssense.exe"))
| project TimeGenerated, DeviceName, InitiatingProcessFileName,
          InitiatingProcessCommandLine, AdditionalFields
| order by TimeGenerated desc
```

### PPID Spoofing

```kusto
DeviceProcessEvents
| where FileName =~ "powershell.exe" or FileName =~ "cmd.exe"
| where InitiatingProcessFileName in~ ("lsass.exe", "smss.exe", "csrss.exe")
| project TimeGenerated, DeviceName, FileName, ProcessCommandLine,
          InitiatingProcessFileName
| order by TimeGenerated desc
```

---

## Response Checklist

| Step | Action |
|---|---|
| 1 | AMSI bypass: collect script block logs; identify payload |
| 2 | Injection detected: memory dump target process immediately |
| 3 | PPID spoof: trace real process lineage in MDE process tree |
| 4 | Hunt persistence post-evasion |
| 5 | Escalate: advanced threat — engage IR team |

---

## MITRE ATT&CK

| Technique | ID | Coverage |
|---|---|---|
| Process Injection | T1055 | Remote thread, reflective DLL |
| Access Token Manipulation: PPID Spoof | T1134.004 | PPID spoofing |
| Disable Security Tools | T1562.001 | AMSI/ETW bypass |

---

## References & Verified Sources

**MITRE ATT&CK**
- T1055 Process Injection: https://attack.mitre.org/techniques/T1055/
- T1134 Access Token Manipulation: https://attack.mitre.org/techniques/T1134/
- T1134.004 PPID Spoofing: https://attack.mitre.org/techniques/T1134/004/
- T1562.001 Disable or Modify Tools: https://attack.mitre.org/techniques/T1562/001/
- T1620 Reflective Code Loading: https://attack.mitre.org/techniques/T1620/

**Detection tables / docs**
- `DeviceImageLoadEvents`: https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceimageloadevents-table
- `DeviceEvents`: https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceevents-table
- AMSI overview: https://learn.microsoft.com/en-us/windows/win32/amsi/antimalware-scan-interface-portal
- ETW (Event Tracing for Windows): https://learn.microsoft.com/en-us/windows/win32/etw/event-tracing-portal

**Detection content**
- Elastic detection rules (defense_evasion): https://github.com/elastic/detection-rules/tree/main/rules/windows/defense_evasion
- SigmaHQ defense_evasion rules: https://github.com/SigmaHQ/sigma/tree/master/rules/windows/process_creation
- Red Canary Atomic Red Team T1055: https://github.com/redcanaryco/atomic-red-team/tree/master/atomics/T1055

**Background research**
- "Hells Gate" / direct syscalls (am0nsec & smelly__vx): https://github.com/am0nsec/HellsGate
- "Bring Your Own Vulnerable Driver" (BYOVD) — CVE-2023-21768 etc.: https://nvd.nist.gov/vuln/detail/CVE-2023-21768
