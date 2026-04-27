---
name: defensive-crash-analysis
description: "Crash analysis and exploitability triage: WER EventID 1001, exception code reference (0xc0000005, 0xc0000409, 0xc000001d), faulting address fill pattern detection, WinDbg workflow. KQL for MDE crash telemetry and crash-to-shell correlation. Use for SOC crash triage and vulnerability response."
---

# SKILL: Crash Analysis

## Metadata
- **Skill Name**: defensive-crash-analysis
- **Folder**: Skills/defensive-crash-analysis
- **Source**: sources/defensive-checklist/crash-analysis.md
- **Mirrors**: offensive-crash-analysis

## Trigger Phrases
Use this skill when the conversation involves any of:
`crash analysis, WER crash triage, exploitability scoring, exception code 0xc0000005, GS cookie exception, DEP violation, memory dump analysis, WinDbg crash, application crash KQL, crash exploitability`

## Instructions for Claude

When this skill is active:
1. Faulting address `0x41414141` = confirmed exploitation attempt; patch immediately
2. Exception `0xc0000409` (GS cookie) = stack canary triggered; attacker probing mitigations
3. Exception `0xc000001d` (illegal instruction) = DEP triggered; escalate to security team
4. KQL: join crash events with post-crash process creation (30s window) to confirm exploitation
5. WinDbg command: `!analyze -v` for automated exploitability hint

---

## Full Methodology

# Crash Analysis

## Shortcut

- `0xc0000005` (ACCESS_VIOLATION) = most common; check if faulting address is controlled.
- `0xc0000409` = GS cookie; attacker hit stack overflow; patch.
- `0xc000001d` = DEP; attacker tried to execute from data page.
- Faulting module in `ntdll!RtlFreeHeap` = heap corruption; check for heap spray.
- Faulting address `0x41414141` = fill pattern; confirmed exploit attempt.

---

## Exception Code Reference

| Code | Name | Action |
|---|---|---|
| `0xc0000005` | ACCESS_VIOLATION | Investigate faulting address |
| `0xc000001d` | ILLEGAL_INSTRUCTION | DEP triggered; patch immediately |
| `0xc0000409` | STACK_BUFFER_OVERRUN | Stack canary; patch immediately |
| `0xc0000374` | HEAP_CORRUPTION | Heap vulnerability; collect dump |
| `0xc00000FD` | STACK_OVERFLOW | Deep recursion or corruption |

---

## KQL — MDE

### Crash → Shell Correlation (Confirmed Exploitation)

```kusto
let Crashes = DeviceEvents
    | where ActionType == "AppCrashed"
    | project CrashTime=TimeGenerated, DeviceName, CrashedProcess=InitiatingProcessFileName;
let PostCrash = DeviceProcessEvents
    | where FileName in~ ("cmd.exe", "powershell.exe", "sh", "bash")
    | project ShellTime=TimeGenerated, DeviceName, FileName, ProcessCommandLine;
Crashes
| join kind=inner PostCrash on DeviceName
| where ShellTime between (CrashTime .. (CrashTime + 30s))
| project DeviceName, CrashedProcess, CrashTime, FileName, ProcessCommandLine
| order by CrashTime desc
```

### High-Value Process Crashes

```kusto
DeviceEvents
| where ActionType == "AppCrashed"
| where InitiatingProcessFileName in~ (
    "w3wp.exe", "java.exe", "nginx.exe", "httpd.exe", "mysqld.exe",
    "chrome.exe", "acrobat.exe"
  )
| project TimeGenerated, DeviceName, InitiatingProcessFileName, AdditionalFields
| order by TimeGenerated desc
```

---

## Response Checklist

| Step | Action |
|---|---|
| 1 | Collect crash dump (WER LocalDumps → full dump) |
| 2 | Open in WinDbg: `!analyze -v` → check exception code + faulting address |
| 3 | Fill pattern in EIP/RIP = confirmed exploitation; isolate host |
| 4 | Run crash→shell KQL correlation query |
| 5 | Apply patch or virtual patch (WAF rule) |

---

## MITRE ATT&CK

| Technique | ID | Coverage |
|---|---|---|
| Exploitation for Client Execution | T1203 | Client crash analysis |
| Exploitation of Remote Services | T1210 | Server crash triage |
