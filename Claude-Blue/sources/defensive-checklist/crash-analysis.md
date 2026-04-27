# Crash Analysis — Detection & Defense

## Overview
WER (Windows Error Reporting) crash triage, exploitability scoring, memory dump workflow, exception code reference. KQL for MDE crash telemetry and WER EventID 1001.

## Shortcut

- EventID 1001 = WER crash report; ExceptionCode in event data.
- `ExceptionCode 0xc0000005` = access violation (NULL deref or OOB write).
- `ExceptionCode 0xc0000409` = GS stack cookie; attacker probed stack mitigation.
- `ExceptionCode 0xc000001d` = illegal instruction; DEP triggered.
- Faulting address at `0x41414141` = fill pattern; confirmed exploitation.
- Crash in `w3wp.exe`, `java.exe`, `nginx.exe`, `acrobat.exe` = high exploitability.

---

## Exception Code Reference

| Code | Name | Likely Cause |
|---|---|---|
| `0xc0000005` | ACCESS_VIOLATION | NULL deref, OOB read/write, Use-after-free |
| `0xc000001d` | ILLEGAL_INSTRUCTION | DEP triggered (code on data page) |
| `0xc0000409` | STACK_BUFFER_OVERRUN | GS stack cookie triggered |
| `0xc0000374` | HEAP_CORRUPTION | Heap overflow, double-free |
| `0xc00000FD` | STACK_OVERFLOW | Infinite recursion or deep stack |
| `0x80000003` | BREAKPOINT | Debug trap — not normally crash |
| `0xc0000094` | INTEGER_DIVIDE_BY_ZERO | Logic bug |

---

## Exploitability Scoring

| Factor | Low | High |
|---|---|---|
| Exception code | `0xc00000fd` (stack OVF) | `0xc0000005` + controlled IP |
| Process type | Background daemon | Network-facing (IIS, Java) |
| Faulting address | Mapped region | Fill pattern (`0x41414141`) |
| Crash rate | 1 crash | Repeated crashes same process |
| Reproducibility | Random | Consistent after same input |

---

## Memory Dump Workflow

1. Configure WER to collect full dumps:
   ```
   HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps
   DumpType = 2 (full dump)
   DumpFolder = C:\CrashDumps
   ```
2. Open dump in WinDbg: `!analyze -v`
3. Check faulting module and instruction:
   ```
   !analyze -v
   k   (call stack)
   r   (registers)
   .exr -1  (exception record)
   ```
4. Check if EIP/RIP is controlled:
   - `41414141` = fill pattern (attacker controlled)
   - Stack overwrite visible in `k` output

---

## KQL — MDE

### Crash in Network-Facing Process

```kusto
DeviceEvents
| where ActionType == "AppCrashed"
| where InitiatingProcessFileName in~ (
    "w3wp.exe", "java.exe", "httpd.exe", "nginx.exe",
    "mysqld.exe", "chrome.exe", "acrobat.exe", "acrord32.exe"
  )
| project TimeGenerated, DeviceName, InitiatingProcessFileName, AdditionalFields
| order by TimeGenerated desc
```

### High Crash Rate (Exploitation or Fuzzing)

```kusto
DeviceEvents
| where ActionType == "AppCrashed"
| summarize CrashCount=count() by DeviceName, InitiatingProcessFileName, bin(TimeGenerated, 1h)
| where CrashCount > 5
| order by CrashCount desc
```

### Crash Followed by Shell Spawn (Confirmed Exploitation)

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

---

## Response Checklist

| Step | Action |
|---|---|
| 1 | Collect crash dump; analyze with WinDbg `!analyze -v` |
| 2 | Check exception code against reference table |
| 3 | Faulting address at fill pattern: confirmed exploitation; patch immediately |
| 4 | Check post-crash processes for shell spawn |
| 5 | High crash rate: network block source IP; apply virtual patch via WAF |

---

## MITRE ATT&CK

| Technique | ID | Notes |
|---|---|---|
| Exploitation for Client Execution | T1203 | Crash analysis for client exploits |
| Exploitation of Remote Services | T1210 | Server-side crash triage |
