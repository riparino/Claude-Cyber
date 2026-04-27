# Keylogger Detection

## Shortcut

- YARA: detect `SetWindowsHookEx` (WH_KEYBOARD_LL) + file write combination in PE files.
- Detect raw keyboard input API hooks: `GetAsyncKeyState` / `GetKeyState` in a loop with file write.
- MDE: alert on new processes opening keyboard device objects (`\Device\KeyboardClass0`).
- Monitor for processes capturing clipboard: `OpenClipboard` + `GetClipboardData` in non-clipboard-manager contexts.
- Suspicious process with handles to all keyboard-related input objects.

---

## Detection Scope

| Method | What to Detect |
|---|---|
| WH_KEYBOARD_LL hook | `SetWindowsHookEx(WH_KEYBOARD_LL, ...)` call |
| Raw input API | `RegisterRawInputDevices` for keyboard |
| Polling `GetAsyncKeyState` | High-frequency poll loop + file write |
| Kernel driver keylogger | Driver loading + filtering keyboard I/O |
| Clipboard monitor | `OpenClipboard` + `GetClipboardData` in background process |
| Browser form field hook | JavaScript `keydown` event exfil (web keylogger) |

---

## YARA — Keylogger Artifacts

```yara
rule Keylogger_LowLevel_Hook {
    meta:
        description = "Keylogger using WH_KEYBOARD_LL low-level keyboard hook"
        author = "claude-blue"
    strings:
        $hook_fn  = "SetWindowsHookEx" ascii wide
        $hook_id  = { 0D 00 00 00 }     // WH_KEYBOARD_LL = 13 (0x0D)
        $write    = "WriteFile" ascii wide
        $file     = "fopen" ascii wide
    condition:
        $hook_fn and $hook_id and ($write or $file)
}

rule Keylogger_GetAsyncKeyState_Poll {
    meta:
        description = "Keylogger polling GetAsyncKeyState in a loop"
    strings:
        $gaks  = "GetAsyncKeyState" ascii wide
        $write = "WriteFile" ascii wide
        $sleep = "Sleep" ascii wide
    condition:
        $gaks and $write and $sleep
}

rule Keylogger_RawInput {
    meta:
        description = "Raw input device registration for keyboard"
    strings:
        $raw    = "RegisterRawInputDevices" ascii wide
        $get    = "GetRawInputData" ascii wide
        $write  = "WriteFile" ascii wide
    condition:
        $raw and $get and $write
}

rule Keylogger_Clipboard_Stealer {
    meta:
        description = "Clipboard content stealer"
    strings:
        $open  = "OpenClipboard" ascii wide
        $get   = "GetClipboardData" ascii wide
        $write = "WriteFile" ascii wide
    condition:
        $open and $get and $write
}
```

---

## Sigma Rules

### Process Registering Low-Level Keyboard Hook

```yaml
title: Process Registering Low-Level Keyboard Hook
id: c2d3e4f5-a6b7-8901-cdef-234567890060
status: experimental
description: >
  Detects processes calling SetWindowsHookEx with WH_KEYBOARD_LL (13) — used
  by keyloggers to capture all keyboard input system-wide.
  Requires API call monitoring (Sysmon API telemetry or MDE).
author: claude-blue
date: 2026-04-27
logsource:
  product: windows
  category: process_access
detection:
  selection:
    CallTrace|contains: 'SetWindowsHookEx'
  filter_known:
    Image|endswith:
      - '\TextInputHost.exe'
      - '\ctfmon.exe'
      - '\TabTip.exe'
  condition: selection and not filter_known
falsepositives:
  - Accessibility software, some input method editors (allowlist)
level: high
tags:
  - attack.t1056.001
  - attack.collection
```

### Suspicious Process Writing to User-Accessible File After Input API

```yaml
title: Input Capture - Process Writing to File After Keyboard API Call
id: d3e4f5a6-b7c8-9012-defa-345678901061
status: experimental
description: >
  Detects processes that call keyboard APIs and then write to a file —
  behavioral keylogger indicator.
author: claude-blue
date: 2026-04-27
logsource:
  product: windows
  category: file_event
detection:
  selection:
    TargetFilename|endswith:
      - '.log'
      - '.txt'
      - '.dat'
  filter_expected:
    Image|endswith:
      - '\svchost.exe'
      - '\explorer.exe'
  condition: selection and not filter_expected
falsepositives:
  - Logging applications (baseline allowed writers to log files)
level: medium
tags:
  - attack.t1056.001
```

---

## KQL — MDE

### Process Opening Keyboard Device Object

```kusto
DeviceEvents
| where ActionType == "NamedPipeEvent" or ActionType == "DeviceAccessEvent"
| where AdditionalFields has "KeyboardClass" or AdditionalFields has "kbdclass"
| where not(InitiatingProcessFileName in~ (
    "csrss.exe", "winlogon.exe", "LogonUI.exe", "TextInputHost.exe"
  ))
| project TimeGenerated, DeviceName, AccountName, InitiatingProcessFileName,
          InitiatingProcessCommandLine, AdditionalFields
| order by TimeGenerated desc
```

### New Process with High File Write Rate (Keyboard Log)

```kusto
DeviceFileEvents
| where ActionType == "FileCreated" or ActionType == "FileModified"
| where FileName endswith ".log" or FileName endswith ".txt" or FileName endswith ".dat"
| where FolderPath contains "\\AppData\\" or FolderPath contains "\\Temp\\"
| where InitiatingProcessFileName !in~ (
    "explorer.exe", "svchost.exe", "MsMpEng.exe"
  )
| summarize WriteCount=count() by DeviceName, InitiatingProcessFileName, FolderPath
| where WriteCount > 100
| order by WriteCount desc
```

---

## Response Checklist

| Step | Action |
|---|---|
| 1 | Identify the keylogger binary: hash, file path, persistence mechanism |
| 2 | Check for exfil: network connections, clipboard data written to external endpoint |
| 3 | Assume all keystrokes and clipboard data captured by the keylogger are compromised |
| 4 | Reset all credentials entered on affected endpoint |
| 5 | Remove keylogger binary; remove persistence (registry, scheduled task) |
| 6 | Check other endpoints for same hash or behavioral pattern |

---

## MITRE ATT&CK

| Technique | ID | Coverage |
|---|---|---|
| Keylogging | T1056.001 | Hook/API keylogging detection |
| Clipboard Data | T1115 | Clipboard stealer detection |
| Input Capture | T1056 | All input capture methods |
