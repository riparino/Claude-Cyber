---
name: defensive-keylogger-detection
description: "Keylogger detection: YARA for WH_KEYBOARD_LL hook, GetAsyncKeyState polling, raw input registration, clipboard stealer patterns. Sigma for keyboard API hook registration. KQL for MDE keyboard device object access and high-rate log file writes. Use for malware analysis, SOC triage, and endpoint forensics."
---

# SKILL: Keylogger Detection

## Metadata
- **Skill Name**: defensive-keylogger-detection
- **Folder**: Skills/defensive-keylogger-detection
- **Source**: sources/defensive-checklist/keylogger-detection.md
- **Mirrors**: offensive-keylogger-arch

## Trigger Phrases
Use this skill when the conversation involves any of:
`keylogger detection, YARA keylogger, SetWindowsHookEx detection, keyboard hook detection, GetAsyncKeyState detection, clipboard stealer detection, input capture detection, keylogger YARA, keylogger KQL`

## Instructions for Claude

When this skill is active:
1. YARA is the primary detection mechanism — provide all 4 keylogger YARA rules immediately
2. Assume all keystrokes and clipboard content captured are compromised
3. Reset all credentials entered on affected endpoints
4. KQL for MDE keyboard device access and high-rate file writes in AppData/Temp
5. Check for exfil: network connections from keylogger process to external hosts

---

## Full Methodology

# Keylogger Detection

## Shortcut

- YARA: `SetWindowsHookEx` + `WH_KEYBOARD_LL` + file write in same PE.
- `GetAsyncKeyState` in a loop + `Sleep` + file write = polling keylogger.
- `RegisterRawInputDevices` + `GetRawInputData` + file write = raw input keylogger.
- Suspicious process writing frequently to `.log`/`.txt` in AppData = keylog file.

---

## YARA (All Rules)

```yara
rule Keylogger_LowLevel_Hook {
    meta:
        description = "WH_KEYBOARD_LL low-level keyboard hook keylogger"
    strings:
        $hook_fn = "SetWindowsHookEx" ascii wide
        $hook_id = { 0D 00 00 00 }   // WH_KEYBOARD_LL = 13
        $write   = "WriteFile" ascii wide
        $file    = "fopen" ascii wide
    condition:
        $hook_fn and $hook_id and ($write or $file)
}

rule Keylogger_GetAsyncKeyState_Poll {
    meta:
        description = "Keylogger polling GetAsyncKeyState"
    strings:
        $gaks  = "GetAsyncKeyState" ascii wide
        $write = "WriteFile" ascii wide
        $sleep = "Sleep" ascii wide
    condition:
        $gaks and $write and $sleep
}

rule Keylogger_RawInput {
    meta:
        description = "Raw input device registration keylogger"
    strings:
        $raw  = "RegisterRawInputDevices" ascii wide
        $get  = "GetRawInputData" ascii wide
        $write = "WriteFile" ascii wide
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

## KQL — MDE

### High-Rate Writes to AppData Log Files

```kusto
DeviceFileEvents
| where ActionType in ("FileCreated", "FileModified")
| where FileName endswith ".log" or FileName endswith ".txt" or FileName endswith ".dat"
| where FolderPath contains "\\AppData\\" or FolderPath contains "\\Temp\\"
| where InitiatingProcessFileName !in~ ("explorer.exe", "svchost.exe", "MsMpEng.exe")
| summarize WriteCount=count() by DeviceName, InitiatingProcessFileName, FolderPath
| where WriteCount > 100
| order by WriteCount desc
```

---

## Response Checklist

| Step | Action |
|---|---|
| 1 | Identify keylogger: hash, path, persistence mechanism |
| 2 | Check network: connections to external hosts from keylogger process |
| 3 | Assume all credentials entered on endpoint are compromised; reset all |
| 4 | Remove keylogger; remove persistence (registry run key, scheduled task) |
| 5 | Check other endpoints for same hash or behavioral pattern |

---

## MITRE ATT&CK

| Technique | ID | Coverage |
|---|---|---|
| Keylogging | T1056.001 | Hook/API/raw input keylogger |
| Clipboard Data | T1115 | Clipboard stealer |
