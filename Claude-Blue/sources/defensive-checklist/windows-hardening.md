# Windows Security Boundaries — Hardening & Detection

## Shortcut

- Detect boundary crossing: user-mode process accessing kernel objects, privilege escalation via token impersonation.
- Alert on integrity level violations: medium-IL process writing to high-IL locations.
- Monitor for UAC bypass: process creating high-IL child without UAC prompt via auto-elevate COM objects.
- Detect Kerberos golden/silver ticket usage: TGT with non-standard lifetime or from non-DC issuer.
- Watch for SeDebugPrivilege being enabled on non-admin processes.

---

## Windows Security Boundaries

| Boundary | What it Prevents | Bypass Indicator |
|---|---|---|
| UAC | Unauthorized privilege elevation | Auto-elevate COM (fodhelper, eventvwr) |
| Integrity Levels | Low-IL writing to high-IL | Elevation without UAC prompt |
| Session Isolation | Cross-session process injection | Process accessing other session's objects |
| AppContainer / Sandbox | Browser escape | WriteProcessMemory from AppContainer |
| Kerberos TGT | Pass-the-ticket / golden ticket | Abnormal ticket lifetime, wrong issuer |
| SeDebugPrivilege | LSASS read, process injection | Non-admin process with debug privilege |
| Token Impersonation | Privilege escalation | Impersonation of higher-priv token |

---

## Sigma Rules

### UAC Bypass via Auto-Elevate COM (fodhelper / eventvwr)

```yaml
title: UAC Bypass via Auto-Elevate COM Object
id: f3a4b5c6-d7e8-9012-fabc-345678901051
status: stable
description: >
  Detects common UAC bypass techniques using auto-elevate COM objects
  that run with high integrity without prompting UAC.
author: claude-blue
date: 2026-04-27
logsource:
  product: windows
  category: process_creation
detection:
  selection_parent:
    ParentImage|endswith:
      - '\fodhelper.exe'
      - '\eventvwr.exe'
      - '\sdclt.exe'
      - '\SilentCleanup.exe'
      - '\wsreset.exe'
      - '\cmstp.exe'
  selection_child:
    Image|endswith:
      - '\cmd.exe'
      - '\powershell.exe'
      - '\reg.exe'
  condition: selection_parent and selection_child
falsepositives:
  - None expected for these parent → child combinations
level: critical
tags:
  - attack.t1548.002
  - attack.privilege_escalation
```

### SeDebugPrivilege Enabled on Non-Standard Process

```yaml
title: SeDebugPrivilege Enabled on Non-Admin Process
id: a4b5c6d7-e8f9-0123-abce-456789012052
status: experimental
description: >
  Detects SeDebugPrivilege being enabled outside of expected admin/security contexts —
  used for LSASS memory access and process injection.
author: claude-blue
date: 2026-04-27
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4703  # Token Right Adjusted
    EnabledPrivilegeList|contains: 'SeDebugPrivilege'
  filter_expected:
    ProcessName|endswith:
      - '\MsMpEng.exe'
      - '\mssense.exe'
      - '\procexp64.exe'
  condition: selection and not filter_expected
falsepositives:
  - Debugging tools on developer workstations (allowlist)
level: high
tags:
  - attack.t1134
  - attack.privilege_escalation
```

### Kerberos: Golden/Silver Ticket (Abnormal Ticket Lifetime)

```yaml
title: Kerberos Ticket with Abnormal Lifetime (Golden Ticket Indicator)
id: b5c6d7e8-f9a0-1234-bcdf-567890123053
status: experimental
description: >
  Detects Kerberos TGT events with non-standard ticket lifetime — mimikatz
  golden tickets default to 10 years, outside normal 10-hour maximum.
author: claude-blue
date: 2026-04-27
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4768   # Kerberos Authentication Service (TGT request)
  filter_normal:
    TicketOptions: '0x40810010'  # Standard options
    # Lifetime check requires EventID 4769 correlation
  condition: selection
falsepositives:
  - Requires correlation with ticket lifetime field — implement as KQL rule
level: high
tags:
  - attack.t1558.001
  - attack.credential_access
```

---

## KQL — Azure / MDE

### Kerberos Golden Ticket Detection

```kusto
SecurityEvent
| where EventID == 4768
| extend TicketLifetime = extract("Ticket Options:\\s+0x([\\dA-F]+)", 1, EventData)
| extend ServiceName = extract("Service Name:\\s+(\\S+)", 1, EventData)
| extend ClientAddress = extract("Client Address:\\s+(\\S+)", 1, EventData)
// Flag TGT requests not originating from a DC
| where ClientAddress !startswith "10.0."  // Adjust for your DC subnet
| project TimeGenerated, Computer, ServiceName, ClientAddress, TicketLifetime
| order by TimeGenerated desc
```

### UAC Bypass: High Integrity Child from Auto-Elevate Parent

```kusto
DeviceProcessEvents
| where InitiatingProcessFileName in~ (
    "fodhelper.exe", "eventvwr.exe", "sdclt.exe",
    "SilentCleanup.exe", "wsreset.exe"
  )
| where FileName in~ ("cmd.exe", "powershell.exe", "reg.exe")
| project TimeGenerated, DeviceName, AccountName, InitiatingProcessFileName,
          FileName, ProcessCommandLine
| order by TimeGenerated desc
```

### Token Impersonation via SeDebugPrivilege

```kusto
DeviceEvents
| where ActionType == "TokenPrivilegesAdjusted"
| where AdditionalFields has "SeDebugPrivilege"
| where not(InitiatingProcessFileName in~ ("MsMpEng.exe", "mssense.exe"))
| project TimeGenerated, DeviceName, AccountName, InitiatingProcessFileName,
          InitiatingProcessCommandLine, AdditionalFields
| order by TimeGenerated desc
```

---

## Response Checklist

| Step | Action |
|---|---|
| 1 | UAC bypass detected: identify the payload executed with elevated privileges |
| 2 | Golden ticket: reset the `krbtgt` account password TWICE (invalidates all tickets) |
| 3 | Token impersonation: identify what privileges were gained and what was accessed |
| 4 | Check for new admin accounts or scheduled tasks created post-elevation |
| 5 | Enable Windows Credential Guard to protect Kerberos TGTs |

---

## Hardening Reference

- **Enable Credential Guard**: protects NTLM hashes and Kerberos TGTs
- **Enable Protected Users security group**: members cannot use NTLM, constrained delegation
- **Enable audit for privilege use**: EventID 4703, 4768, 4769
- **WDAC / AppLocker**: prevent UAC bypass binaries from executing code
- **Restrict auto-elevate COM**: disable auto-elevate for non-admin accounts

---

## MITRE ATT&CK

| Technique | ID | Coverage |
|---|---|---|
| Bypass User Account Control | T1548.002 | UAC bypass via COM |
| Access Token Manipulation | T1134 | SeDebugPrivilege, token impersonation |
| Golden Ticket | T1558.001 | Kerberos ticket anomaly |
| Silver Ticket | T1558.002 | Service ticket abuse |
