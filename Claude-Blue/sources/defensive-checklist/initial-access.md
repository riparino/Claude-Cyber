# Initial Access Detection

## Shortcut

- Email-based initial access: alert on Office document with macro executing PowerShell or spawning cmd.exe.
- Browser exploitation: script engine (wscript, mshta) spawned by browser process.
- AiTM phishing: see `defensive-oauth.md` — stolen session post-MFA.
- Valid credentials from unknown location: alert on sign-in from new country/ASN with no travel baseline.
- Supply chain: alert on software spawning PowerShell to download additional payloads post-install.
- Drive-by: browser spawning wscript/mshta/regsvr32.

---

## Detection Scope

| Vector | What to Detect |
|---|---|
| Malicious attachment | Office process spawning cmd/PowerShell |
| Phishing link | Browser spawning script interpreter |
| Valid account abuse | Sign-in from impossible travel or new ASN |
| Supply chain | Installer/updater spawning download cradle |
| Drive-by | Browser child process anomaly |
| ISO/LNK delivery | Explorer spawning PowerShell/mshta from removable media |

---

## Log Sources

| Source | Content | Platform |
|---|---|---|
| MDE DeviceProcessEvents | Process creation with parent chain | MDE |
| MDE DeviceNetworkEvents | C2 beacon post-initial access | MDE |
| Entra ID SigninLogs | Location/device anomalies | Azure |
| EmailEvents (Defender) | Mail delivery, attachment metadata | M365 |
| DeviceEvents | Script engine execution, macro execution | MDE |

---

## Sigma Rules

### Office Process Spawning Script Engine (Malicious Attachment)

```yaml
title: Microsoft Office Spawning Script Engine or Shell (Malicious Attachment)
id: a2b3c4d5-e6f7-8901-abce-234567890040
status: stable
description: >
  Detects Office processes spawning scripting engines or command shells —
  high-confidence indicator of malicious macro or embedded object execution.
author: claude-blue
date: 2026-04-27
logsource:
  product: windows
  category: process_creation
detection:
  selection_office_parent:
    ParentImage|endswith:
      - '\WINWORD.EXE'
      - '\EXCEL.EXE'
      - '\POWERPNT.EXE'
      - '\MSPUB.EXE'
      - '\MSACCESS.EXE'
      - '\VISIO.EXE'
  selection_child:
    Image|endswith:
      - '\cmd.exe'
      - '\powershell.exe'
      - '\wscript.exe'
      - '\cscript.exe'
      - '\mshta.exe'
      - '\regsvr32.exe'
      - '\rundll32.exe'
      - '\certutil.exe'
  condition: selection_office_parent and selection_child
falsepositives:
  - Specific Office add-ins (document and allowlist)
level: high
tags:
  - attack.t1566.001
  - attack.t1059
```

### Browser Spawning Script Interpreter (Drive-by / Phishing Link)

```yaml
title: Browser Process Spawning Script Interpreter
id: b3c4d5e6-f7a8-9012-bcdf-345678901041
status: experimental
description: >
  Detects web browser spawning scripting engines or LOLBins — indicator
  of drive-by compromise or user clicking a malicious link.
author: claude-blue
date: 2026-04-27
logsource:
  product: windows
  category: process_creation
detection:
  selection_browser_parent:
    ParentImage|endswith:
      - '\chrome.exe'
      - '\msedge.exe'
      - '\firefox.exe'
      - '\iexplore.exe'
  selection_child:
    Image|endswith:
      - '\cmd.exe'
      - '\powershell.exe'
      - '\wscript.exe'
      - '\mshta.exe'
      - '\regsvr32.exe'
  condition: selection_browser_parent and selection_child
falsepositives:
  - Browser-integrated dev tools (allowlist developer machines)
level: high
tags:
  - attack.t1566.002
  - attack.t1059
```

### ISO/LNK Delivery via Explorer (Removable Media / Phishing)

```yaml
title: Explorer Spawning Script Engine from Removable Media Path
id: c4d5e6f7-a8b9-0123-cdeg-456789012042
status: experimental
description: >
  Detects Explorer spawning script engines from removable media or Downloads
  paths — ISO/LNK/JS delivery via phishing.
author: claude-blue
date: 2026-04-27
logsource:
  product: windows
  category: process_creation
detection:
  selection_parent:
    ParentImage|endswith: '\explorer.exe'
  selection_child:
    Image|endswith:
      - '\wscript.exe'
      - '\cscript.exe'
      - '\mshta.exe'
      - '\powershell.exe'
  selection_path:
    CommandLine|contains:
      - '\Downloads\'
      - 'D:\'
      - 'E:\'
      - 'F:\'
  condition: selection_parent and selection_child and selection_path
falsepositives:
  - Legitimate scripts run from Downloads (uncommon; investigate)
level: high
tags:
  - attack.t1566
  - attack.t1204.001
```

---

## KQL — Azure / Microsoft Sentinel

### MDE: Office Process Spawning Shell

```kusto
DeviceProcessEvents
| where InitiatingProcessFileName in~ (
    "WINWORD.EXE", "EXCEL.EXE", "POWERPNT.EXE", "MSPUB.EXE", "MSACCESS.EXE"
  )
| where FileName in~ (
    "cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe",
    "mshta.exe", "regsvr32.exe", "rundll32.exe", "certutil.exe"
  )
| project TimeGenerated, DeviceName, InitiatingProcessFileName,
          FileName, ProcessCommandLine, InitiatingProcessCommandLine
| order by TimeGenerated desc
```

### Entra ID: Sign-in from New Country (Impossible Travel)

```kusto
SigninLogs
| where ResultType == 0
| summarize LastKnownLocations=make_set(Location) by UserPrincipalName
| extend UnusualLocations = array_length(LastKnownLocations) > 1
// Combine with Entra ID Identity Protection risk events for impossible travel
```

### M365: Malicious Attachment Delivery

```kusto
EmailEvents
| where ThreatTypes has "Malware" or ThreatTypes has "Phish"
| where DeliveryAction == "Delivered"
| project TimeGenerated, RecipientEmailAddress, SenderMailFromAddress,
          Subject, ThreatTypes, FileName=tostring(AttachmentCount),
          LatestDeliveryLocation
| order by TimeGenerated desc
```

### MDE: Download Cradle — PowerShell Downloading from Internet

```kusto
DeviceProcessEvents
| where FileName =~ "powershell.exe"
| where ProcessCommandLine has_any (
    "DownloadString", "DownloadFile", "IEX", "Invoke-Expression",
    "WebClient", "Invoke-WebRequest", "curl", "wget"
  )
| where ProcessCommandLine !contains "WindowsUpdate"
| project TimeGenerated, DeviceName, AccountName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by TimeGenerated desc
```

---

## Response Checklist

| Step | Action |
|---|---|
| 1 | Isolate device if active shell detected |
| 2 | Identify attachment/URL that delivered the initial payload |
| 3 | Search for all endpoints that received same email/file (blast radius) |
| 4 | Check for persistence: scheduled tasks, registry run keys, services |
| 5 | Check for lateral movement: RDP, SMB, WMI from compromised host |
| 6 | Reset credentials for any accounts used on the compromised host |
| 7 | Block sender, URL, and hash in M365 Defender |

---

## MITRE ATT&CK

| Technique | ID | Coverage |
|---|---|---|
| Spearphishing Attachment | T1566.001 | Malicious Office document |
| Spearphishing Link | T1566.002 | Phishing link to payload |
| Drive-by Compromise | T1189 | Browser exploitation |
| Valid Accounts | T1078 | Stolen credentials |
| Supply Chain Compromise | T1195 | Malicious installer |
