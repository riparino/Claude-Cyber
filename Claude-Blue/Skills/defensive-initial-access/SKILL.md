---
name: defensive-initial-access
description: "Initial access detection: malicious Office macro spawning shells, browser drive-by, ISO/LNK delivery, phishing email detection, PowerShell download cradles, Entra ID impossible travel. Sigma rules for parent-child process anomalies, KQL for MDE DeviceProcessEvents, EmailEvents, and SigninLogs. Use for SOC triage and IR."
---

# SKILL: Initial Access Detection

## Metadata
- **Skill Name**: defensive-initial-access
- **Folder**: Skills/defensive-initial-access
- **Source**: sources/defensive-checklist/initial-access.md
- **Mirrors**: offensive-initial-access

## Trigger Phrases
Use this skill when the conversation involves any of:
`initial access detection, phishing detection, malicious macro detection, Office spawning PowerShell, drive-by detection, download cradle detection, MDE initial access KQL, phishing email detection, impossible travel alert`

## Instructions for Claude

When this skill is active:
1. Office process spawning cmd/PowerShell = high confidence malicious macro; treat as active incident
2. Browser spawning script interpreter = drive-by or phishing link; scope blast radius via email delivery
3. KQL for MDE DeviceProcessEvents (parent-child chains), EmailEvents (delivery), SigninLogs (impossible travel)
4. Immediate: isolate device + identify all endpoints that received same email/file
5. Hunt persistence immediately: scheduled tasks, registry run keys, services after initial access

---

## Full Methodology

# Initial Access Detection

## Shortcut

- `WINWORD.EXE → cmd.exe / powershell.exe` = malicious macro; critical.
- `chrome.exe / msedge.exe → wscript.exe / mshta.exe` = drive-by.
- `powershell.exe -enc` or containing `DownloadString` + `IEX` = download cradle.
- Entra ID: sign-in from new country within impossible timeframe = credential theft.

---

## Key Detection Signals

| Vector | Sigma | KQL | Severity |
|---|---|---|---|
| Office → cmd/PS | WinWord spawning cmd | DeviceProcessEvents | High |
| Browser → script engine | Chrome spawning wscript | DeviceProcessEvents | High |
| ISO/LNK delivery | Explorer → script from Downloads | DeviceProcessEvents | High |
| PowerShell download cradle | `DownloadString` + `IEX` | DeviceProcessEvents | High |
| Phishing email delivered | ThreatTypes = Malware/Phish | EmailEvents | Medium |
| Impossible travel | New country sign-in | SigninLogs | High |

---

## KQL — MDE / Entra ID

### Office Macro → Shell

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
          FileName, ProcessCommandLine
| order by TimeGenerated desc
```

### PowerShell Download Cradle

```kusto
DeviceProcessEvents
| where FileName =~ "powershell.exe"
| where ProcessCommandLine has_any (
    "DownloadString", "DownloadFile", "IEX", "Invoke-Expression",
    "WebClient", "Invoke-WebRequest"
  )
| where ProcessCommandLine !contains "WindowsUpdate"
| project TimeGenerated, DeviceName, AccountName, ProcessCommandLine,
          InitiatingProcessFileName
| order by TimeGenerated desc
```

### M365: Phishing Delivered to Inbox

```kusto
EmailEvents
| where ThreatTypes has "Malware" or ThreatTypes has "Phish"
| where DeliveryAction == "Delivered"
| project TimeGenerated, RecipientEmailAddress, SenderMailFromAddress,
          Subject, ThreatTypes, LatestDeliveryLocation
| order by TimeGenerated desc
```

---

## Response Checklist

| Step | Action |
|---|---|
| 1 | Isolate device with active shell spawn |
| 2 | Identify attachment/URL that triggered execution |
| 3 | Scope: all devices that received same email/file |
| 4 | Hunt persistence: scheduled tasks, run keys, services |
| 5 | Check lateral movement: RDP, SMB, WMI from compromised host |
| 6 | Block sender/URL/hash in M365 Defender |

---

## MITRE ATT&CK

| Technique | ID | Coverage |
|---|---|---|
| Spearphishing Attachment | T1566.001 | Office macro delivery |
| Spearphishing Link | T1566.002 | Phishing link exploitation |
| Drive-by Compromise | T1189 | Browser exploitation |
| Valid Accounts | T1078 | Stolen credential use |

---

## References & Verified Sources

**MITRE ATT&CK**
- Initial Access tactic (TA0001): https://attack.mitre.org/tactics/TA0001/
- T1566 Phishing: https://attack.mitre.org/techniques/T1566/
- T1078 Valid Accounts: https://attack.mitre.org/techniques/T1078/
- T1189 Drive-by Compromise: https://attack.mitre.org/techniques/T1189/
- T1190 Exploit Public-Facing Application: https://attack.mitre.org/techniques/T1190/

**Microsoft Defender / Sentinel KQL tables**
- `EmailEvents` schema: https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-emailevents-table
- `EmailUrlInfo` schema: https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-emailurlinfo-table
- `SigninLogs` schema: https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/signinlogs
- `AADRiskyUsers` / Identity Protection: https://learn.microsoft.com/en-us/entra/id-protection/

**Detection content**
- Microsoft Sentinel detections (GitHub): https://github.com/Azure/Azure-Sentinel/tree/master/Detections
- AiTM phishing detection guidance (MS Security blog): https://www.microsoft.com/security/blog/2022/07/12/from-cookie-theft-to-bec-attackers-use-aitm-phishing-sites-as-entry-point-to-further-financial-fraud/
- SigmaHQ phishing & initial-access rules: https://github.com/SigmaHQ/sigma/tree/master/rules/category/web

**Reference incidents (CVE / campaign)**
- Midnight Blizzard (Storm-0558) token theft: https://msrc.microsoft.com/blog/2023/09/results-of-major-technical-investigations-for-storm-0558-key-acquisition/
- ProxyShell (CVE-2021-34473, CVE-2021-34523, CVE-2021-31207): https://nvd.nist.gov/vuln/detail/CVE-2021-34473
