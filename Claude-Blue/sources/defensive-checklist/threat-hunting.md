# Threat Hunting — Hypothesis-Driven Methodology

## Overview
Structured threat hunting: hypothesis generation, TTP-based pivots, KQL hunt queries per MITRE phase, MITRE Navigator coverage tracking, hunt documentation.

## Shortcut

- Hunt hypothesis: "Adversary is living off the land using LOLBAS." KQL: unusual `certutil.exe`, `bitsadmin.exe`, `mshta.exe` executions.
- Start with high-confidence IOCs → expand to behavioral TTPs → validate or rule out.
- Living off the land (LotL): signed Windows binaries (`certutil`, `regsvr32`, `rundll32`) used for malicious purposes.
- ATT&CK Navigator: map hunt findings to MITRE; identify coverage gaps.

---

## Hunt Process

1. **Hypothesis**: define what attacker behavior to look for (MITRE-aligned)
2. **Data sources**: identify relevant MDE/SIEM tables
3. **Query**: write KQL/Sigma to hunt
4. **Investigate**: triage hits; pivot to related events
5. **Document**: record findings; update detection rules with confirmed TTPs
6. **Tune**: promote validated hunts to production detection rules

---

## Hunt Hypotheses by Phase

### Initial Access
- Hypothesis: Phishing with malicious attachment → macro execution
- KQL table: `DeviceProcessEvents` — Office products spawning `cmd.exe` or `wscript.exe`

### Persistence
- Hypothesis: New scheduled task or registry run key created by non-admin process
- KQL table: `DeviceRegistryEvents`, `DeviceEvents (ScheduledTask)`

### Defense Evasion
- Hypothesis: LOLBAS abuse (`certutil`, `bitsadmin`, `mshta`, `regsvr32`)
- KQL table: `DeviceProcessEvents`

### Credential Access
- Hypothesis: LSASS memory access for credential dumping
- KQL table: `DeviceEvents (LsassProcessAccess)`

### Lateral Movement
- Hypothesis: PsExec or WMI lateral movement
- KQL table: `DeviceProcessEvents`, `DeviceNetworkEvents`

### Exfiltration
- Hypothesis: Large data upload to uncommon external IP
- KQL table: `DeviceNetworkEvents` — outbound bytes spike

---

## KQL Hunt Queries

### LOLBAS Abuse (Defense Evasion)

```kusto
DeviceProcessEvents
| where FileName in~ (
    "certutil.exe", "bitsadmin.exe", "mshta.exe", "regsvr32.exe",
    "rundll32.exe", "msiexec.exe", "wscript.exe", "cscript.exe"
  )
| where ProcessCommandLine has_any ("http://", "https://", ".ps1", "download", "urlcache")
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine
| order by TimeGenerated desc
```

### New Scheduled Tasks (Persistence)

```kusto
DeviceEvents
| where ActionType == "ScheduledTaskCreated"
| where InitiatingProcessFileName !in~ ("svchost.exe", "TaskScheduler.exe", "msiexec.exe")
| project TimeGenerated, DeviceName, AccountName, InitiatingProcessFileName,
          InitiatingProcessCommandLine, AdditionalFields
| order by TimeGenerated desc
```

### Large Outbound Transfer (Exfiltration)

```kusto
DeviceNetworkEvents
| where RemoteIPType == "Public"
| where InitiatingProcessFileName !in~ ("MsMpEng.exe", "svchost.exe", "wuauclt.exe")
| summarize TotalBytes=sum(SentBytes) by DeviceName, InitiatingProcessFileName, RemoteIP
| where TotalBytes > 100000000  // 100 MB
| order by TotalBytes desc
```

### LSASS Access (Credential Hunting)

```kusto
DeviceEvents
| where ActionType == "LsassProcessAccess"
| where not(InitiatingProcessFileName in~ ("MsMpEng.exe", "mssense.exe"))
| project TimeGenerated, DeviceName, AccountName, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by TimeGenerated desc
```

---

## Hunt Documentation Template

```
Hunt ID: HUNT-YYYY-NNN
Date: 
Analyst:
Hypothesis: 
Data Sources:
Query:
Findings: [confirmed malicious / false positive / inconclusive]
MITRE Techniques Covered:
Promoted to Detection Rule: [Yes/No - Rule ID]
```

---

## MITRE ATT&CK Coverage

Use ATT&CK Navigator (https://mitre-attack.github.io/attack-navigator/) to:
- Mark covered techniques in green
- Mark hunted (but undetected) techniques in yellow
- Prioritize techniques with high frequency but no coverage

---

## MITRE ATT&CK

| Technique | ID | Hunt Query |
|---|---|---|
| LOLBAS | T1218 | LOLBAS query above |
| Scheduled Task | T1053.005 | Scheduled task creation |
| LSASS Memory | T1003.001 | LSASS access query |
| Exfiltration | T1041 | Large outbound transfer |
