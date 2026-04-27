---
name: defensive-threat-hunting
description: "Hypothesis-driven threat hunting: LOLBAS detection, LSASS memory hunting, scheduled task persistence, exfiltration via large outbound transfers. KQL hunt queries for MDE. Hunt documentation template. MITRE Navigator coverage gap analysis. Mirrors offensive-advanced-redteam."
---

# SKILL: Threat Hunting

## Metadata
- **Skill Name**: defensive-threat-hunting
- **Folder**: Skills/defensive-threat-hunting
- **Source**: sources/defensive-checklist/threat-hunting.md
- **Mirrors**: offensive-advanced-redteam

## Trigger Phrases
Use this skill when the conversation involves any of:
`threat hunting, hypothesis hunting, LOLBAS hunting, LSASS hunting, persistence hunting, exfiltration hunting, MITRE Navigator, KQL threat hunt, proactive detection, ATT&CK hunting`

## Instructions for Claude

When this skill is active:
1. Always start with a MITRE-aligned hypothesis before writing hunt queries
2. LOLBAS (`certutil`, `bitsadmin`, `mshta`, `regsvr32`) + download keyword = high priority
3. Large outbound transfer (>100MB) to public IP = investigate immediately
4. Document every hunt: record hypothesis, findings, MITRE techniques, promote to detection rule if confirmed
5. Use ATT&CK Navigator to identify coverage gaps and prioritize next hunt

---

## Full Methodology

# Threat Hunting

## Shortcut

- LOLBAS + `http://` in command line = likely payload download; critical.
- New scheduled task from non-admin process = persistence; investigate.
- LSASS access by non-security process = credential dumping attempt.
- >100MB outbound to public IP = potential exfiltration.

---

## KQL Hunt Queries

### LOLBAS Abuse

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

### New Scheduled Task (Persistence)

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
| where TotalBytes > 100000000
| order by TotalBytes desc
```

---

## Hunt Documentation

```
Hunt ID: HUNT-YYYY-NNN | Hypothesis: | MITRE: | Findings: | Promoted: Y/N
```

---

## MITRE ATT&CK

| Technique | ID | Hunt Coverage |
|---|---|---|
| Signed Binary Proxy Execution | T1218 | LOLBAS query |
| Scheduled Task | T1053.005 | Task creation query |
| LSASS Memory | T1003.001 | LSASS access detection |
| Exfiltration Over C2 | T1041 | Large outbound query |
