---
name: defensive-incident-response
description: "Incident response playbook: PICERL lifecycle phases, containment decision matrix, evidence collection order, KQL hunt queries per phase. MDE host isolation, lateral movement scoping, persistence eradication, recovery verification. Use for SOC IR operations and breach response."
---

# SKILL: Incident Response

## Metadata
- **Skill Name**: defensive-incident-response
- **Folder**: Skills/defensive-incident-response
- **Source**: sources/defensive-checklist/incident-response.md

## Trigger Phrases
Use this skill when the conversation involves any of:
`incident response, IR playbook, containment, eradication, recovery, PICERL, breach response, isolate host, lateral movement scope, forensics, MDE isolation, IR KQL`

## Instructions for Claude

When this skill is active:
1. Identification: confirm scope — single host or lateral movement across multiple hosts?
2. Containment: isolate via MDE before touching evidence; don't alert adversary
3. Domain admin compromised: disable account + all tokens + reset krbtgt twice
4. Eradication: remove malware → revoke tokens → rotate credentials → patch vulnerability
5. Recovery: restore from clean backup; monitor 72h for reinfection

---

## Full Methodology

# Incident Response

## PICERL Phases

| Phase | Key Actions | KQL Table |
|---|---|---|
| Preparation | IR plan, contacts, tools | — |
| Identification | Triage, scope, IOC confirm | `DeviceAlertEvents`, `SigninLogs` |
| Containment | Isolate, block, disable | MDE portal actions |
| Eradication | Remove, rotate, patch | `DeviceFileEvents`, `DeviceRegistryEvents` |
| Recovery | Restore, monitor | `DeviceProcessEvents` |
| Lessons Learned | RCA, detection gaps | — |

---

## KQL — IR Queries

### Critical Alerts (Identification)

```kusto
DeviceAlertEvents
| where TimeGenerated > ago(24h)
| where Severity in ("High", "Critical")
| summarize AlertCount=count() by DeviceName, Title, Severity
| order by Severity, AlertCount desc
```

### Lateral Movement Scope (Containment)

```kusto
DeviceNetworkEvents
| where TimeGenerated > ago(7d)
| where InitiatingProcessFileName in~ ("psexec.exe", "wmic.exe", "wmiprvse.exe")
| where RemotePort in (445, 135, 5985)
| project TimeGenerated, DeviceName, InitiatingProcessFileName, RemoteIP, RemotePort
| order by TimeGenerated desc
```

---

## Containment Matrix

| Situation | Action |
|---|---|
| Single host | MDE: Isolate machine |
| Domain admin compromised | Disable account; revoke tokens; reset krbtgt x2 |
| Ransomware spreading | Segment network; disable SMB |
| Cloud account | Revoke all tokens; rotate credentials; audit log |

---

## Evidence Order

1. Volatile: RAM → network connections → running processes
2. Semi-volatile: event logs → log files
3. Persistent: disk image → registry → $MFT

---

## MITRE ATT&CK

| Technique | ID | IR Phase |
|---|---|---|
| Lateral Movement | T1021 | Containment scope |
| Persistence | T1053, T1547 | Eradication |
