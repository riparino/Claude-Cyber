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

---

## References & Verified Sources

**Frameworks & playbooks**
- NIST SP 800-61 Rev. 2 — Computer Security Incident Handling Guide: https://csrc.nist.gov/pubs/sp/800/61/r2/final
- SANS Incident Handler's Handbook (PICERL): https://www.sans.org/white-papers/33901/
- Microsoft Incident Response Playbooks: https://learn.microsoft.com/en-us/security/operations/incident-response-playbooks
- CISA Federal Government Cybersecurity Incident & Vulnerability Response Playbooks: https://www.cisa.gov/sites/default/files/publications/Federal_Government_Cybersecurity_Incident_and_Vulnerability_Response_Playbooks_508C.pdf

**Microsoft Defender / Sentinel actions**
- MDE machine isolation API: https://learn.microsoft.com/en-us/defender-endpoint/api/isolate-machine
- Entra ID — revoke user sessions: https://learn.microsoft.com/en-us/entra/identity/users/users-revoke-access
- Reset krbtgt password (twice) guidance: https://learn.microsoft.com/en-us/defender-for-identity/cas-isp-reset-krbtgt
- Sentinel automation rules / playbooks: https://learn.microsoft.com/en-us/azure/sentinel/automate-incident-handling-with-automation-rules

**Hunt query libraries**
- Microsoft Sentinel Hunting Queries: https://github.com/Azure/Azure-Sentinel/tree/master/Hunting%20Queries
- MDE Advanced Hunting query pack: https://github.com/microsoft/Microsoft-365-Defender-Hunting-Queries
