# Incident Response — Playbook

## Overview
IR lifecycle phases: Preparation, Identification, Containment, Eradication, Recovery, Lessons Learned (PICERL). KQL hunt queries per phase. Containment decision matrix.

## Shortcut

- Identification: `DeviceAlertEvents | where Severity == "Critical"` + process tree.
- Containment: isolate host via MDE (`Isolate machine`) before forensics.
- Eradication: remove malware, revoke tokens, reset passwords, patch vulnerability.
- Recovery: restore from clean backup; verify no reinfection.
- Evidence collection order: volatile (RAM/network) → persistent (disk/logs).

---

## IR Lifecycle

| Phase | Key Actions | KQL Table |
|---|---|---|
| Preparation | IR plan, contact list, tool readiness | — |
| Identification | Alert triage, scope, confirm IOC | `DeviceAlertEvents`, `SigninLogs` |
| Containment | Isolate hosts, block network, disable accounts | MDE portal actions |
| Eradication | Remove malware, rotate creds, patch | `DeviceFileEvents`, `DeviceRegistryEvents` |
| Recovery | Restore services, monitor closely | `DeviceProcessEvents` |
| Lessons Learned | RCA, detection gap, process improvement | — |

---

## KQL — IR Hunt Queries

### Identification: Critical Alerts in Last 24h

```kusto
DeviceAlertEvents
| where TimeGenerated > ago(24h)
| where Severity in ("High", "Critical")
| summarize AlertCount=count() by DeviceName, AlertId, Title, Severity
| order by Severity, AlertCount desc
```

### Containment: Confirm Lateral Movement Scope

```kusto
DeviceNetworkEvents
| where TimeGenerated > ago(7d)
| where InitiatingProcessFileName in~ ("psexec.exe", "psexec64.exe", "wmic.exe", "wmiprvse.exe")
| where RemotePort in (445, 135, 5985, 5986)
| project TimeGenerated, DeviceName, InitiatingProcessFileName, RemoteIP, RemotePort
| order by TimeGenerated desc
```

### Eradication: New Persistence Mechanisms

```kusto
union
(DeviceRegistryEvents
 | where ActionType == "RegistryValueSet"
 | where RegistryKey contains "Run" or RegistryKey contains "Services"
 | where TimeGenerated between (incident_start .. now())),
(DeviceEvents
 | where ActionType == "ScheduledTaskCreated"
 | where TimeGenerated between (incident_start .. now()))
| project TimeGenerated, DeviceName, ActionType, RegistryKey, AdditionalFields
| order by TimeGenerated asc
```

### Recovery: Watch for Reinfection

```kusto
DeviceFileEvents
| where TimeGenerated > (recovery_date)
| where SHA1 in (ioc_hashes)
| project TimeGenerated, DeviceName, FileName, FolderPath, SHA1
```

---

## Containment Decision Matrix

| Situation | Action |
|---|---|
| Single host confirmed compromised | MDE: Isolate machine |
| Domain admin compromised | Disable account + all tokens; krbtgt reset |
| Ransomware spreading | Network segment isolation; disable SMB |
| Cloud account compromised | Revoke all tokens; rotate credentials; audit audit log |

---

## Evidence Collection Order

1. **Volatile**: RAM dump → active network connections → running processes
2. **Semi-volatile**: log files → event logs → browser history
3. **Persistent**: disk image → registry hives → $MFT

---

## MITRE ATT&CK

| Phase | Technique | ID |
|---|---|---|
| Identification | Command and Scripting | T1059 |
| Containment | Lateral Movement | T1021 |
| Eradication | Persistence | T1053, T1547 |
