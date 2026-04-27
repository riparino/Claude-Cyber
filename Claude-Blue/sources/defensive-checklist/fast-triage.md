# Fast SOC Triage — Rapid Alert Prioritization

## Overview
Rapid SOC triage SOP: alert severity matrix, first-5-minutes checklist, escalation triggers, triage pivot queries. Designed for L1/L2 analyst speed.

## Shortcut

- First action: check alert type → look up in triage matrix → assess critical or not → act.
- Process from web server = RCE: critical, escalate immediately.
- LSASS access = critical, isolate host.
- New external IP sign-in after MFA change = AiTM: critical.
- Defender alert + Entra sign-in spike same user = correlate before escalating.

---

## Triage Severity Matrix

| Alert Type | First Action | Critical? |
|---|---|---|
| Shell spawned from web process | Isolate host; check network connections | Yes |
| LSASS process access | Reset all host passwords; check lateral movement | Yes |
| Defender real-time protection disabled | Re-enable; hunt for malware installed | Yes |
| Sign-in from unfamiliar country + MFA bypassed | Disable account; revoke tokens | Yes |
| New scheduled task from non-admin | Investigate; hunt persistence | High |
| Port scan from external IP | Block source IP; check downstream hits | Medium |
| WAF 942xxx SQL rule match | Check if 200 response (bypass) vs 403 (blocked) | Medium |

---

## First 5 Minutes Checklist

1. **Identify scope**: single user/host or lateral movement?
2. **Check process tree**: what spawned what?
3. **Check network**: what outbound connections did the process make?
4. **Check persistence**: new run keys, scheduled tasks, services?
5. **Escalate or contain**: isolate if critical IOC confirmed

---

## KQL — Fast Triage

### Confirm Shell Spawn from Web Process

```kusto
DeviceProcessEvents
| where InitiatingProcessFileName in~ (
    "w3wp.exe", "java.exe", "nginx.exe", "httpd.exe", "tomcat9.exe"
  )
| where FileName in~ ("cmd.exe", "powershell.exe", "bash", "sh", "wscript.exe")
| project TimeGenerated, DeviceName, AccountName, InitiatingProcessFileName,
          FileName, ProcessCommandLine
| order by TimeGenerated desc
```

### Recent High-Severity Defender Alerts

```kusto
DeviceAlertEvents
| where Severity in ("High", "Critical")
| project TimeGenerated, DeviceName, AccountName, AlertId, Title, Category, Severity
| order by TimeGenerated desc
| take 50
```

---

## Escalation Triggers

Escalate immediately when:
- Shell spawned from web/document process
- LSASS access by non-security tool
- More than 3 hosts with same IOC (lateral movement)
- Admin account signed in from external IP never seen before
- Security tool disabled on multiple hosts simultaneously

---

## MITRE ATT&CK

| Technique | ID | Triage Priority |
|---|---|---|
| Exploitation for Client Exec | T1203 | Immediate |
| OS Credential Dumping | T1003 | Immediate |
| Scheduled Task | T1053.005 | High |
| Disable Security Tools | T1562 | High |
