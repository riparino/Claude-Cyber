---
name: defensive-fast-triage
description: "Rapid SOC triage SOP: alert severity matrix, first-5-minutes checklist, escalation triggers, fast KQL queries. Covers shell-from-web-process, LSASS access, Defender disabled, AiTM sign-in. Use for L1/L2 analyst speed and alert prioritization."
---

# SKILL: Fast SOC Triage

## Metadata
- **Skill Name**: defensive-fast-triage
- **Folder**: Skills/defensive-fast-triage
- **Source**: sources/defensive-checklist/fast-triage.md
- **Mirrors**: offensive-fast-checking

## Trigger Phrases
Use this skill when the conversation involves any of:
`fast triage, alert triage, SOC triage, first 5 minutes, alert prioritization, escalation decision, L1 analyst, quick SOC response, what to do first, alert severity`

## Instructions for Claude

When this skill is active:
1. Always start triage with: scope check → process tree → network connections → persistence
2. Shell from web process = critical; isolate immediately before investigation
3. LSASS access = credential compromise; reset all host passwords
4. Lateral movement indicators (>3 hosts same IOC) = escalate to senior/IR team
5. Use the severity matrix to determine escalate vs investigate independently

---

## Full Methodology

# Fast SOC Triage

## Triage Severity Matrix

| Alert Type | First Action | Critical? |
|---|---|---|
| Shell from web process | Isolate host | Yes |
| LSASS access | Reset passwords; hunt lateral | Yes |
| Defender RTP disabled | Re-enable; hunt malware | Yes |
| AiTM post-MFA sign-in | Disable account; revoke tokens | Yes |
| New scheduled task non-admin | Investigate persistence | High |
| Port scan external IP | Block IP; check downstream | Medium |
| WAF 942xxx + 200 response | Possible SQL bypass | Medium |

---

## First 5 Minutes

1. **Scope**: single host or lateral movement?
2. **Process tree**: what spawned what?
3. **Network**: outbound connections from alerting process?
4. **Persistence**: new run keys, tasks, services?
5. **Escalate or contain**: isolate if critical IOC confirmed

---

## KQL — Fast Triage

### Shell from Web Process

```kusto
DeviceProcessEvents
| where InitiatingProcessFileName in~ ("w3wp.exe", "java.exe", "nginx.exe", "httpd.exe")
| where FileName in~ ("cmd.exe", "powershell.exe", "bash", "sh")
| project TimeGenerated, DeviceName, AccountName, InitiatingProcessFileName,
          FileName, ProcessCommandLine
| order by TimeGenerated desc
```

### High-Severity Defender Alerts

```kusto
DeviceAlertEvents
| where Severity in ("High", "Critical")
| project TimeGenerated, DeviceName, AccountName, Title, Category, Severity
| order by TimeGenerated desc
| take 50
```

---

## Escalation Triggers

Escalate immediately:
- Shell from web/document process
- LSASS access by non-security tool
- >3 hosts with same IOC
- Admin sign-in from new external IP
- Security tool disabled on multiple hosts

---

## MITRE ATT&CK

| Technique | ID | Triage Priority |
|---|---|---|
| Exploitation for Client Exec | T1203 | Immediate |
| OS Credential Dumping | T1003 | Immediate |
| Scheduled Task | T1053.005 | High |
| Disable Security Tools | T1562 | High |

---

## References & Verified Sources

**MITRE ATT&CK**
- T1203 Exploitation for Client Execution: https://attack.mitre.org/techniques/T1203/
- T1003 OS Credential Dumping: https://attack.mitre.org/techniques/T1003/
- T1053.005 Scheduled Task: https://attack.mitre.org/techniques/T1053/005/
- T1562 Impair Defenses: https://attack.mitre.org/techniques/T1562/

**Microsoft docs**
- Defender XDR alert investigation: https://learn.microsoft.com/en-us/defender-xdr/investigate-alerts
- `DeviceAlertEvents`: https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicealertevents-table
- AiTM phishing investigation guidance: https://learn.microsoft.com/en-us/defender-xdr/alert-grading-playbook-aitm
- Sentinel incident triage: https://learn.microsoft.com/en-us/azure/sentinel/investigate-cases

**Triage methodology references**
- SANS SOC Survey & SOC Class SEC450: https://www.sans.org/cyber-security-courses/blue-team-fundamentals-security-operations-analysis/
- Palantir Alerting and Detection Strategy framework: https://github.com/palantir/alerting-detection-strategy-framework
