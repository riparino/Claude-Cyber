# SOC Workflows — Alert Triage & Escalation

## Overview
SOC operational workflows: alert triage SOP, escalation matrix, shift handoff, case management, SOAR automation patterns, analyst fatigue mitigation.

## Shortcut

- L1: triage → enrich → close/escalate within 15 minutes.
- L2: investigate → contain → document → close/escalate within 2 hours.
- L3/IR: complex incidents; breach response.
- SOAR: automate IP enrichment, user context, device isolation on high-severity alerts.

---

## Alert Triage SOP

```
1. Receive alert
2. Check severity (Critical/High/Medium/Low)
3. Identify alert type (process/network/identity)
4. Run quick KQL pivot (related events, same device)
5. Enrich: IP reputation, user risk, device compliance
6. Determine: True Positive / False Positive / Undetermined
7. TP: Contain → escalate if scope > 1 host
8. FP: Close with documentation; flag rule for tuning
9. Undetermined: escalate to L2
```

---

## Escalation Matrix

| Scenario | Escalate To | SLA |
|---|---|---|
| Shell from web process | L2 / IR immediately | 5 minutes |
| Confirmed lateral movement | L3 / IR team | 15 minutes |
| Domain admin compromised | CISO + IR team | Immediate |
| Ransomware indicators | IR team + management | Immediate |
| Single host malware, no spread | L2 | 1 hour |
| Multiple FPs same rule | Detection engineering | Next business day |

---

## SOAR Automation Patterns

| Trigger | Automated Action |
|---|---|
| High/Critical alert | Auto-enrich: IP + user + device |
| LSASS access alert | Auto-isolate host + create incident ticket |
| Failed logins >10/min | Auto-block IP (conditional access) |
| Phishing email confirmed | Auto-purge from all mailboxes |
| New external admin sign-in | Auto-disable account; request validation |

---

## Shift Handoff Checklist

1. Open incidents: status, owner, next action
2. Alerts in queue: triaged/untriaged count
3. Active hunts: hypothesis, progress
4. Known FP patterns: alert analyst to ignore
5. Planned maintenance: systems down, expected noise

---

## KQL — SOC Operations

### Open Incidents by Severity

```kusto
SecurityIncident
| where Status != "Closed"
| summarize Count=count() by Severity, Status
| order by Severity asc
```

### Alert Queue (Last 4h)

```kusto
SecurityAlert
| where TimeGenerated > ago(4h)
| where AlertSeverity in ("High", "Critical")
| project TimeGenerated, AlertName, AlertSeverity, CompromisedEntity, Tactics
| order by TimeGenerated desc
```

---

## Analyst Fatigue Mitigation

| Problem | Solution |
|---|---|
| High FP rate | Weekly FP review; rule tuning cycle |
| Alert volume spike | Group related alerts into incidents |
| Same alert daily | Auto-suppress after 3 confirmations as FP |
| Context switching | Tier-based queue assignment |

---

## MITRE ATT&CK

| Technique | ID | SOC Action |
|---|---|---|
| All phases | — | Alert triage maps to MITRE |
