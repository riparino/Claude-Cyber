---
name: defensive-soc-workflows
description: "SOC operational workflows: alert triage SOP, L1/L2/L3 escalation matrix, shift handoff checklist, SOAR automation patterns, analyst fatigue mitigation. KQL for open incidents and alert queue. Use for SOC process design and analyst training."
---

# SKILL: SOC Workflows

## Metadata
- **Skill Name**: defensive-soc-workflows
- **Folder**: Skills/defensive-soc-workflows
- **Source**: sources/defensive-checklist/soc-workflows.md

## Trigger Phrases
Use this skill when the conversation involves any of:
`SOC workflow, alert triage SOP, escalation matrix, shift handoff, SOAR automation, analyst fatigue, L1 L2 L3 triage, incident escalation, SOC process, case management`

## Instructions for Claude

When this skill is active:
1. L1: triage → enrich → close/escalate within 15 minutes; don't sit on alerts
2. Critical triggers: shell from web process, LSASS access, domain admin compromised = L3/IR immediately
3. SOAR: automate IP enrichment + host isolation on High/Critical LSASS alerts
4. FP rate: weekly review cycle; flag rules >5 FPs/week for detection engineering
5. Shift handoff: always document open incidents + next actions before shift end

---

## Full Methodology

# SOC Workflows

## Alert Triage SOP

1. Receive alert → check severity
2. Identify alert type (process/network/identity)
3. KQL pivot: related events, same device
4. Enrich: IP reputation, user risk, device compliance
5. Classify: TP / FP / Undetermined
6. TP: contain → escalate if >1 host scope
7. FP: close + flag rule for tuning

---

## Escalation Matrix

| Scenario | Level | SLA |
|---|---|---|
| Shell from web process | L3/IR | 5 minutes |
| Lateral movement >3 hosts | L3/IR | 15 minutes |
| Domain admin compromised | CISO + IR | Immediate |
| Ransomware indicators | IR + management | Immediate |
| Single host malware, no spread | L2 | 1 hour |
| Repeated FPs same rule | Detection Eng | Next business day |

---

## SOAR Automation

| Trigger | Automated Action |
|---|---|
| High/Critical alert | Enrich IP + user + device |
| LSASS access | Isolate host + create ticket |
| Failed logins >10/min | Block IP via Conditional Access |
| Phishing confirmed | Auto-purge all mailboxes |

---

## KQL — SOC Operations

### Alert Queue (Last 4h)

```kusto
SecurityAlert
| where TimeGenerated > ago(4h)
| where AlertSeverity in ("High", "Critical")
| project TimeGenerated, AlertName, AlertSeverity, CompromisedEntity, Tactics
| order by TimeGenerated desc
```

### Open Incidents by Severity

```kusto
SecurityIncident
| where Status != "Closed"
| summarize Count=count() by Severity, Status
| order by Severity asc
```

---

## MITRE ATT&CK

| Phase | Notes |
|---|---|
| All | SOC workflow maps triage actions to MITRE techniques per alert type |
