# Detection Engineering — Sigma Lifecycle & MITRE Coverage

## Overview
Detection engineering: Sigma rule development lifecycle, MITRE ATT&CK coverage mapping, false positive tuning methodology, detection quality scoring, pipeline from hypothesis to production rule.

## Shortcut

- Sigma rule lifecycle: Write → Test (replay logs) → Measure FP rate → Tune → Deploy → Monitor.
- MITRE Navigator: map active detection rules; identify coverage gaps.
- Detection quality score: TP rate + coverage breadth + FP rate (lower is better).
- Rule ID format: UUID v4; `status: experimental` → `test` → `stable`.

---

## Sigma Rule Anatomy

```yaml
title: <concise title>
id: <uuid v4>
status: experimental | test | stable
description: <what it detects>
logsource:
  category: webserver | process_creation | network_connection | ...
  product: windows | linux | azure
detection:
  selection:
    FieldName|contains: "value"
    FieldName|re: "regex"
  filter:
    FieldName|startswith: "benign_"
  condition: selection and not filter
falsepositives:
  - Known benign use cases
level: low | medium | high | critical
tags:
  - attack.t<technique_id>
  - attack.<tactic>
```

## Status Progression

| Status | Meaning | FP Rate |
|---|---|---|
| experimental | First draft; untested | Unknown |
| test | Tested in lab; some FPs expected | <20% |
| stable | Production; tuned | <5% |

---

## Detection Quality Scoring

| Metric | Target | Notes |
|---|---|---|
| TP Rate | >90% | Catch real attacks |
| FP Rate | <5% per week | Analyst fatigue prevention |
| Coverage | MITRE ATT&CK breadth | Navigator map |
| Latency | <5 min detection delay | Near-realtime |

---

## MITRE Coverage Mapping

Use ATT&CK Navigator to:
1. Import rule tag list as JSON
2. Color: green = covered, yellow = partial, red = gap
3. Prioritize high-frequency gap techniques for new rule development

---

## FP Tuning Methodology

1. **Identify FP pattern**: what legitimate activity triggers the rule?
2. **Add filter condition**: `filter: LegitProcess|startswith: "expected_"`
3. **Scope narrow**: tighten field values; avoid broad `contains` on short strings
4. **Allowlist entities**: known-good hosts/users via lookup table
5. **Time-box**: alert only during business hours for certain techniques

---

## KQL — Rule Performance Monitoring

### Alert Volume by Rule (Last 7d)

```kusto
SecurityAlert
| where TimeGenerated > ago(7d)
| summarize AlertCount=count() by AlertName, Severity
| order by AlertCount desc
```

### FP Rate Estimate (Closed as False Positive)

```kusto
SecurityIncident
| where TimeGenerated > ago(30d)
| where Status == "Closed"
| where Classification == "FalsePositive"
| summarize FPCount=count() by IncidentName
| order by FPCount desc
```

---

## Detection Pipeline

```
Hypothesis → Sigma Rule → Log Replay Test → FP Rate <5% → 
Deploy to SIEM → Monitor 2 weeks → Promote to stable
```

---

## MITRE ATT&CK

| Technique | ID | Detection Engineering Focus |
|---|---|---|
| All phases | — | Coverage gap analysis via Navigator |
