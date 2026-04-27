---
name: defensive-detection-engineering
description: "Detection engineering lifecycle: Sigma rule development, MITRE ATT&CK coverage mapping via Navigator, FP tuning methodology, detection quality scoring, rule promotion pipeline from experimental to stable. KQL for Sentinel alert volume and FP rate monitoring."
---

# SKILL: Detection Engineering

## Metadata
- **Skill Name**: defensive-detection-engineering
- **Folder**: Skills/defensive-detection-engineering
- **Source**: sources/defensive-checklist/detection-engineering.md

## Trigger Phrases
Use this skill when the conversation involves any of:
`detection engineering, Sigma rule development, MITRE coverage mapping, false positive tuning, detection quality, ATT&CK Navigator, rule FP rate, Sigma lifecycle, detection gap analysis, rule status experimental stable`

## Instructions for Claude

When this skill is active:
1. New rule: always start with `status: experimental`; test; promote to `stable` after 2-week low-FP
2. FP rate target: <5% per week for production rules; retune if exceeded
3. MITRE Navigator: export all rule tags; map coverage; identify gaps
4. Filter conditions: always scoped (specific field + specific value), not global exclusions
5. KQL: monitor alert volume by rule name; flag rules with >50 alerts/day for FP review

---

## Full Methodology

# Detection Engineering

## Sigma Rule Template

```yaml
title: <concise title>
id: <uuid v4>
status: experimental
description: <what it detects>
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    FieldName|contains: "value"
  filter:
    FieldName|startswith: "benign_"
  condition: selection and not filter
falsepositives:
  - Known benign cases
level: medium
tags:
  - attack.t<id>
```

## Status Progression

| Status | FP Rate | Duration |
|---|---|---|
| experimental | Unknown | First 2 weeks |
| test | <20% | 2–4 weeks |
| stable | <5% | Production |

---

## Detection Quality Score

| Metric | Target |
|---|---|
| TP Rate | >90% |
| FP Rate | <5% per week |
| MITRE Coverage | Breadth (Navigator) |
| Latency | <5 min |

---

## FP Tuning Workflow

1. Identify FP pattern (what legitimate activity triggers rule)
2. Add scoped filter: specific field + specific value
3. Test: replay with filter; confirm TP rate maintained
4. Document: update `falsepositives` field in Sigma

---

## KQL — Alert Volume Monitoring

```kusto
SecurityAlert
| where TimeGenerated > ago(7d)
| summarize AlertCount=count() by AlertName, Severity
| order by AlertCount desc
```

---

## MITRE ATT&CK

Coverage mapping via [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/): import rule tag JSON; identify red cells (gaps) to prioritize.
