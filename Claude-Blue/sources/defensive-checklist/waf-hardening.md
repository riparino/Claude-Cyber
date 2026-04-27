# WAF Hardening — Detection & Defense

## Overview
Web Application Firewall configuration, rule tuning, gap analysis, mode progression (Detection → Prevention). Azure WAF CRS OWASP 3.2. Sigma for WAF rule bypasses. KQL for WAF logs to identify blind spots.

## Shortcut

- WAF in Detection mode = logging only; no blocking. Switch to Prevention after tuning FPs.
- Azure WAF CRS OWASP rule sets: XSS 941xxx, SQLi 942xxx, RCE 932xxx, XXE 921xxx, Java 944xxx.
- High-confidence block rules: RuleId `942100`, `941310`, `932160`.
- FP tuning: exclusions by RequestHeaderNames, RequestArgNames, RequestBodyPostArgNames.
- `az network application-gateway waf-policy rule-set` — set to OWASP 3.2.

---

## WAF Rule Sets (Azure CRS Mapping)

| CRS Rule Group | Rule IDs | Attack Type |
|---|---|---|
| REQUEST-941 | 941xxx | XSS |
| REQUEST-942 | 942xxx | SQL Injection |
| REQUEST-932 | 932xxx | RCE (OS Command) |
| REQUEST-921 | 921xxx | Protocol Attack/XXE |
| REQUEST-944 | 944xxx | Java / Deserialization |
| REQUEST-933 | 933xxx | PHP Injection |
| REQUEST-934 | 934xxx | SSRF |

---

## Detection Mode vs Prevention Mode

| Mode | Behavior | Use Case |
|---|---|---|
| Detection | Log only; no block | Initial tuning, FP reduction |
| Prevention | Block matched traffic | Production after tuning |

Transition steps:
1. Enable Detection mode; monitor for 2–4 weeks
2. Review FPs by rule ID; add exclusions for legitimate patterns
3. Enable Prevention mode
4. Continue monitoring; tune exclusions

---

## WAF Gap Analysis (Blind Spots)

| Gap | Why WAF Misses It | Mitigation |
|---|---|---|
| Encoded payloads | WAF decodes once; double-encode bypasses | Enable full decode in CRS |
| Custom rule bypass | Only OOTB rules enabled | Add custom rules for app-specific patterns |
| JSON body attack | CRS may not deep-inspect JSON | Enable `RequestBodyInspectLimitInKB` |
| HTTP/2 smuggling | Some WAFs don't inspect H2 | Use WAF that supports HTTP/2 inspection |

---

## Sigma Rules

```yaml
title: WAF in Detection Mode - Block Rule Not Enforcing
id: c3d4e567-8901-cdef-0123-4567890123ef
status: experimental
description: Azure WAF matched a high-severity rule but did not block (Detection mode)
logsource:
  service: azurewaf
detection:
  selection:
    action: Matched
    ruleId|startswith:
      - "942"
      - "941"
      - "932"
  condition: selection
falsepositives:
  - Normal in Detection mode during tuning
level: informational
tags:
  - attack.defense-evasion
```

```yaml
title: WAF Block Rule Bypass via Encoded Payload
id: d4e5f678-9012-def0-1234-5678901234f0
status: experimental
description: Repeated WAF rule matches followed by successful 200 response (possible bypass)
logsource:
  service: azurewaf
detection:
  selection:
    action: Matched
    httpStatusCode: 200
    ruleId|startswith:
      - "942"
      - "941"
  condition: selection
falsepositives:
  - Detection mode (all matched = 200 is expected)
level: high
tags:
  - attack.defense-evasion
  - attack.t1027
```

---

## KQL — Azure WAF

### Rules Matching but Not Blocking (Detection Mode Exposure)

```kusto
AzureDiagnostics
| where ResourceType == "APPLICATIONGATEWAYS"
| where OperationName == "ApplicationGatewayFirewall"
| where action_s == "Matched"
| where ruleId_s startswith "942" or ruleId_s startswith "941" or ruleId_s startswith "932"
| summarize MatchCount=count() by ruleId_s, clientIP_s, bin(TimeGenerated, 1h)
| order by MatchCount desc
```

### Top Blocked IPs

```kusto
AzureDiagnostics
| where ResourceType == "APPLICATIONGATEWAYS"
| where OperationName == "ApplicationGatewayFirewall"
| where action_s == "Blocked"
| summarize BlockCount=count() by clientIP_s
| top 20 by BlockCount desc
```

### Rule IDs Generating Most Alerts

```kusto
AzureDiagnostics
| where ResourceType == "APPLICATIONGATEWAYS"
| where OperationName == "ApplicationGatewayFirewall"
| summarize Count=count() by ruleId_s, action_s
| order by Count desc
```

---

## Hardening Checklist

| Control | Recommended Setting |
|---|---|
| Mode | Prevention |
| CRS Version | OWASP 3.2 |
| Request Body Inspection | Enabled, limit 128 KB |
| Exclusions | Scoped (arg-specific, not global) |
| Custom rules | App-specific patterns |
| Bot protection | Enabled |
| Rate limiting | Custom rule: >100 req/min/IP |

---

## MITRE ATT&CK

| Technique | ID | Notes |
|---|---|---|
| Impair Defenses | T1562 | WAF disabled/bypass |
| Obfuscated Files | T1027 | Encoding to bypass WAF rules |
