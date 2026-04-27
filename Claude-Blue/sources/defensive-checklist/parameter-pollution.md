# Parameter Pollution Detection

## Shortcut

- Alert on HTTP requests containing duplicate parameter names: `?id=1&id=2`.
- Detect backend-reaching parameters hidden behind duplicate names (WAF bypass technique).
- Monitor for query string and POST body parameter anomalies that suggest HPP (HTTP Parameter Pollution) payloads.
- Primarily a WAF bypass technique — check if duplicate params appear in requests that subsequently triggered downstream errors.

---

## Detection Scope

| Vector | What to Detect |
|---|---|
| Duplicate GET params | Same key appearing multiple times: `?id=1&id=2` |
| Duplicate POST body params | Same param in body multiple times |
| Mixed GET+POST pollution | Same param in both locations |
| WAF bypass via pollution | Malicious value split across two params |
| Backend routing anomaly | Param passed to downstream service differs from WAF-visible value |

---

## Sigma Rules

### Duplicate Parameters in HTTP Request

```yaml
title: HTTP Parameter Pollution - Duplicate Parameters
id: b8c9d0e1-f2a3-4567-bcde-012345678037
status: experimental
description: >
  Detects HTTP requests containing the same parameter name multiple times —
  used to bypass WAF rules by splitting payloads across duplicate parameters.
author: claude-blue
date: 2026-04-27
logsource:
  category: webserver
detection:
  selection:
    cs-uri-query|re: '([?&]([^&=]+)=[^&]*)&\2='
  condition: selection
falsepositives:
  - Frameworks generating duplicate checkbox/multi-select params (audit)
level: medium
tags:
  - attack.defense_evasion
  - attack.t1027
```

### HPP with Injection Payload Split

```yaml
title: HTTP Parameter Pollution with Split Injection Payload
id: c9d0e1f2-a3b4-5678-cdef-123456789038
status: experimental
description: >
  Detects potential WAF bypass where injection payload is split across
  duplicate parameters. Combines HPP pattern with injection keywords.
author: claude-blue
date: 2026-04-27
logsource:
  category: webserver
detection:
  selection_dup:
    cs-uri-query|re: '([?&]([^&=]+)=[^&]*)&\2='
  selection_injection:
    cs-uri-query|contains:
      - 'UNION'
      - 'SELECT'
      - 'script'
      - 'EXEC'
  condition: selection_dup and selection_injection
falsepositives:
  - WAF test traffic
level: high
tags:
  - attack.defense_evasion
  - attack.t1027
```

---

## KQL — Azure / Microsoft Sentinel

### Azure WAF: Blocked Requests with Duplicate Parameters

```kusto
AzureDiagnostics
| where ResourceType == "APPLICATIONGATEWAYS"
| where OperationName == "ApplicationGatewayFirewall"
| where requestUri_s matches regex @"[?&]([^&=]+)=[^&]*&\1="
| project TimeGenerated, clientIP_s, requestUri_s, ruleId_s, action_s, message_s
| order by TimeGenerated desc
```

### Application Gateway Access Log: Anomalous Query String Length

```kusto
AzureDiagnostics
| where ResourceType == "APPLICATIONGATEWAYS"
| where OperationName == "ApplicationGatewayAccess"
| extend QSLength = strlen(queryString_s)
| where QSLength > 500
| where queryString_s matches regex @"([^&=]+)=[^&]*&\1="
| project TimeGenerated, clientIP_s, requestUri_s, QSLength, httpStatus_d
| order by QSLength desc
```

---

## Response Checklist

| Step | Action |
|---|---|
| 1 | Identify what was bypassed: WAF rule vs. application logic |
| 2 | Check downstream request logs to confirm which param value was processed |
| 3 | Validate if the pollution achieved injection: check for SQLi, XSS indicators |
| 4 | Fix application: use consistent framework behavior for duplicate params |
| 5 | WAF custom rule: block or flag requests with duplicate parameter names |

---

## Hardening Reference

- **Normalize parameters before WAF inspection**: reject or de-duplicate before processing
- **Application-level uniqueness enforcement**: reject requests with duplicate param names
- **Framework configuration**: PHP/ASP.NET handle duplicates differently — know your framework's behavior

---

## MITRE ATT&CK

| Technique | ID | Coverage |
|---|---|---|
| Obfuscated Files or Information | T1027 | WAF bypass via parameter pollution |
| Exploitation of Public-Facing Application | T1190 | HPP enabling SQLi/XSS bypass |
