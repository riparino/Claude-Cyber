---
name: defensive-parameter-pollution
description: "HTTP Parameter Pollution (HPP) detection: duplicate parameter names, WAF bypass via split payloads, mixed GET/POST pollution. Sigma rules for duplicate param patterns combined with injection keywords, KQL for Azure Application Gateway anomalous query strings. Use for WAF tuning and detection engineering."
---

# SKILL: HTTP Parameter Pollution Detection

## Metadata
- **Skill Name**: defensive-parameter-pollution
- **Folder**: Skills/defensive-parameter-pollution
- **Source**: sources/defensive-checklist/parameter-pollution.md
- **Mirrors**: offensive-parameter-pollution

## Trigger Phrases
Use this skill when the conversation involves any of:
`HTTP parameter pollution detection, HPP detection, duplicate parameter WAF bypass, parameter pollution Sigma, HPP KQL, WAF bypass detection parameter, detect duplicate query parameters`

## Instructions for Claude

When this skill is active:
1. HPP is primarily a WAF bypass technique — pair detection with downstream injection indicators
2. Sigma regex rule for duplicate parameter names in query strings
3. KQL for Azure Application Gateway detecting WAF-blocked HPP attempts
4. Check if the pollution achieved injection: look for SQLi/XSS alongside the duplicate params
5. Fix: normalize parameters before WAF inspection; reject duplicate param names at application level

---

## Full Methodology

# HTTP Parameter Pollution Detection

## Shortcut

- Duplicate param names: `?id=1&id=2` — log and alert.
- Most dangerous when combined with injection keywords (UNION, SELECT, script) split across the duplicates.
- WAF bypass: attacker puts safe value first, payload second, hoping WAF inspects first only.

---

## Detection: Key Signals

| Pattern | Indicator | Severity |
|---|---|---|
| Duplicate GET params | Same key `N` times in query string | Medium |
| Duplicate + injection keyword | Duplicate params with UNION/SELECT/script | High |
| Anomalous query string length | >500 chars with duplicate pattern | Medium |

---

## Sigma Rules (Summary)

1. **Duplicate parameters**: `cs-uri-query` regex match for same key twice → medium
2. **Duplicate + injection**: combine duplicate regex with injection keyword filter → high

See `sources/defensive-checklist/parameter-pollution.md` for full Sigma YAML.

---

## KQL — Azure Application Gateway

### WAF-Blocked HPP Attempts

```kusto
AzureDiagnostics
| where ResourceType == "APPLICATIONGATEWAYS"
| where OperationName == "ApplicationGatewayFirewall"
| where requestUri_s matches regex @"[?&]([^&=]+)=[^&]*&\1="
| project TimeGenerated, clientIP_s, requestUri_s, ruleId_s, action_s, message_s
| order by TimeGenerated desc
```

### Anomalous Query String Length with Duplication

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
| 1 | Identify what WAF rule was bypassed (if any) |
| 2 | Check downstream request: which param value reached the app? |
| 3 | Validate if injection succeeded: SQLi/XSS indicators in logs/DB |
| 4 | WAF: add custom rule blocking or flagging duplicate parameter names |
| 5 | Application: reject requests with duplicate param names |

---

## MITRE ATT&CK

| Technique | ID | Coverage |
|---|---|---|
| Obfuscated Files or Information | T1027 | WAF bypass via HPP |
| Exploit Public-Facing Application | T1190 | HPP enabling injection bypass |
