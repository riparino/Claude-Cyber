# GraphQL Security — Detection & Defense

## Overview
GraphQL introspection abuse, batch attack DoS, depth/complexity exploitation, field injection, SSRF via schema. Azure WAF KQL targeting GraphQL patterns.

## Shortcut

- Introspection query `__schema` from non-internal IP = information disclosure.
- Array of operations `[{query:...},{query:...}]` >10 in single request = batch DoS.
- Query depth >10 (nested) = abuse or DoS; set `maxDepth` enforcement.
- Mutation with aliased batch = query alias bypass for brute force.
- SSRF via subscription or URL-resolving custom scalars.

---

## Attack Patterns to Detect

### 1. Introspection Query
```
{ __schema { types { name fields { name } } } }
```
Detection: HTTP request body contains `__schema` or `__type` from non-internal source.

### 2. Batch Attack
```json
[
  {"query": "mutation { resetPassword(email: \"a@b.com\") }"},
  {"query": "mutation { resetPassword(email: \"b@b.com\") }"}
]
```
Detection: Request body is JSON array with >N operations.

### 3. Deep Query (DoS)
```graphql
{ a { b { c { d { e { f { name } } } } } } }
```
Detection: Nested depth beyond threshold; reject or limit.

### 4. Alias Abuse (Brute Force Rate Limit Bypass)
```graphql
{ a1: login(user:"x", pass:"a"), a2: login(user:"x", pass:"b") }
```
Detection: Multiple aliases for same mutation field.

---

## Sigma Rules

```yaml
title: GraphQL Introspection from External Source
id: 8f9a1234-5678-90bc-def0-1234567890ab
status: experimental
description: Detects GraphQL introspection queries from non-internal sources
logsource:
  category: webserver
detection:
  selection:
    c-uri|contains: /graphql
    cs-bytes|contains:
      - "__schema"
      - "__type"
  filter:
    c-ip|cidr:
      - 10.0.0.0/8
      - 172.16.0.0/12
      - 192.168.0.0/16
  condition: selection and not filter
falsepositives:
  - Developer tools in non-production environments
level: medium
tags:
  - attack.discovery
  - attack.t1590
```

```yaml
title: GraphQL Batch Attack
id: 9a0b2345-6789-01cd-ef01-2345678901bc
status: experimental
description: Detects JSON array body indicating GraphQL batch operation
logsource:
  category: webserver
detection:
  selection:
    c-uri|contains: /graphql
    cs-method: POST
    # Request body starts with array
    cs-body|startswith: "["
  condition: selection
falsepositives:
  - Legitimate batch operations from internal tooling
level: medium
tags:
  - attack.t1499
```

---

## KQL — Azure WAF / Application Gateway

### Introspection Queries

```kusto
AzureDiagnostics
| where ResourceType == "APPLICATIONGATEWAYS"
| where requestUri_s contains "/graphql"
| where Message contains "__schema" or Message contains "__type"
| where clientIP_s !startswith "10." and clientIP_s !startswith "172." and clientIP_s !startswith "192.168."
| project TimeGenerated, clientIP_s, requestUri_s, Message
| order by TimeGenerated desc
```

### Batch Operation Anomaly

```kusto
AzureDiagnostics
| where ResourceType == "APPLICATIONGATEWAYS"
| where requestUri_s contains "/graphql"
| where requestContentLength_d > 5000
| summarize RequestCount=count(), AvgSize=avg(requestContentLength_d) by clientIP_s, bin(TimeGenerated, 5m)
| where RequestCount > 20 or AvgSize > 10000
| order by RequestCount desc
```

---

## Hardening

| Control | Implementation |
|---|---|
| Disable introspection | Production: return 400 on `__schema` |
| Query depth limit | Max 5–7 levels; reject deeper |
| Query complexity limit | Score fields; reject above threshold |
| Batch limit | Reject arrays >1 operation (or limit to 5) |
| Rate limiting | Per-user/IP; use persisted queries |

---

## MITRE ATT&CK

| Technique | ID | Notes |
|---|---|---|
| Active Scanning | T1595 | Introspection-based schema enumeration |
| Resource Exhaustion | T1499 | Batch/deep query DoS |
