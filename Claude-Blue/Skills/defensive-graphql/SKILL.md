---
name: defensive-graphql
description: "GraphQL security detection: introspection abuse, batch attack, deep query DoS, alias brute force, SSRF via schema. Sigma for introspection from external sources and batch operations. KQL for Azure Application Gateway GraphQL anomalies. Use for API security monitoring and hardening."
---

# SKILL: GraphQL Security

## Metadata
- **Skill Name**: defensive-graphql
- **Folder**: Skills/defensive-graphql
- **Source**: sources/defensive-checklist/graphql.md
- **Mirrors**: offensive-graphql

## Trigger Phrases
Use this skill when the conversation involves any of:
`GraphQL detection, introspection detection, GraphQL batch attack, GraphQL DoS, GraphQL Sigma, GraphQL KQL, GraphQL rate limiting, GraphQL hardening, disable introspection, GraphQL depth limit`

## Instructions for Claude

When this skill is active:
1. Introspection from external IP = disable in production; return 400 on `__schema`
2. Batch attack: JSON array body with >N operations = DoS or brute force; rate limit
3. KQL: Azure App Gateway for large body requests to `/graphql` endpoint
4. Hardening priority: disable introspection → depth limit (7) → complexity scoring → alias limit
5. Alias abuse in mutations can bypass per-operation rate limits; detect repeated mutation fields

---

## Full Methodology

# GraphQL Security Detection

## Shortcut

- `__schema` in request body from external IP = information disclosure.
- JSON array body `[{query:...},{query:...}]` = batch attack; reject or limit.
- Depth >7 nested selectors = abuse or DoS.
- Multiple aliases for same mutation = brute force rate-limit bypass.

---

## Key Detection Signals

| Attack | Indicator | Severity |
|---|---|---|
| Introspection | `__schema`/`__type` in body | Medium |
| Batch attack | JSON array body to `/graphql` | High |
| Deep query | Nested depth >7 | Medium |
| Alias brute force | Multiple aliases for mutation | High |
| SSRF | URL-resolving scalar with external host | High |

---

## KQL — Azure Application Gateway

### Introspection Queries from External Sources

```kusto
AzureDiagnostics
| where ResourceType == "APPLICATIONGATEWAYS"
| where requestUri_s contains "/graphql"
| where Message contains "__schema" or Message contains "__type"
| where clientIP_s !startswith "10." and clientIP_s !startswith "172." and clientIP_s !startswith "192.168."
| project TimeGenerated, clientIP_s, requestUri_s, Message
| order by TimeGenerated desc
```

### Large GraphQL Requests (Batch/Complexity Attack)

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

## Response Checklist

| Step | Action |
|---|---|
| 1 | Introspection: disable in production (return 400 on `__schema`) |
| 2 | Batch attack: enforce max operations per request (1–5) |
| 3 | Deep query: implement depth and complexity limits |
| 4 | Alias brute force: deduplicate mutation fields per request |
| 5 | Use persisted queries in production |

---

## MITRE ATT&CK

| Technique | ID | Coverage |
|---|---|---|
| Active Scanning | T1595 | Introspection schema enumeration |
| Resource Exhaustion | T1499 | Batch/deep query DoS |
