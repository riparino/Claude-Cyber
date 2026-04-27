# IDOR Detection

## Shortcut

- Detect horizontal privilege escalation: user accessing resource IDs that don't belong to them (high-rate sequential ID access, ID patterns outside the user's usual range).
- Monitor access log anomalies: a single user accessing many different user IDs' resources in a short window.
- Entra ID / Azure: detect cross-user resource access via AuditLogs, OfficeActivity, and StorageActivity.
- IDOR is primarily detected through access pattern analysis — baseline per-user access volume, then alert on deviation.

---

## Detection Scope

| Pattern | What to Detect |
|---|---|
| Sequential ID enumeration | User accessing monotonically increasing IDs |
| High-cardinality user-ID access | One user accessing many users' data |
| Parameter manipulation | IDs changed in request vs session-bound user |
| Insecure direct object reference in file paths | `../../../user/42/report.pdf` |
| API response data belonging to other users | Response contains other-user PII |

---

## Log Sources

| Source | Content | Platform |
|---|---|---|
| Application access logs | Resource IDs accessed per user per session | Any |
| Azure Application Gateway / WAF | URL parameters, path components | Azure |
| AuditLogs | Entra ID resource access | Azure |
| OfficeActivity | SharePoint/OneDrive cross-user access | M365 |
| Web proxy logs | URL patterns per user | Any |

---

## Sigma Rules

### Sequential Resource ID Access (IDOR Enumeration)

```yaml
title: IDOR - Sequential Resource ID Enumeration by Single User
id: d4e5f6a7-b8c9-0123-defa-678901234033
status: experimental
description: >
  Detects a single authenticated user accessing many different resource IDs in short
  time — indicative of horizontal privilege escalation enumeration.
author: claude-blue
date: 2026-04-27
logsource:
  category: webserver
detection:
  selection:
    sc-status: 200
    cs-uri-stem|re: '/api/v[0-9]+/(user|account|profile|order|invoice)/[0-9]+'
  timeframe: 5m
  condition: selection | count() by cs-username > 30
falsepositives:
  - Admin users legitimately batch-accessing many resources (allowlist admins)
level: high
tags:
  - attack.t1078
  - attack.credential_access
```

### Vertical/Horizontal Privilege Escalation via Parameter Manipulation

```yaml
title: User ID Parameter Not Matching Authenticated Session
id: e5f6a7b8-c9d0-1234-efab-789012345034
status: experimental
description: >
  Detects requests where a user ID or account ID parameter in the URL
  does not match the authenticated session user — IDOR exploitation pattern.
  Requires application to log both session user and requested resource owner ID.
author: claude-blue
date: 2026-04-27
logsource:
  category: application
detection:
  selection:
    EventID: 'access_control_violation'  # Application must emit this
    session_user|not: '%resource_owner%'
  condition: selection
falsepositives:
  - Admin or support roles legitimately accessing other users (document)
level: high
tags:
  - attack.t1078
```

---

## KQL — Azure / Microsoft Sentinel

### SharePoint/OneDrive: Cross-User File Access Anomaly

```kusto
OfficeActivity
| where Operation in ("FileAccessed", "FileDownloaded", "FileViewed")
| where SiteUrl contains "/personal/"  // OneDrive paths
| extend SiteOwner = extract(@"/personal/([^/]+)/", 1, SiteUrl)
| where SiteOwner !contains tostring(split(UserId, "@")[0])  // User accessing another's OneDrive
| summarize AccessCount=count() by UserId, SiteOwner, ClientIP
| where AccessCount > 5
| order by AccessCount desc
```

### Azure Storage: Cross-Account Blob Access

```kusto
StorageBlobLogs
| where OperationName in ("GetBlob", "ListBlobs")
| where AuthenticationType == "OAuth"
| extend ResourcePath = tostring(Uri)
| summarize AccessCount=count(), UniqueContainers=dcount(ResourcePath) by CallerIpAddress, AccountName
| where UniqueContainers > 10
| order by UniqueContainers desc
```

### API Gateway: High-Rate ID Enumeration by Single IP

```kusto
AzureDiagnostics
| where ResourceType == "APPLICATIONGATEWAYS"
| where OperationName == "ApplicationGatewayAccess"
| where requestUri_s matches regex "/api/v[0-9]+/(user|account|profile|order)/[0-9]+"
| summarize RequestCount=count(), UniqueIDs=dcount(requestUri_s)
    by clientIP_s, bin(TimeGenerated, 5m)
| where UniqueIDs > 30
| order by UniqueIDs desc
```

---

## Response Checklist

| Step | Action |
|---|---|
| 1 | Identify affected resource IDs — determine what data was exposed |
| 2 | Scope the attacker's access: all resource IDs they touched |
| 3 | Notify affected users per GDPR/regulatory requirements if PII was exposed |
| 4 | Force session invalidation for attacker's session |
| 5 | Fix: enforce resource ownership validation server-side per request |
| 6 | Switch from sequential integer IDs to non-guessable UUIDs |

---

## Hardening Reference

- **Resource ownership check on every request**: validate `resource.owner == session.user_id` server-side
- **UUIDs not sequential integers**: eliminates enumeration
- **Rate limiting**: limit ID lookups per session per minute
- **Centralized authorization middleware**: never trust client-supplied user/account IDs

---

## MITRE ATT&CK

| Technique | ID | Coverage |
|---|---|---|
| Valid Accounts | T1078 | Accessing resources with legitimate auth but wrong authorization |
| Data from Information Repositories | T1213 | Mass data exfiltration via IDOR |
