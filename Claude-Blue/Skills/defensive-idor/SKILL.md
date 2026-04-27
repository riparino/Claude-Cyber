---
name: defensive-idor
description: "IDOR/broken object-level authorization detection: sequential ID enumeration, horizontal privilege escalation, cross-user resource access patterns, access log anomaly analysis. Sigma rules for API ID enumeration, KQL for SharePoint/OneDrive cross-user access and Azure API Gateway anomalies. Use for SOC triage and API security."
---

# SKILL: IDOR Detection

## Metadata
- **Skill Name**: defensive-idor
- **Folder**: Skills/defensive-idor
- **Source**: sources/defensive-checklist/idor.md
- **Mirrors**: offensive-idor

## Trigger Phrases
Use this skill when the conversation involves any of:
`IDOR detection, broken object level authorization, horizontal privilege escalation detection, API enumeration detection, BOLA detection, cross-user access detection, IDOR KQL, detect insecure direct object reference`

## Instructions for Claude

When this skill is active:
1. IDOR is detected via access pattern analysis — baseline per-user access volume then alert on deviation
2. Sigma: rate-based detection for single user accessing many resource IDs via API
3. KQL for SharePoint/OneDrive cross-user file access and API gateway ID enumeration
4. Critical: identify scope of data exposed — GDPR/breach notification may be required
5. Fix: server-side resource ownership validation on every request; switch to UUIDs

---

## Full Methodology

# IDOR Detection

## Shortcut

- One user accessing >30 different resource IDs via API in 5m = enumeration.
- SharePoint/OneDrive: user accessing `/personal/` paths belonging to other users.
- Access log anomaly: single session with high count of unique user/account IDs in URL paths.
- Application must log both session user and requested resource owner for proper IDOR detection.

---

## Detection: Key Signals

| Pattern | Indicator | Severity |
|---|---|---|
| Sequential ID enumeration | >30 unique numeric IDs accessed in 5m by one user | High |
| Cross-user OneDrive access | `/personal/<other-user>/` accessed | High |
| Parameter ≠ session user | Resource owner ID != authenticated user | High |
| Admin tool accessed by non-admin | URL patterns for privileged resources | High |

---

## Sigma Rules (Summary)

1. **Sequential ID enumeration**: single user accessing >30 `/api/v*/user|account|profile|order/[0-9]+` URIs in 5m → high
2. **Session user ≠ resource owner**: application-emitted event `EventID: access_control_violation` where resource owner ≠ session user → high

See `sources/defensive-checklist/idor.md` for full Sigma YAML.

---

## KQL — Azure / Microsoft Sentinel

### SharePoint/OneDrive: Cross-User File Access

```kusto
OfficeActivity
| where Operation in ("FileAccessed", "FileDownloaded", "FileViewed")
| where SiteUrl contains "/personal/"
| extend SiteOwner = extract(@"/personal/([^/]+)/", 1, SiteUrl)
| where SiteOwner !contains tostring(split(UserId, "@")[0])
| summarize AccessCount=count() by UserId, SiteOwner, ClientIP
| where AccessCount > 5
| order by AccessCount desc
```

### API Gateway: High-Rate ID Enumeration

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
| 1 | Identify all resource IDs accessed — determine data scope |
| 2 | Scope attacker's access: every ID they touched |
| 3 | Notify affected users per GDPR/regulatory requirements |
| 4 | Invalidate attacker's session immediately |
| 5 | Fix: enforce `resource.owner == session.user_id` server-side on every request |
| 6 | Switch from sequential integers to UUIDs |
| 7 | Add rate limiting on ID lookup endpoints |

---

## MITRE ATT&CK

| Technique | ID | Coverage |
|---|---|---|
| Valid Accounts | T1078 | Authenticated but unauthorized access |
| Data from Information Repositories | T1213 | Mass exfiltration via IDOR |
