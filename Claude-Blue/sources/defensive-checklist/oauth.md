# OAuth Attack Detection

## Shortcut

- Alert on OAuth authorization requests with `redirect_uri` values pointing to attacker-controlled domains (open redirect / token theft).
- Detect OAuth consent phishing: application registrations requesting broad scopes (`Mail.Read`, `Files.ReadWrite.All`) from users outside your tenant.
- Monitor for AiTM (Adversary-in-the-Middle) proxy kit indicators: cookie theft after successful MFA, sign-ins from Evilginx/EvilProxy infrastructure IPs.
- Detect stolen OAuth tokens in use: sessions from unexpected locations, device IDs, or user agents immediately after a sign-in.
- In Entra ID: alert on new app registrations, consent grants to external apps, and `offline_access` scope grants.

---

## Detection Scope

| Attack | What to Detect |
|---|---|
| Redirect URI manipulation | `redirect_uri` not matching registered URIs |
| Consent phishing | External apps requesting high-privilege scopes |
| AiTM session hijack | Session cookies used from new IP post-MFA |
| State parameter bypass | Missing or reused `state` param (CSRF) |
| Authorization code theft | Referer header leaking code, code replay |
| Token exfiltration | Refresh tokens exfiltrated to external hosts |
| Malicious app registration | New SPN/App with high-privilege role grants |

---

## Log Sources

| Source | Content | Platform |
|---|---|---|
| Entra ID SigninLogs | Authentication events, MFA results | Azure |
| AuditLogs | App registrations, consent grants, role assignments | Azure |
| AADNonInteractiveUserSignInLogs | Service token flows | Azure |
| CloudAppEvents | Defender for Cloud Apps — OAuth app activity | MDE/MDCA |
| OfficeActivity | File/mail access via OAuth token | M365 |
| Web server / proxy logs | OAuth `redirect_uri` parameters | Any |

---

## Sigma Rules

### OAuth Redirect URI to External/Unexpected Domain

```yaml
title: OAuth Authorization Request with External Redirect URI
id: a1b2c3d4-e5f6-7890-abce-345678901030
status: experimental
description: >
  Detects OAuth authorization requests where redirect_uri points to domains
  outside the application's registered redirect URIs — authorization code theft indicator.
author: claude-blue
date: 2026-04-27
logsource:
  category: webserver
detection:
  selection:
    cs-uri-query|contains: 'redirect_uri='
    cs-uri-query|re: 'redirect_uri=https?://(?!yourdomain\.com|api\.yourdomain\.com)'
  condition: selection
falsepositives:
  - Legitimate partner integrations (document expected redirect URIs)
level: high
tags:
  - attack.t1550
  - attack.credential_access
```

### OAuth `state` Parameter Missing (CSRF Risk)

```yaml
title: OAuth Authorization Request Missing State Parameter
id: b2c3d4e5-f6a7-8901-bcdf-456789012031
status: experimental
description: >
  Detects OAuth authorization requests without a `state` parameter — indicates
  CSRF vulnerability or attacker stripping CSRF protection.
author: claude-blue
date: 2026-04-27
logsource:
  category: webserver
detection:
  selection_oauth:
    cs-uri-query|contains:
      - 'response_type=code'
      - 'client_id='
  filter_has_state:
    cs-uri-query|contains: 'state='
  condition: selection_oauth and not filter_has_state
falsepositives:
  - Legacy OAuth integrations not implementing state (audit these)
level: medium
tags:
  - attack.t1550
```

### AiTM: Session Used Immediately from New IP Post-MFA

```yaml
title: Session Cookie Used From New IP Immediately After MFA (AiTM Indicator)
id: c3d4e5f6-a7b8-9012-cdeg-567890123032
status: experimental
description: >
  Detects rapid session usage from a different IP address immediately following
  successful MFA — indicator of AiTM proxy (Evilginx, EvilProxy, Tycoon) session hijack.
  Correlate SigninLogs MFA success with subsequent requests from different IP.
author: claude-blue
date: 2026-04-27
logsource:
  product: azure
  service: signin
detection:
  selection:
    ResultType: 0
    AuthenticationRequirement: 'multiFactorAuthentication'
  # Requires correlation: IP at MFA vs IP at resource access within 5min
  # Best implemented as KQL with join logic (see KQL section)
  condition: selection
falsepositives:
  - VPN change, corporate proxy switchover
level: high
tags:
  - attack.t1539
  - attack.t1550
```

---

## KQL — Azure / Entra ID

### Entra ID: New OAuth App Consent Grants (Consent Phishing)

```kusto
AuditLogs
| where OperationName in (
    "Consent to application",
    "Add delegated permission grant",
    "Add app role assignment to service principal"
  )
| extend ConsentedBy = tostring(InitiatedBy.user.userPrincipalName)
| extend AppName = tostring(TargetResources[0].displayName)
| extend Permissions = tostring(TargetResources[0].modifiedProperties)
| where Permissions contains "Mail.Read" or Permissions contains "Files.ReadWrite"
    or Permissions contains "offline_access" or Permissions contains "User.Read.All"
    or Permissions contains "Mail.Send"
| project TimeGenerated, ConsentedBy, AppName, Permissions, OperationName
| order by TimeGenerated desc
```

### Entra ID: New External App Registrations with High Privilege

```kusto
AuditLogs
| where OperationName == "Add application"
| extend AppName = tostring(TargetResources[0].displayName)
| extend CreatedBy = tostring(InitiatedBy.user.userPrincipalName)
| project TimeGenerated, AppName, CreatedBy
| order by TimeGenerated desc
```

### AiTM Detection: IP Change After MFA Success

```kusto
// Detect sessions where MFA succeeded from IP1, then the session was used from IP2 within 10 min
let MFASuccess = SigninLogs
    | where AuthenticationRequirement == "multiFactorAuthentication"
    | where ResultType == 0
    | project UserId, UserPrincipalName, MFATime=TimeGenerated, MFA_IP=IPAddress, SessionId=CorrelationId;
let PostMFAAccess = SigninLogs
    | where ResultType == 0
    | project UserId, AccessTime=TimeGenerated, Access_IP=IPAddress, SessionId=CorrelationId,
              AppDisplayName, ConditionalAccessStatus;
MFASuccess
| join kind=inner PostMFAAccess on UserId, SessionId
| where MFA_IP != Access_IP
| where AccessTime between (MFATime .. (MFATime + 10m))
| project UserPrincipalName, MFATime, MFA_IP, AccessTime, Access_IP, AppDisplayName
| order by MFATime desc
```

### Defender for Cloud Apps: OAuth App Accessing Mail/Files

```kusto
CloudAppEvents
| where Application == "Microsoft Exchange Online" or Application == "Microsoft SharePoint Online"
| where ActionType == "MailItemsAccessed" or ActionType == "FileDownloaded"
| where AccountType == "Regular"
// Flag accesses from apps not in your approved inventory
| summarize AccessCount=count(), UniqueFiles=dcount(ObjectName)
    by AccountUpn, Application, ActionType, IPAddress
| where AccessCount > 100
| order by AccessCount desc
```

### OfficeActivity: Mass Mail Access by OAuth App (Post-Consent Phishing)

```kusto
OfficeActivity
| where Operation == "MailItemsAccessed"
| where ClientInfoString contains "Client=REST" // API access, not web client
| summarize MailboxAccessCount=count() by UserId, ClientInfoString, bin(TimeGenerated, 1h)
| where MailboxAccessCount > 50
| order by MailboxAccessCount desc
```

---

## Response Checklist

| Step | Action |
|---|---|
| 1 | Consent phishing: revoke app consent immediately (Entra ID Enterprise Applications → Permissions) |
| 2 | AiTM confirmed: revoke all active sessions for affected user; reset credentials |
| 3 | Review all actions taken with the stolen session (OfficeActivity, CloudAppEvents) |
| 4 | Check for mail forwarding rules, Inbox rules, delegations created post-compromise |
| 5 | Review OAuth apps with `offline_access` + high-privilege scope grants |
| 6 | Enforce Conditional Access: block legacy auth, require compliant device |
| 7 | Enable Entra ID App governance policies for risky app detection |

---

## Hardening Reference

- **FIDO2 / Passkeys**: phishing-resistant MFA — AiTM proxy kits cannot steal these
- **Token Protection**: binds token to device (preview) — prevents replay from new IP
- **Conditional Access**: require compliant device + named location for sensitive apps
- **App allowlist**: block consent to apps not pre-approved by IT
- **Entra ID App governance**: auto-revoke apps exceeding permission baseline

---

## MITRE ATT&CK

| Technique | ID | Coverage |
|---|---|---|
| Steal Application Access Token | T1528 | OAuth consent phishing |
| Web Session Cookie Theft | T1539 | AiTM session hijack |
| Use Alternate Auth Material | T1550 | OAuth token replay |
| Phishing | T1566 | Consent phishing campaign |
