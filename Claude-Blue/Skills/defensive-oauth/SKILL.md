---
name: defensive-oauth
description: "OAuth attack detection: consent phishing, AiTM proxy session hijacking, redirect URI manipulation, state parameter bypass (CSRF), token exfiltration. Sigma rules for redirect URI anomalies, KQL for Entra ID AuditLogs, SigninLogs, CloudAppEvents, and OfficeActivity. Use for identity security and SOC triage."
---

# SKILL: OAuth Attack Detection

## Metadata
- **Skill Name**: defensive-oauth
- **Folder**: Skills/defensive-oauth
- **Source**: sources/defensive-checklist/oauth.md
- **Mirrors**: offensive-oauth

## Trigger Phrases
Use this skill when the conversation involves any of:
`OAuth detection, consent phishing detection, AiTM detection, EvilProxy detection, Evilginx detection, OAuth redirect URI, OAuth token theft KQL, Entra ID consent abuse, OAuth CSRF detection, M365 session hijack`

## Instructions for Claude

When this skill is active:
1. Consent phishing: check AuditLogs for new app consent grants with Mail.Read/Files.ReadWrite
2. AiTM: correlate MFA success IP vs. subsequent session IP — discrepancy = critical
3. KQL for Entra ID SigninLogs, AuditLogs, CloudAppEvents, and OfficeActivity
4. Redirect URI detection: compare `redirect_uri` param against registered URIs allowlist
5. Hardening priority: FIDO2/passkeys (blocks AiTM), token protection, app consent governance

---

## Full Methodology

# OAuth Attack Detection

## Shortcut

- Consent phishing: AuditLogs for `Consent to application` with high-privilege scopes (`Mail.Read`, `Files.ReadWrite.All`, `offline_access`).
- AiTM (Evilginx, EvilProxy, Tycoon): MFA success from IP1, session used from IP2 within 10m = critical.
- External `redirect_uri`: alert on OAuth flows sending auth code to non-registered domains.
- Mass mailbox access after consent: OfficeActivity `MailItemsAccessed` from REST client.

---

## Detection: Key Signals

| Attack | Indicator | Severity |
|---|---|---|
| Consent phishing | New consent grant with Mail.Read/Files.ReadWrite | High |
| AiTM session hijack | IP change within 10m of MFA success | Critical |
| Redirect URI abuse | `redirect_uri` to external domain | High |
| CSRF (missing state) | OAuth `response_type=code` without `state` param | Medium |
| Token exfiltration | Refresh tokens sent to external host | High |
| Mass mailbox access | >50 MailItemsAccessed from REST in 1h | High |

---

## KQL — Entra ID / Microsoft Sentinel

### Consent Phishing: High-Privilege App Consent

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
    or Permissions contains "offline_access" or Permissions contains "Mail.Send"
| project TimeGenerated, ConsentedBy, AppName, Permissions
| order by TimeGenerated desc
```

### AiTM: IP Change After MFA Success

```kusto
let MFASuccess = SigninLogs
    | where AuthenticationRequirement == "multiFactorAuthentication"
    | where ResultType == 0
    | project UserId, UserPrincipalName, MFATime=TimeGenerated, MFA_IP=IPAddress, SessionId=CorrelationId;
let PostMFAAccess = SigninLogs
    | where ResultType == 0
    | project UserId, AccessTime=TimeGenerated, Access_IP=IPAddress, SessionId=CorrelationId,
              AppDisplayName;
MFASuccess
| join kind=inner PostMFAAccess on UserId, SessionId
| where MFA_IP != Access_IP
| where AccessTime between (MFATime .. (MFATime + 10m))
| project UserPrincipalName, MFATime, MFA_IP, AccessTime, Access_IP, AppDisplayName
| order by MFATime desc
```

### OfficeActivity: Mass Mailbox Access via OAuth App

```kusto
OfficeActivity
| where Operation == "MailItemsAccessed"
| where ClientInfoString contains "Client=REST"
| summarize MailboxAccessCount=count() by UserId, ClientInfoString, bin(TimeGenerated, 1h)
| where MailboxAccessCount > 50
| order by MailboxAccessCount desc
```

---

## Response Checklist

| Step | Action |
|---|---|
| 1 | Consent phishing: revoke app consent in Entra ID Enterprise Applications |
| 2 | AiTM confirmed: revoke all active sessions; reset credentials |
| 3 | Review OfficeActivity for mail/file access during compromised session |
| 4 | Check for mail forwarding rules, inbox rules, new delegations |
| 5 | Enforce Conditional Access: block legacy auth; require compliant device |
| 6 | Enable App governance policies for risky consent detection |

---

## Hardening

- **FIDO2/passkeys**: phishing-resistant MFA; AiTM cannot steal these
- **Token protection**: binds tokens to device; prevents replay from new IP
- **Conditional Access**: require compliant device + named location
- **App allowlist**: block consent to unapproved external apps

---

## MITRE ATT&CK

| Technique | ID | Coverage |
|---|---|---|
| Steal Application Access Token | T1528 | Consent phishing |
| Web Session Cookie Theft | T1539 | AiTM session hijack |
| Use Alternate Auth Material | T1550 | OAuth token replay |
| Phishing | T1566 | Consent phishing campaign |

---

## References & Verified Sources

**Specifications**
- RFC 6749 — OAuth 2.0 Authorization Framework: https://datatracker.ietf.org/doc/html/rfc6749
- RFC 6819 — OAuth 2.0 Threat Model & Security Considerations: https://datatracker.ietf.org/doc/html/rfc6819
- RFC 8252 — OAuth 2.0 for Native Apps: https://datatracker.ietf.org/doc/html/rfc8252
- RFC 9700 — OAuth 2.0 Security Best Current Practice: https://datatracker.ietf.org/doc/html/rfc9700

**MITRE ATT&CK**
- T1528 Steal Application Access Token: https://attack.mitre.org/techniques/T1528/
- T1539 Steal Web Session Cookie: https://attack.mitre.org/techniques/T1539/
- T1550 Use Alternate Authentication Material: https://attack.mitre.org/techniques/T1550/
- T1566 Phishing: https://attack.mitre.org/techniques/T1566/

**Microsoft guidance & detections**
- Detect & remediate illicit consent grants: https://learn.microsoft.com/en-us/defender-office-365/detect-and-remediate-illicit-consent-grants
- App consent policies: https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/configure-user-consent
- Risk-based Conditional Access: https://learn.microsoft.com/en-us/entra/id-protection/howto-identity-protection-configure-risk-policies
- Sentinel — OAuth & consent phishing detections: https://github.com/Azure/Azure-Sentinel/tree/master/Detections/AuditLogs

**Reference incidents**
- Midnight Blizzard OAuth consent attacks: https://www.microsoft.com/security/blog/2024/01/25/midnight-blizzard-guidance-for-responders-on-nation-state-attack/
- "PwnAuth" — illicit consent phishing toolkit (FireEye): https://cloud.google.com/blog/topics/threat-intelligence/pwnauth/
