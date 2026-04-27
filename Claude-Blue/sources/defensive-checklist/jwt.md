# JWT Attack Detection

## Shortcut

- Monitor for JWT tokens with `"alg": "none"` — no legitimate application should accept unsigned tokens.
- Detect `RS256 → HS256` algorithm confusion: tokens claiming HMAC signature where the key would be the server's public RSA key.
- Alert on JWT tokens with unusually long headers or payloads — may indicate embedded attack payloads or JWK injection.
- Monitor for JWT signing secret brute force attempts: high-rate JWT verification failures or `hashcat -m 16500` artifacts on endpoint.
- In Entra ID / Azure AD context: detect tokens with unexpected issuers, missing `aud` claims, or replay of expired tokens.

---

## Detection Scope

| Attack | What to Detect |
|---|---|
| `alg:none` | JWT header `"alg":"none"` or `"alg":"None"` |
| Algorithm confusion | RS256/ES256 token sent to HS256-accepting endpoint |
| JWK injection | `"jwk"` or `"jku"` header pointing to attacker-controlled URL |
| Secret brute force | High-rate signature verification failures |
| Kid injection | `"kid"` header with SQL/file path injection |
| Claim manipulation | Modified `exp`, `nbf`, `iss`, `aud`, `sub` claims |
| Azure/Entra ID | Unexpected issuers, missing audience, expired but accepted tokens |

---

## Log Sources

| Source | Content | Platform |
|---|---|---|
| Application / API logs | JWT validation errors, algorithm details | Any |
| Azure Application Gateway WAF | Anomalous Authorization header patterns | Azure |
| Entra ID SigninLogs | Token issuance, app token events | Azure |
| AADNonInteractiveUserSignInLogs | Service-to-service token flows | Azure |
| MDE DeviceEvents | JWT library errors if verbose logging | MDE |
| Web proxy | Authorization header observation | Any |

---

## Sigma Rules

### JWT `alg:none` in Authorization Header

```yaml
title: JWT Algorithm None Attack in Authorization Header
id: c7d8e9f0-a1b2-3456-cdef-901234567026
status: experimental
description: >
  Detects JWT tokens with "alg":"none" — an attempt to bypass signature verification.
  The base64-encoded header `eyJhbGciOiJub25lIn0` decodes to {"alg":"none"}.
author: claude-blue
date: 2026-04-27
logsource:
  category: webserver
detection:
  selection:
    cs(Authorization)|contains:
      - 'eyJhbGciOiJub25lIn0'      # {"alg":"none"}
      - 'eyJhbGciOiAibm9uZSJ9'     # {"alg": "none"}
      - 'eyJhbGciOiJOb25lIn0'      # {"alg":"None"}
  condition: selection
falsepositives:
  - None expected in production
level: critical
tags:
  - attack.t1550
  - attack.defense_evasion
```

### JWK/JKU Injection in JWT Header

```yaml
title: JWT Header JWK or JKU Injection Attack
id: d8e9f0a1-b2c3-4567-defa-012345678027
status: experimental
description: >
  Detects JWT tokens with "jwk" or "jku" parameters in the header pointing to
  attacker-controlled key sources — enables signature bypass by providing own public key.
author: claude-blue
date: 2026-04-27
logsource:
  category: webserver
detection:
  selection_jwk:
    cs(Authorization)|contains:
      - '"jwk":'
      - '"jku":'
      - '"x5u":'    # X.509 URL — similar attack vector
  condition: selection
falsepositives:
  - Applications that legitimately use JKU (audit these)
level: high
tags:
  - attack.t1550
```

### High-Rate JWT Verification Failures (Secret Brute Force)

```yaml
title: High Rate of JWT Authentication Failures (Secret Brute Force)
id: e9f0a1b2-c3d4-5678-efab-123456789028
status: experimental
description: >
  Detects unusually high rates of JWT signature validation failures from a single source —
  indicator of offline HMAC secret brute force using hashcat or jwt_tool.
author: claude-blue
date: 2026-04-27
logsource:
  category: webserver
detection:
  selection:
    sc-status: 401
    cs(Authorization)|startswith: 'Bearer '
  timeframe: 5m
  condition: selection | count() by c-ip > 50
falsepositives:
  - Misconfigured clients rotating tokens rapidly
level: high
tags:
  - attack.t1110
```

### JWT `kid` Header Path Traversal / SQL Injection

```yaml
title: JWT Kid Header Path Traversal or Injection Attack
id: f0a1b2c3-d4e5-6789-fabc-234567890029
status: experimental
description: >
  Detects JWT tokens with `kid` parameter containing path traversal or SQL injection —
  used to point key lookup to /dev/null or attacker-controlled DB value.
author: claude-blue
date: 2026-04-27
logsource:
  category: webserver
detection:
  selection:
    # Base64-decode of {"kid":"../../..} or {"kid":"' OR 1=1"}
    # These patterns in raw Authorization header indicate kid manipulation
    cs(Authorization)|contains:
      - '..%2F'       # path traversal encoded
      - '..%5C'
      - '%27%20OR'    # SQL in kid
  condition: selection
falsepositives:
  - None expected
level: high
tags:
  - attack.t1550
```

---

## KQL — Azure / Entra ID / Microsoft Sentinel

### Entra ID: Tokens with Unexpected Issuers or Missing Audience

```kusto
SigninLogs
| where ResultType == 0  // Successful sign-in
| where AppId !in (
    // Add your known application IDs
    "00000003-0000-0000-c000-000000000000",  // MS Graph
    "797f4846-ba00-4fd7-ba43-dac1f8f63013"   // Azure AD PowerShell
  )
| where TokenIssuancePolicyId == ""
| project TimeGenerated, UserPrincipalName, AppDisplayName, AppId,
          IPAddress, Location, ClientAppUsed, AuthenticationRequirement
| order by TimeGenerated desc
```

### Entra ID: Non-Interactive Sign-ins with Unusual Audience

```kusto
AADNonInteractiveUserSignInLogs
| where ResultType == 0
| where ResourceDisplayName !in ("Microsoft Graph", "Azure Resource Manager", "Office 365")
| summarize count() by UserPrincipalName, ResourceDisplayName, AppDisplayName, IPAddress
| where count_ > 10
| order by count_ desc
```

### Sentinel: High-Rate 401 from Same IP (JWT Brute Force)

```kusto
AzureDiagnostics
| where ResourceType == "APPLICATIONGATEWAYS"
| where OperationName == "ApplicationGatewayAccess"
| where httpStatus_d == 401
| summarize FailureCount=count() by clientIP_s, bin(TimeGenerated, 5m)
| where FailureCount > 50
| order by FailureCount desc
```

### Azure AD: App-Only Tokens with Broad Permissions (T1528)

```kusto
AuditLogs
| where OperationName == "Add app role assignment to service principal"
| where TargetResources has "RoleDefinitionId"
| extend AppName = tostring(TargetResources[0].displayName)
| extend GrantedRole = tostring(TargetResources[0].modifiedProperties[0].newValue)
| project TimeGenerated, AppName, GrantedRole, InitiatedBy=tostring(InitiatedBy.user.userPrincipalName)
| order by TimeGenerated desc
```

---

## Response Checklist

| Step | Action |
|---|---|
| 1 | Identify attack type: alg:none, JWK injection, kid injection, or brute force |
| 2 | `alg:none` accepted: disable in JWT library config immediately |
| 3 | JWK/JKU injection: restrict key resolution to trusted internal JWKS endpoint only |
| 4 | Brute force: check if HMAC secret was compromised; rotate signing key |
| 5 | Rotate all existing sessions if secret is suspected compromised |
| 6 | Review Entra ID audit logs for unauthorized token issuance or role grants |
| 7 | Enable Entra ID sign-in risk policies to flag impossible travel and anomalous tokens |

---

## Hardening Reference

- **Explicitly validate `alg`**: whitelist only `RS256`, `ES256` — never `none` or `HS256` with a public key
- **Pin JWKS URI**: resolve keys only from your own `/.well-known/jwks.json` — reject `jku`/`jwk` headers
- **Validate all claims**: `iss`, `aud`, `exp`, `nbf` — reject tokens missing or with unexpected values
- **Short expiry + refresh tokens**: limit blast radius of stolen tokens
- **Entra ID**: enable token protection (binding tokens to device); use Conditional Access

---

## MITRE ATT&CK

| Technique | ID | Coverage |
|---|---|---|
| Use Alternate Authentication Material: Web Session Cookie | T1550.004 | JWT replay / forged tokens |
| Brute Force: Password Spraying | T1110.003 | JWT secret brute force |
| Steal Application Access Token | T1528 | JWT theft for app impersonation |
