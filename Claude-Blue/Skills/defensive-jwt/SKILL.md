---
name: defensive-jwt
description: "JWT attack detection: alg:none bypass, JWK/JKU injection, algorithm confusion (RS256→HS256), kid header injection, secret brute force. Sigma rules for JWT header patterns, KQL for Entra ID SigninLogs and AuditLogs, AiTM post-MFA IP change detection. Use for SOC triage, identity security, and detection engineering."
---

# SKILL: JWT Attack Detection

## Metadata
- **Skill Name**: defensive-jwt
- **Folder**: Skills/defensive-jwt
- **Source**: sources/defensive-checklist/jwt.md
- **Mirrors**: offensive-jwt

## Trigger Phrases
Use this skill when the conversation involves any of:
`JWT detection, JWT attack, alg none detection, JWT brute force, algorithm confusion JWT, JWK injection, JKU injection, kid injection JWT, JWT signature bypass, detect JWT tampering, JWT Sigma, JWT KQL`

## Instructions for Claude

When this skill is active:
1. `alg:none` accepted = critical severity; disable in library config immediately
2. JWK/JKU injection = critical; restrict key resolution to internal JWKS URI only
3. Sigma rules for `alg:none` base64 pattern, JWK header, high-rate 401s
4. KQL for Entra ID SigninLogs (unexpected issuer, post-MFA IP change) and AuditLogs (app role grants)
5. Hardening: explicitly whitelist `RS256`/`ES256`; validate `iss`, `aud`, `exp` on every request

---

## Full Methodology

# JWT Attack Detection

## Shortcut

- `alg:none` in Authorization header = critical; no legitimate app should accept unsigned tokens.
- JWK/JKU header pointing to external URL = critical; attacker-supplied key bypass.
- RS256→HS256 algorithm confusion: detect by monitoring 401 spikes after JWT changes.
- Kid header path traversal or SQL injection: `kid` containing `../` or `'`.
- Secret brute force: >50 401 responses in 5m from same IP.

---

## Detection: Key Signals

| Attack | Indicator | Severity |
|---|---|---|
| `alg:none` | `eyJhbGciOiJub25lIn0` in Authorization | Critical |
| JWK injection | `"jwk":` or `"jku":` in JWT header | Critical |
| Algorithm confusion | RS256 endpoint accepting HS256-signed token | High |
| Secret brute force | >50 401s in 5m from single IP | High |
| Kid injection | `../` or `'` in kid claim | High |
| Claim manipulation | Modified `exp`/`iss`/`aud` | Medium |

---

## Sigma Rules (Summary)

1. **`alg:none`**: `cs(Authorization)` contains `eyJhbGciOiJub25lIn0` → critical
2. **JWK/JKU injection**: Authorization header contains `"jwk":` or `"jku":` → critical
3. **Brute force**: >50 401s in 5m from same IP → high
4. **Kid injection**: encoded `../` or `'` in Authorization header → high

See `sources/defensive-checklist/jwt.md` for full Sigma YAML.

---

## KQL — Entra ID / Azure Sentinel

### Unexpected Issuer or Audience in SigninLogs

```kusto
SigninLogs
| where ResultType == 0
| where AppId !in (
    "00000003-0000-0000-c000-000000000000",
    "797f4846-ba00-4fd7-ba43-dac1f8f63013"
  )
| where TokenIssuancePolicyId == ""
| project TimeGenerated, UserPrincipalName, AppDisplayName, AppId,
          IPAddress, Location, AuthenticationRequirement
| order by TimeGenerated desc
```

### AiTM: IP Change Post-MFA (Session Hijack)

```kusto
let MFASuccess = SigninLogs
    | where AuthenticationRequirement == "multiFactorAuthentication"
    | where ResultType == 0
    | project UserId, MFATime=TimeGenerated, MFA_IP=IPAddress, SessionId=CorrelationId;
let PostMFAAccess = SigninLogs
    | where ResultType == 0
    | project UserId, AccessTime=TimeGenerated, Access_IP=IPAddress, SessionId=CorrelationId,
              AppDisplayName;
MFASuccess
| join kind=inner PostMFAAccess on UserId, SessionId
| where MFA_IP != Access_IP
| where AccessTime between (MFATime .. (MFATime + 10m))
| project UserPrincipalName=UserId, MFATime, MFA_IP, AccessTime, Access_IP, AppDisplayName
| order by MFATime desc
```

---

## Response Checklist

| Step | Action |
|---|---|
| 1 | `alg:none` accepted: disable in JWT library config; re-deploy |
| 2 | JWK/JKU: block header parameters in library; pin to internal JWKS |
| 3 | Brute force confirmed: rotate HMAC secret; invalidate all sessions |
| 4 | AiTM detected: revoke session; reset user credentials |
| 5 | Review Entra ID for suspicious app consent grants |

---

## Hardening

- Whitelist only `RS256`/`ES256` — never `none` or `HS256` with public key
- Pin JWKS URI to internal endpoint; reject `jku`/`jwk` headers
- Validate `iss`, `aud`, `exp`, `nbf` on every token
- Entra ID: enable token protection; Conditional Access requiring compliant device

---

## MITRE ATT&CK

| Technique | ID | Coverage |
|---|---|---|
| Use Alternate Auth Material | T1550.004 | JWT bypass / forged token |
| Brute Force | T1110 | JWT secret brute force |
| Steal Application Access Token | T1528 | JWT theft |

---

## References & Verified Sources

**Specifications**
- RFC 7519 — JSON Web Token (JWT): https://datatracker.ietf.org/doc/html/rfc7519
- RFC 7515 — JSON Web Signature (JWS): https://datatracker.ietf.org/doc/html/rfc7515
- RFC 8725 — JWT Best Current Practices: https://datatracker.ietf.org/doc/html/rfc8725

**MITRE ATT&CK**
- T1550.004 Web Session Cookie / Alternate Auth: https://attack.mitre.org/techniques/T1550/004/
- T1528 Steal Application Access Token: https://attack.mitre.org/techniques/T1528/
- T1110 Brute Force: https://attack.mitre.org/techniques/T1110/

**OWASP & guidance**
- OWASP JWT Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html
- Auth0 — Critical vulnerabilities in JSON Web Token libraries: https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/

**Microsoft Entra ID token references**
- Access tokens (v1.0/v2.0): https://learn.microsoft.com/en-us/entra/identity-platform/access-tokens
- ID tokens: https://learn.microsoft.com/en-us/entra/identity-platform/id-tokens
- Token theft detection (Entra ID Protection): https://learn.microsoft.com/en-us/entra/id-protection/concept-identity-protection-risks

**Reference CVEs**
- CVE-2015-9235 jsonwebtoken alg confusion: https://nvd.nist.gov/vuln/detail/CVE-2015-9235
- CVE-2022-21449 Java ECDSA blank-signature bypass ("Psychic Signatures"): https://nvd.nist.gov/vuln/detail/CVE-2022-21449
