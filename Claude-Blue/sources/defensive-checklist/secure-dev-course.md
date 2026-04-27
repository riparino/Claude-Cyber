# Secure Development Course — Defensive Practices

## Overview
Secure coding fundamentals, SAST/DAST integration into CI/CD, threat modeling, OWASP Top 10 mitigations, code review checklist, secrets management.

## Shortcut

- Input validation: allowlist > denylist; validate type, length, format.
- Output encoding: HTML encode before rendering into HTML context.
- Parameterized queries: no string concatenation with user input in SQL.
- Secrets: never in code/environment; use Key Vault / Secrets Manager.
- Threat model every new feature: STRIDE analysis.

---

## OWASP Top 10 Mitigations (2021)

| # | Category | Primary Mitigation |
|---|---|---|
| A01 | Broken Access Control | Deny by default; enforce server-side |
| A02 | Cryptographic Failures | TLS 1.2+; AES-256; bcrypt passwords |
| A03 | Injection | Parameterized queries; allowlist validation |
| A04 | Insecure Design | Threat model; secure SDLC |
| A05 | Security Misconfiguration | Automated config scanning; harden defaults |
| A06 | Vulnerable Components | SCA; patch policy |
| A07 | Auth Failures | MFA; account lockout; session expiry |
| A08 | Software Integrity Failures | Code signing; SBOM; artifact integrity |
| A09 | Logging Failures | Centralized logging; log auth events |
| A10 | SSRF | Allowlist outbound; block metadata endpoints |

---

## Secure Coding Patterns

### Input Validation
```python
# Allowlist example
import re
def validate_username(username):
    if not re.match(r'^[a-zA-Z0-9_]{3,30}$', username):
        raise ValueError("Invalid username")
    return username
```

### Parameterized Query
```python
# Correct
cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
# Wrong — SQL injection risk
cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
```

### Secrets Management
- Never in code: `.env` files excluded from version control
- Use: Azure Key Vault, AWS Secrets Manager, HashiCorp Vault
- Rotate: API keys every 90 days; service account passwords every 180 days

---

## SAST/DAST CI/CD Integration

| Stage | Tool | What It Finds |
|---|---|---|
| Pre-commit | git-secrets, Gitleaks | Secrets in code |
| PR check | Semgrep, CodeQL | SAST — logic flaws, injection |
| Build | Snyk, OWASP Dependency-Check | SCA — vulnerable dependencies |
| Deploy | OWASP ZAP | DAST — runtime web vulns |
| Production | Burp Enterprise | Continuous DAST |

---

## Threat Modeling (STRIDE)

| Threat | Example | Control |
|---|---|---|
| Spoofing | Forged JWT | Signature validation |
| Tampering | Modify request | HMAC, server-side state |
| Repudiation | No audit log | Immutable logging |
| Info Disclosure | Error message leaks stack | Generic error pages |
| Denial of Service | No rate limit | Rate limiting + WAF |
| Elevation of Privilege | IDOR | Authorization check per request |

---

## MITRE ATT&CK

| Technique | ID | Mitigation |
|---|---|---|
| Exploit Public-Facing App | T1190 | Input validation, parameterized queries |
| Server Software Component | T1505.003 | Secure upload handling |
| Credentials in Files | T1552.001 | Secrets management |
