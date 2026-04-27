---
name: defensive-secure-dev-course
description: "Secure development training: OWASP Top 10 mitigations, input validation patterns, parameterized queries, output encoding, secrets management, SAST/DAST CI/CD integration, STRIDE threat modeling. Mirrors offensive-exploit-dev-course from the defensive perspective."
---

# SKILL: Secure Development Course

## Metadata
- **Skill Name**: defensive-secure-dev-course
- **Folder**: Skills/defensive-secure-dev-course
- **Source**: sources/defensive-checklist/secure-dev-course.md
- **Mirrors**: offensive-exploit-dev-course

## Trigger Phrases
Use this skill when the conversation involves any of:
`secure coding, OWASP Top 10 mitigation, input validation, parameterized query, output encoding, secrets management, SAST DAST, threat modeling, STRIDE, secure SDLC, secure development practices`

## Instructions for Claude

When this skill is active:
1. Injection mitigation: parameterized queries only; never concatenate user input into SQL/LDAP/command
2. Secrets: never in code or environment variables; always Azure Key Vault / Secrets Manager
3. SAST at PR gate; DAST in staging before production deploy
4. Threat model every new feature: STRIDE per data flow
5. Output encoding: context-specific — HTML entity, URL encode, JSON encode as appropriate

---

## Full Methodology

# Secure Development Course

## Shortcut

- `cursor.execute("SELECT ... WHERE id = %s", (user_id,))` = correct parameterized query.
- `<%= escape_html(user_input) %>` = correct HTML output encoding.
- `.env` in `.gitignore`; secrets in Key Vault.
- Semgrep + CodeQL at PR = catch 80% of injection patterns before merge.

---

## OWASP Top 10 Quick Reference

| # | Category | Fix |
|---|---|---|
| A01 | Broken Access Control | Deny by default; server-side enforce |
| A02 | Cryptographic Failures | TLS 1.2+; bcrypt; AES-256 |
| A03 | Injection | Parameterized; allowlist validation |
| A04 | Insecure Design | STRIDE threat model |
| A06 | Vulnerable Components | SCA scan; patch policy |
| A07 | Auth Failures | MFA; lockout; session expiry |
| A10 | SSRF | Allowlist outbound; block IMDS |

---

## SAST/DAST Integration

| Stage | Tool | Finds |
|---|---|---|
| Pre-commit | Gitleaks | Secrets |
| PR check | Semgrep, CodeQL | Injection, SAST |
| Build | Snyk | Vulnerable dependencies |
| Staging | OWASP ZAP | Runtime DAST |

---

## STRIDE Template

| Threat | Control |
|---|---|
| Spoofing | Signature validation, MFA |
| Tampering | HMAC, server-side state |
| Repudiation | Immutable audit logs |
| Info Disclosure | Generic errors; no stack traces |
| DoS | Rate limiting + WAF |
| Elevation of Privilege | AuthZ check per request |

---

## MITRE ATT&CK

| Technique | ID | Mitigation |
|---|---|---|
| Exploit Public-Facing App | T1190 | Input validation |
| Credentials in Files | T1552.001 | Key Vault |
