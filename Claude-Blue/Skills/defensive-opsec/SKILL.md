---
name: defensive-opsec
description: "Organizational OPSEC and exposure reduction: leaked credential monitoring, subdomain exposure via certificate transparency, GitHub secret scanning, job posting intelligence leakage, DNS zone transfer prevention. KQL for Entra ID SigninLogs from breached credentials. Sigma for DNS AXFR. Mirrors offensive-osint."
---

# SKILL: Organizational OPSEC

## Metadata
- **Skill Name**: defensive-opsec
- **Folder**: Skills/defensive-opsec
- **Source**: sources/defensive-checklist/opsec.md
- **Mirrors**: offensive-osint

## Trigger Phrases
Use this skill when the conversation involves any of:
`organizational OPSEC, credential leak monitoring, certificate transparency exposure, GitHub secret scanning, subdomain exposure, DNS zone transfer, job posting OSINT, HIBP monitoring, attack surface reduction`

## Instructions for Claude

When this skill is active:
1. Check crt.sh for org subdomain exposure; dev/staging exposed = remediate immediately
2. GitHub: run TruffleHog/GitLeaks on all repos; add pre-commit hooks
3. KQL: SigninLogs for sign-in from anonymized IP or malware-flagged network
4. Credential leak confirmed: force password reset for affected accounts; MFA all
5. DNS: block AXFR from external; restrict zone transfer to secondary NS only

---

## Full Methodology

# Organizational OPSEC

## Shortcut

- `crt.sh ?q=%.<domain>` = all certificates issued for domain = subdomain enumeration.
- GitHub secret scan: `git log -p | grep -E "(password|api_key|secret|token)"`.
- HIBP API: monitor for corporate email domain in breach data.
- DNS AXFR from external = full zone enumeration if not blocked.

---

## Exposure Vectors

| Vector | What Attacker Learns | Mitigation |
|---|---|---|
| crt.sh / Censys | All subdomains | Private CA for internal; monitor CT logs |
| Shodan / FOFA | Open ports, versions | Firewall; suppress banners |
| GitHub repos | API keys, credentials | Git secrets; pre-commit hooks |
| LinkedIn / jobs | Tech stack, vendors | Sanitize descriptions |
| DNS AXFR | Full zone | Block external AXFR |

---

## KQL — Entra ID

### Sign-in from Compromised/Anonymized Network

```kusto
SigninLogs
| where ResultType == 0
| where NetworkLocationDetails has "anonymizedIPAddress" or NetworkLocationDetails has "malware"
| project TimeGenerated, UserPrincipalName, IPAddress, Location, AppDisplayName, DeviceDetail
| order by TimeGenerated desc
```

---

## Response Checklist

| Step | Action |
|---|---|
| 1 | Run crt.sh for all subdomains; remove or firewall dev/staging |
| 2 | Run TruffleHog on all repos; rotate exposed secrets immediately |
| 3 | Enable HIBP API alert for corporate email domain |
| 4 | Suppress version banners on all web servers |
| 5 | Block DNS AXFR from external; audit DNS records quarterly |

---

## MITRE ATT&CK

| Technique | ID | Coverage |
|---|---|---|
| Gather Victim Network Information | T1590 | Subdomain exposure |
| Search Open Technical Databases | T1596 | CT logs, Shodan |
| Credentials from Password Stores | T1555 | Leaked credential monitoring |
