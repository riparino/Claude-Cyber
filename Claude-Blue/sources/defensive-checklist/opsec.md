# Organizational OPSEC & Exposure Reduction

## Overview
Minimize organizational attack surface visible to OSINT. Leaked credential monitoring, shadow IT discovery, DNS/certificate exposure, job posting intelligence leakage, metadata removal.

## Shortcut

- Check `crt.sh` for wildcard/dev/staging subdomains exposed publicly.
- Hunt `site:github.com <org>` for leaked credentials and internal code.
- Monitor `HaveIBeenPwned` / `dehashed.com` / `SpyCloud` for credential breach data.
- Review LinkedIn/job postings for technology stack disclosures.
- SSL certificate Transparency Logs expose all subdomains.

---

## OSINT Exposure Vectors

| Vector | What Attacker Learns | Mitigation |
|---|---|---|
| crt.sh / Censys | All subdomains including dev/staging | Private cert issuance; remove from CT logs |
| Shodan / FOFA | Open ports, banners, version info | Firewall; reduce banner verbosity |
| GitHub / GitLab | API keys, passwords, internal hostnames | Git secrets scanning; pre-commit hooks |
| LinkedIn / job ads | Tech stack, vendors, internal tools | Sanitize job descriptions |
| WHOIS records | Admin contacts, registration details | Domain privacy |
| Google Cache | Old versions of internal pages | `noindex` headers; robots.txt |

---

## Credential Leak Monitoring

Tools:
- `HaveIBeenPwned` API — monitor corporate email domain
- `dehashed.com` — search by email domain
- `SpyCloud` — enterprise credential monitoring
- `GitLeaks` / `TruffleHog` — scan repos for secrets

Azure Sentinel KQL for impossible travel (follow-on from leaked credential use):
```kusto
SigninLogs
| where ResultType == 0
| summarize Locations=make_set(Location), IPs=make_set(IPAddress) by UserPrincipalName, bin(TimeGenerated, 2h)
| where array_length(Locations) > 1
| order by TimeGenerated desc
```

---

## KQL — Entra ID: Sign-in from Credential Dump Source

```kusto
SigninLogs
| where ResultType == 0
| where NetworkLocationDetails has "anonymizedIPAddress" or NetworkLocationDetails has "malware"
| project TimeGenerated, UserPrincipalName, IPAddress, Location, AppDisplayName, DeviceDetail
| order by TimeGenerated desc
```

---

## Sigma Rules

```yaml
title: External DNS Subdomain Enumeration via AXFR
id: e5f6a789-0123-ef01-2345-6789012345ab
status: experimental
description: Detects DNS zone transfer (AXFR) request from external IP
logsource:
  category: dns
detection:
  selection:
    dns.query.type: AXFR
  filter:
    src_ip|cidr:
      - 10.0.0.0/8
      - 172.16.0.0/12
      - 192.168.0.0/16
  condition: selection and not filter
falsepositives:
  - Legitimate secondary DNS servers
level: high
tags:
  - attack.reconnaissance
  - attack.t1590.002
```

---

## Hardening Checklist

| Control | Action |
|---|---|
| Certificate Transparency | Restrict dev/staging cert issuance via private CA |
| DNS | Block zone transfer (AXFR) from external; restrict BIND ACLs |
| GitHub | Enable secret scanning; add pre-commit hooks (git-secrets) |
| Job postings | Remove specific technology names; use generic terms |
| Banner grab | Suppress server version banners (Apache, nginx, IIS) |
| Credential monitoring | Integrate HIBP API alert for corporate domain |

---

## MITRE ATT&CK

| Technique | ID | Notes |
|---|---|---|
| Gather Victim Network Information | T1590 | Subdomain/IP enumeration |
| Gather Victim Org Information | T1591 | Job posting / LinkedIn OSINT |
| Search Open Technical Databases | T1596 | Shodan, crt.sh, FOFA |
| Credentials from Password Stores | T1555 | Leaked credential use |
