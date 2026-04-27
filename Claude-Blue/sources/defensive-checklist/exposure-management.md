# Attack Surface Management & Exposure Management

## Overview
Continuous discovery of internet-facing assets, external port scan detection, shadow IT discovery, cloud misconfigurations. Sigma for scanner IP patterns. KQL for SigninLogs anomalies from scanner IPs and Azure Security Center findings.

## Shortcut

- Masscan/ZMap SYN scan = many ports in short time from same source IP; Sigma for firewall logs.
- Azure Security Center: `SecurityResources` table for public-facing VM exposure.
- Azure Defender for Cloud: recommendations API for internet-facing critical assets.
- Subdomain takeover: CNAME pointing to decommissioned service = claimed by attacker.

---

## External Exposure Categories

| Category | Discovery Tool | Defense |
|---|---|---|
| Open ports | Shodan, Censys, Masscan | Firewall, SG rules, JIT access |
| Subdomains | Amass, subfinder, crt.sh | Monitor CT logs; remove unused subdomains |
| Cloud storage | ScoutSuite, Prowler | Private ACLs; deny public access |
| Shadow IT | CASB (Defender for Cloud Apps) | DLP; SSPM |
| Expired certs | CT log monitoring | Auto-renew; Let's Encrypt |
| Dangling DNS | `MX Record`, CNAME to removed service | Audit DNS records quarterly |

---

## Port Scan Detection

### Sigma

```yaml
title: External Port Scan via High-Rate SYN
id: f6a7b890-1234-f012-3456-7890123456bc
status: experimental
description: Detects high-rate SYN packets from external IP (port scan)
logsource:
  category: firewall
detection:
  selection:
    action: DROP
    flags: SYN
  filter:
    src_ip|cidr:
      - 10.0.0.0/8
      - 172.16.0.0/12
      - 192.168.0.0/16
  timeframe: 30s
  condition: selection and not filter | count() by src_ip > 100
falsepositives:
  - Network monitoring probes
level: medium
tags:
  - attack.reconnaissance
  - attack.t1595.001
```

---

## KQL — Azure Defender for Cloud / Network

### Internet-Exposed VMs with Critical Findings

```kusto
SecurityResources
| where type == "microsoft.security/assessments"
| where properties.status.code == "Unhealthy"
| extend ResourceId = tostring(properties.resourceDetails.id)
| where ResourceId contains "virtualMachines"
| project TimeGenerated=todatetime(properties.timeGenerated), ResourceId,
          Assessment=tostring(properties.displayName),
          Severity=tostring(properties.metadata.severity)
| where Severity == "High"
| order by TimeGenerated desc
```

### SigninLogs from Known Scanner IP Ranges

```kusto
let ScannerASNs = dynamic(["AS20473", "AS14618", "AS209103"]); // Vultr, AWS, common scanner ASNs
SigninLogs
| where ResultType == 0
| extend ASN = tostring(NetworkLocationDetails[0].networkNames[0])
| where ASN in (ScannerASNs)
| project TimeGenerated, UserPrincipalName, IPAddress, ASN, Location, AppDisplayName
| order by TimeGenerated desc
```

---

## Attack Surface Management Workflow

1. **Discover**: continuous asset enumeration (EASM, Defender EASM, Shodan Monitor)
2. **Classify**: internet-facing vs internal; criticality tier
3. **Analyze**: for each exposed asset — open ports, vulnerabilities, cert status
4. **Prioritize**: CVSS + exposure = risk score
5. **Remediate**: close ports, patch, rotate secrets, remove stale assets
6. **Monitor**: alerts on new exposure; weekly ASM report

---

## MITRE ATT&CK

| Technique | ID | Notes |
|---|---|---|
| Active Scanning | T1595 | Port scan detection |
| Search Open Technical Databases | T1596 | Shodan/Censys exposure |
| Gather Victim Network Information | T1590 | Subdomain, IP range |
