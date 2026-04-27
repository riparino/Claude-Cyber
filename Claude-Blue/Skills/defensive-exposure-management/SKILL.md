---
name: defensive-exposure-management
description: "Attack surface management and exposure management: continuous asset discovery, port scan detection, cloud misconfiguration detection, shadow IT, subdomain takeover prevention. Sigma for SYN scan rate from external IPs. KQL for Azure Defender for Cloud findings and SigninLogs from scanner ASNs. Mirrors offensive-osint-methodology."
---

# SKILL: Exposure Management

## Metadata
- **Skill Name**: defensive-exposure-management
- **Folder**: Skills/defensive-exposure-management
- **Source**: sources/defensive-checklist/exposure-management.md
- **Mirrors**: offensive-osint-methodology

## Trigger Phrases
Use this skill when the conversation involves any of:
`attack surface management, external exposure, port scan detection, cloud misconfiguration detection, shadow IT detection, subdomain takeover, EASM, Defender EASM, internet-facing asset inventory`

## Instructions for Claude

When this skill is active:
1. Continuous ASM: discover → classify → analyze → prioritize → remediate → monitor cycle
2. KQL: SecurityResources for Unhealthy assessments on internet-facing VMs
3. Subdomain takeover: CNAME to decommissioned service = critical; claim or remove DNS record
4. Port scan detection: high-rate SYN from external = reconnaissance in progress; threat hunt
5. Azure EASM or Defender for Cloud for continuous external exposure monitoring

---

## Full Methodology

# Exposure Management

## Shortcut

- Internet-facing VM with Unhealthy High assessment = remediate within 7 days.
- CNAME pointing to deprovisioned service = subdomain takeover risk; remove DNS record.
- Port scan: >100 distinct ports from same IP in 30s = reconnaissance.
- Shadow IT: cloud apps in CASB not approved by IT.

---

## KQL — Azure Defender for Cloud

### Internet-Facing VMs with Critical Findings

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

---

## Response Checklist

| Step | Action |
|---|---|
| 1 | Run EASM scan; identify all internet-facing assets |
| 2 | Audit DNS records; remove CNAMEs to decommissioned services |
| 3 | Review SecurityResources High/Critical; patch or compensate |
| 4 | Scan for open management ports (22, 3389, 5985); restrict via NSG/JIT |
| 5 | Enable Defender for Cloud; review internet exposure recommendations weekly |

---

## MITRE ATT&CK

| Technique | ID | Coverage |
|---|---|---|
| Active Scanning | T1595 | Port scan detection |
| Search Open Technical Databases | T1596 | Cloud exposure |
| Gather Victim Network Information | T1590 | Asset enumeration detection |
