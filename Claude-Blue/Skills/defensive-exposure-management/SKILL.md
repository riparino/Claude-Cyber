---
name: defensive-exposure-management
description: "Attack surface management and exposure management: continuous asset discovery, port scan detection, cloud misconfiguration detection, shadow IT, subdomain takeover prevention. Sigma for port scan bursts. KQL (Sentinel) and Azure Resource Graph queries for internet-facing asset exposure and Defender for Cloud recommendations."
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
2. ARG: SecurityResources for Unhealthy assessments on internet-facing VMs; Sentinel: SecurityRecommendation for the same data in Log Analytics
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

## KQL — Azure Resource Graph (ARG)

> Run these in the **Azure Resource Graph Explorer** (`portal.azure.com > Resource Graph Explorer`), not in Sentinel/Log Analytics.

### Internet-Facing VMs with High Findings

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

## KQL — Microsoft Sentinel / Log Analytics

> Run these in **Sentinel > Logs** or a **Log Analytics workspace** with Defender for Cloud connected.

### High/Critical Unhealthy Recommendations on VMs

```kusto
SecurityRecommendation
| where TimeGenerated > ago(7d)
| where RecommendationState == "Unhealthy"
| where RecommendationSeverity in ("High", "Critical")
| where AssessedResourceId contains "virtualMachines"
| project TimeGenerated, AssessedResourceId, RecommendationName, RecommendationSeverity, Description
| order by RecommendationSeverity asc, TimeGenerated desc
```

### Defender for Cloud Recommendation Trends (Last 30d)

```kusto
SecurityRecommendation
| where TimeGenerated > ago(30d)
| where RecommendationState == "Unhealthy"
| summarize Count=count() by RecommendationSeverity, bin(TimeGenerated, 1d)
| order by TimeGenerated desc
```

### New Unhealthy High Recommendations (Last 24h)

```kusto
SecurityRecommendation
| where TimeGenerated > ago(24h)
| where RecommendationState == "Unhealthy"
| where RecommendationSeverity == "High"
| project TimeGenerated, AssessedResourceId, RecommendationName, Description
| order by TimeGenerated desc
```

---

## Response Checklist

| Step | Action |
|---|---|
| 1 | Run EASM scan; identify all internet-facing assets |
| 2 | Audit DNS records; remove CNAMEs to decommissioned services |
| 3 | Review SecurityRecommendation (Sentinel) or SecurityResources (ARG) High/Critical; patch or compensate |
| 4 | Scan for open management ports (22, 3389, 5985); restrict via NSG/JIT |
| 5 | Enable Defender for Cloud; review internet exposure recommendations weekly |

---

## MITRE ATT&CK

| Technique | ID | Coverage |
|---|---|---|
| Active Scanning | T1595 | Port scan detection |
| Search Open Technical Databases | T1596 | Cloud exposure |
| Gather Victim Network Information | T1590 | Asset enumeration detection |

---

## References & Verified Sources

**Table schemas**
- SecurityRecommendation (Log Analytics): https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/securityrecommendation
- SecurityResources (Azure Resource Graph): https://learn.microsoft.com/en-us/azure/governance/resource-graph/reference/supported-tables-resources

**Defender for Cloud**
- Connect Defender for Cloud to Sentinel: https://learn.microsoft.com/en-us/azure/sentinel/connect-defender-for-cloud
- Azure Resource Graph Explorer: https://learn.microsoft.com/en-us/azure/governance/resource-graph/first-query-portal
