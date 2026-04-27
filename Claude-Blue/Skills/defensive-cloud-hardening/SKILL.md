---
name: defensive-cloud-hardening
description: "Azure cloud hardening: Entra ID Conditional Access baselines, PIM for privileged roles, Defender for Cloud recommendations, storage account hardening, Key Vault protection, legacy auth blocking. KQL for public storage, PIM activations, legacy auth sign-ins, and Defender for Cloud unhealthy controls."
---

# SKILL: Cloud Hardening

## Metadata
- **Skill Name**: defensive-cloud-hardening
- **Folder**: Skills/defensive-cloud-hardening
- **Source**: sources/defensive-checklist/cloud-hardening.md

## Trigger Phrases
Use this skill when the conversation involves any of:
`Azure hardening, cloud hardening, Conditional Access baseline, PIM hardening, Defender for Cloud, block legacy auth, storage account security, Key Vault hardening, Entra ID hardening, Azure security recommendations`

## Instructions for Claude

When this skill is active:
1. Conditional Access: require MFA for all; block legacy auth — both are non-negotiable baselines
2. PIM: no standing admin; all privileged roles must require activation + approval
3. KQL: SecurityResources for High severity Unhealthy assessments on internet-facing resources
4. Legacy auth KQL: SigninLogs for SMTP/POP3/IMAP sign-ins; these must be blocked
5. Storage: disable public blob access on all storage accounts immediately

---

## Full Methodology

# Cloud Hardening

## Conditional Access Baselines

| Policy | Required Setting |
|---|---|
| MFA for all users | All apps, all platforms |
| Block legacy auth | Basic Auth, SMTP, POP3, IMAP |
| Compliant device | Required for sensitive apps |
| Risky sign-in | Block High; MFA for Medium |

## PIM Settings

| Role | Max Duration | Approval |
|---|---|---|
| Global Admin | 4h | Required |
| Privileged Role Admin | 8h | Required |
| All other privileged | 8h | Recommended |

---

## KQL — Azure Hardening

### Public Storage Accounts

```kusto
Resources
| where type == "microsoft.storage/storageaccounts"
| where properties.allowBlobPublicAccess == true
| project name, resourceGroup, location
| order by name asc
```

### Legacy Auth Sign-ins (Block These)

```kusto
SigninLogs
| where AuthenticationProtocol in ("Basic", "SMTP", "POP3", "IMAP")
| where ResultType == 0
| project TimeGenerated, UserPrincipalName, ClientAppUsed, IPAddress, Location
| order by TimeGenerated desc
```

### Defender for Cloud — High Severity Gaps

```kusto
SecurityResources
| where type == "microsoft.security/assessments"
| where properties.status.code == "Unhealthy"
| extend Severity = tostring(properties.metadata.severity)
| where Severity == "High"
| project ResourceId=tostring(properties.resourceDetails.id),
          Assessment=tostring(properties.displayName)
| order by Assessment asc
```

---

## Response Checklist

| Control | Action |
|---|---|
| No MFA policy | Create Conditional Access: MFA for all |
| Legacy auth active | Create CA: Block legacy auth |
| Standing admin role | Migrate to PIM; remove standing assignments |
| Public storage | Set `allowBlobPublicAccess = false` |
| High Defender recs | Prioritize and remediate within 7 days |

---

## MITRE ATT&CK

| Technique | ID | Control |
|---|---|---|
| Valid Accounts | T1078 | MFA + Conditional Access |
| Abuse Elevation | T1548 | PIM |
| Data from Cloud Storage | T1530 | Defender for Storage |

---

## References & Verified Sources

**MITRE ATT&CK (Cloud matrix)**
- Cloud matrix: https://attack.mitre.org/matrices/enterprise/cloud/
- T1078.004 Valid Accounts: Cloud Accounts: https://attack.mitre.org/techniques/T1078/004/
- T1530 Data from Cloud Storage: https://attack.mitre.org/techniques/T1530/
- T1548 Abuse Elevation Control: https://attack.mitre.org/techniques/T1548/

**Microsoft baselines & guidance**
- Azure Security Benchmark v3: https://learn.microsoft.com/en-us/security/benchmark/azure/overview
- Microsoft Cloud Security Benchmark (MCSB): https://learn.microsoft.com/en-us/security/benchmark/azure/introduction
- Conditional Access policy templates: https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-conditional-access-policy-common
- Privileged Identity Management (PIM): https://learn.microsoft.com/en-us/entra/id-governance/privileged-identity-management/pim-configure
- Defender for Cloud secure score: https://learn.microsoft.com/en-us/azure/defender-for-cloud/secure-score-security-controls

**KQL tables**
- `SigninLogs`: https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/signinlogs
- `AuditLogs`: https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/auditlogs
- `AzureActivity`: https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/azureactivity
- `CloudAppEvents` (MDA): https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-cloudappevents-table

**Reference standards**
- CIS Microsoft Azure Foundations Benchmark: https://www.cisecurity.org/benchmark/azure
- NIST SP 800-207 Zero Trust Architecture: https://csrc.nist.gov/pubs/sp/800/207/final
