# Cloud Hardening — Azure / Entra ID / Defender

## Overview
Azure security hardening: Entra ID Conditional Access, Privileged Identity Management (PIM), Defender for Cloud recommendations, Intune compliance, storage account security, Key Vault hardening.

## Shortcut

- Conditional Access: require MFA for all; block legacy auth; require compliant device.
- PIM: no standing admin; require approval for privileged role activation.
- Storage: disable public blob access; enable Defender for Storage.
- Key Vault: soft delete + purge protection; RBAC; private endpoint.
- Defender for Cloud: enable all plans; resolve High severity recommendations.

---

## Conditional Access Baseline

| Policy | Setting |
|---|---|
| Require MFA | All users, all apps, all platforms |
| Block legacy auth | Block Basic Auth, SMTP AUTH, POP3, IMAP |
| Require compliant device | Managed devices for sensitive apps |
| Risky sign-in | Block High risk; require MFA for Medium |
| Admin accounts | Require MFA + compliant device |

---

## PIM Configuration

| Setting | Value |
|---|---|
| Global Admin | No standing; activate on-demand; approval required |
| Privileged Role Admin | No standing; max 8h activation |
| MFA on activation | Required |
| Justification | Required |
| Audit alerts | All PIM activations |

---

## Storage Account Hardening

| Control | Setting |
|---|---|
| Public access | Disabled |
| Minimum TLS | TLS 1.2 |
| Shared Access Signature | Expiry < 1h; HTTPS only |
| Defender for Storage | Enabled |
| Private endpoint | Use for internal apps |

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

### PIM Role Activations (Audit)

```kusto
AuditLogs
| where OperationName == "Add member to role in PIM requested"
| project TimeGenerated, InitiatedBy, TargetResources, Result, AdditionalDetails
| order by TimeGenerated desc
```

### Conditional Access: Legacy Auth Sign-ins

```kusto
SigninLogs
| where AuthenticationProtocol in ("Basic", "SMTP", "POP3", "IMAP")
| where ResultType == 0
| project TimeGenerated, UserPrincipalName, ClientAppUsed, IPAddress, Location
| order by TimeGenerated desc
```

### High-Severity Defender for Cloud Recommendations

```kusto
SecurityResources
| where type == "microsoft.security/assessments"
| where properties.status.code == "Unhealthy"
| extend Severity = tostring(properties.metadata.severity)
| where Severity == "High"
| project ResourceId=tostring(properties.resourceDetails.id),
          Assessment=tostring(properties.displayName), Severity
| order by Assessment asc
```

---

## Hardening Checklist

| Control | Priority |
|---|---|
| Enable all Conditional Access baselines | Critical |
| PIM for all privileged roles | Critical |
| Defender for Cloud — all plans | High |
| Block legacy authentication | Critical |
| Key Vault soft delete + purge protection | High |
| Storage: disable public blob access | High |

---

## MITRE ATT&CK

| Technique | ID | Control |
|---|---|---|
| Valid Accounts | T1078 | MFA + Conditional Access |
| Abuse Elevation Control | T1548 | PIM; no standing admin |
| Data from Cloud Storage | T1530 | Defender for Storage |
