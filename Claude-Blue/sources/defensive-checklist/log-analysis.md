# Log Analysis — Sources, KQL Table Reference, Normalization

## Overview
Log source onboarding, KQL table reference for Azure Sentinel/MDE, normalization patterns, retention policies, enrichment strategies.

## Shortcut

- MDE tables: `DeviceProcessEvents`, `DeviceNetworkEvents`, `DeviceFileEvents`, `DeviceRegistryEvents`, `DeviceEvents`, `DeviceAlertEvents`.
- Entra ID: `SigninLogs`, `AuditLogs`, `AADNonInteractiveUserSignInLogs`.
- Email: `EmailEvents`, `EmailAttachmentInfo`, `EmailUrlInfo`.
- Azure: `AzureDiagnostics`, `AzureActivity`, `AzureNetworkAnalytics_CL`.
- Default retention: 30 days hot; archive for compliance.

---

## KQL Table Reference

| Table | Data | Key Fields |
|---|---|---|
| DeviceProcessEvents | Process creation/termination | FileName, ProcessCommandLine, InitiatingProcessFileName |
| DeviceNetworkEvents | Network connections | RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName |
| DeviceFileEvents | File create/modify/delete | FileName, FolderPath, SHA256, ActionType |
| DeviceRegistryEvents | Registry changes | RegistryKey, RegistryValueData, ActionType |
| DeviceEvents | Misc device events | ActionType (LsassProcessAccess, AppCrashed, etc.) |
| DeviceAlertEvents | MDE alert events | AlertId, Title, Severity, Category |
| SigninLogs | Entra ID sign-ins | UserPrincipalName, IPAddress, Location, ResultType |
| AuditLogs | Entra ID audit | OperationName, InitiatedBy, TargetResources |
| EmailEvents | Email telemetry | SenderFromAddress, RecipientEmailAddress, DeliveryAction |
| AzureDiagnostics | Azure resource logs | ResourceType, OperationName, Message |
| AzureActivity | Azure management | Caller, OperationName, ResourceGroup |
| SecurityAlert | SIEM alerts | AlertName, AlertSeverity, CompromisedEntity |
| ThreatIntelligenceIndicator | TI IOCs | IndicatorType, NetworkIP, FileHashValue |

---

## Log Source Onboarding

| Source | Method | Table |
|---|---|---|
| Windows hosts | MDE agent | DeviceProcess/Network/File/Registry |
| Entra ID | Diagnostic settings → Sentinel | SigninLogs, AuditLogs |
| Azure resources | Diagnostic settings | AzureDiagnostics |
| Email (Exchange/O365) | Defender for O365 | EmailEvents |
| WAF/App Gateway | Diagnostic settings | AzureDiagnostics (WAF) |
| Firewall | Diagnostic settings | AzureDiagnostics (Firewall) |
| Linux hosts | Syslog connector | Syslog table |

---

## KQL — Log Analysis

### Check Table Coverage (What's Ingesting)

```kusto
union withsource=TableName *
| summarize LastRecord=max(TimeGenerated), Count=count() by TableName
| order by LastRecord desc
```

### Entra ID SigninLogs — Recent Failures

```kusto
SigninLogs
| where TimeGenerated > ago(1h)
| where ResultType != 0
| summarize FailureCount=count() by UserPrincipalName, ResultDescription
| order by FailureCount desc
```

### Process Command Line Length Anomaly (Obfuscation)

```kusto
DeviceProcessEvents
| where len(ProcessCommandLine) > 1000
| where FileName in~ ("powershell.exe", "cmd.exe", "wscript.exe")
| project TimeGenerated, DeviceName, FileName, ProcessCommandLine
| order by len(ProcessCommandLine) desc
```

---

## Retention Policy

| Data | Hot (Query) | Archive (Compliance) |
|---|---|---|
| Security events | 30 days default | 1–7 years (regulatory) |
| Sign-in logs | 30 days | 1 year (minimum) |
| Audit logs | 30 days | 1 year |
| Email | 30 days | 90 days |

Set in Sentinel: Workspace → Usage and estimated costs → Data retention

---

## MITRE ATT&CK

| Technique | ID | Log Coverage |
|---|---|---|
| Indicator Removal | T1070 | AuditLogs + DeviceEvents |
| Data Collection | T1119 | DeviceFileEvents + Network |
