---
name: defensive-log-analysis
description: "Log analysis reference: KQL table guide for MDE, Entra ID, Azure, Email, and SIEM. Log source onboarding, normalization, retention policies. Key queries for coverage check, sign-in failures, obfuscated command lines. Use for Sentinel deployment, log source validation, and analyst reference."
---

# SKILL: Log Analysis

## Metadata
- **Skill Name**: defensive-log-analysis
- **Folder**: Skills/defensive-log-analysis
- **Source**: sources/defensive-checklist/log-analysis.md

## Trigger Phrases
Use this skill when the conversation involves any of:
`log analysis, KQL table reference, Sentinel tables, log source onboarding, log retention, DeviceProcessEvents, SigninLogs reference, AzureDiagnostics, MDE table guide, which KQL table to use`

## Instructions for Claude

When this skill is active:
1. Provide the correct KQL table for the query immediately (see table reference)
2. DeviceProcessEvents = process creation; DeviceEvents = misc events including LsassProcessAccess, AppCrashed
3. Retention: 30 days hot by default; set archive retention for compliance
4. Check table coverage first: `union withsource=TableName * | summarize by TableName`
5. Long command line (>1000 chars) in PowerShell = obfuscation indicator; query in DeviceProcessEvents

---

## Full Methodology

# Log Analysis

## KQL Table Reference

| Table | Data |
|---|---|
| DeviceProcessEvents | Process creation; command lines |
| DeviceNetworkEvents | Network connections; DNS |
| DeviceFileEvents | File create/modify/delete; hashes |
| DeviceRegistryEvents | Registry changes |
| DeviceEvents | Misc: LSASS access, crashes, ASR, etc. |
| DeviceAlertEvents | MDE alerts |
| SigninLogs | Entra ID interactive sign-ins |
| AuditLogs | Entra ID audit |
| AADNonInteractiveUserSignInLogs | Non-interactive (service) sign-ins |
| EmailEvents | Email delivery/block |
| AzureDiagnostics | Azure resource logs (WAF, App GW, etc.) |
| AzureActivity | Azure management plane |
| SecurityAlert | SIEM alerts |
| ThreatIntelligenceIndicator | TI IOCs |

---

## KQL — Log Operations

### Coverage Check (Which Tables Are Ingesting)

```kusto
union withsource=TableName *
| summarize LastRecord=max(TimeGenerated), Count=count() by TableName
| order by LastRecord desc
```

### Obfuscated PowerShell Commands

```kusto
DeviceProcessEvents
| where len(ProcessCommandLine) > 1000
| where FileName in~ ("powershell.exe", "cmd.exe")
| project TimeGenerated, DeviceName, FileName, ProcessCommandLine
| order by len(ProcessCommandLine) desc
```

### Sign-in Failure Summary

```kusto
SigninLogs
| where TimeGenerated > ago(1h)
| where ResultType != 0
| summarize FailureCount=count() by UserPrincipalName, ResultDescription
| order by FailureCount desc
```

---

## Retention Settings

| Data | Hot | Archive |
|---|---|---|
| Security events | 30 days | 1–7 years |
| Sign-in logs | 30 days | 1 year minimum |
| Audit logs | 30 days | 1 year |

---

## MITRE ATT&CK

| Technique | ID | Log Table |
|---|---|---|
| Indicator Removal | T1070 | AuditLogs + DeviceEvents |
| Data Collection | T1119 | DeviceFileEvents |
