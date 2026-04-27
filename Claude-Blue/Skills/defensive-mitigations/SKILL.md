---
name: defensive-mitigations
description: "Security mitigations audit and tamper detection: ASLR/DEP/CFG/SEHOP registry monitoring, Defender real-time protection disable detection, LSA registry tamper, ASR compliance. Sigma for mitigation registry changes and Defender EventID 5001. KQL for MDE TVM secure configuration assessment. Use for security posture management and SOC triage."
---

# SKILL: Security Mitigations Audit

## Metadata
- **Skill Name**: defensive-mitigations
- **Folder**: Skills/defensive-mitigations
- **Source**: sources/defensive-checklist/mitigations.md
- **Mirrors**: offensive-mitigations

## Trigger Phrases
Use this skill when the conversation involves any of:
`security mitigations audit, Defender disabled detection, ASLR disabled, DEP disabled, LSA registry tamper, security control tamper detection, mitigation compliance KQL, TVM assessment KQL, Defender EventID 5001`

## Instructions for Claude

When this skill is active:
1. Defender real-time protection disabled (EventID 5001) = critical; investigate who disabled and why
2. LSA registry tampered: hunt for credential dumping activity immediately
3. KQL: DeviceTvmSecureConfigurationAssessment for compliance gap identification across fleet
4. Registry modifications to MitigationOptions/RunAsPPL = alert; validate against ITSM change record
5. Re-enable all security controls; verify via TVM report

---

## Full Methodology

# Security Mitigations Audit

## Shortcut

- EventID 5001 = Defender real-time protection disabled.
- `RunAsPPL` set to 0 = LSA protection disabled; hunt for credential dumping.
- `DisableExceptionChainValidation` set to 1 = SEHOP disabled; exploitation risk elevated.
- `MitigationOptions` registry key modified = review immediately.

---

## Key Controls

| Control | Registry Location | Tamper = Risk |
|---|---|---|
| LSA Protection | `HKLM\...\LSA\RunAsPPL` | Credential dumping |
| SEHOP | `HKLM\...\DisableExceptionChainValidation` | SEH exploitation |
| Defender RTP | Group Policy / EventID 5001 | Malware evasion |
| ASR Rules | Group Policy / Intune | Attack surface unprotected |

---

## KQL — MDE Compliance

### TVM Non-Compliant Security Controls

```kusto
DeviceTvmSecureConfigurationAssessment
| where IsApplicable == 1
| where IsCompliant == 0
| where ConfigurationId in (
    "scid-2010",  // Credential Guard
    "scid-2030",  // LSA Protection
    "scid-2000",  // Defender Real-time Protection
    "scid-2060",  // Network protection
    "scid-2080"   // Controlled folder access
  )
| project DeviceName, ConfigurationName, ConfigurationId, OSPlatform
| summarize NonCompliantCount=count() by ConfigurationName
| order by NonCompliantCount desc
```

### Defender Real-Time Protection Disabled

```kusto
DeviceEvents
| where ActionType == "AntivirusDisabled"
| project TimeGenerated, DeviceName, AccountName, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by TimeGenerated desc
```

---

## Response Checklist

| Step | Action |
|---|---|
| 1 | Tamper protection disabled: re-enable; check for malware installation |
| 2 | LSA registry tampered: hunt for credential dumping activity |
| 3 | Registry mitigation change: identify process that made change; verify change record |
| 4 | Run TVM compliance report; remediate non-compliant endpoints |

---

## MITRE ATT&CK

| Technique | ID | Coverage |
|---|---|---|
| Disable or Modify Tools | T1562.001 | Security software tampering |
| Impair Defenses | T1562 | Mitigation bypass via registry |
