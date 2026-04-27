---
name: defensive-windows-mitigations
description: "Windows exploit mitigations audit and detection: DEP, ASLR, CFG, CET, SEHOP, LSA Protection (RunAsPPL), Credential Guard, ASR rules, PowerShell ConstrainedLanguageMode. Sigma for LSASS access, LSA registry tamper, ASR rule blocks. KQL for MDE TVM compliance assessment. Use for hardening verification and security posture management."
---

# SKILL: Windows Security Mitigations Audit

## Metadata
- **Skill Name**: defensive-windows-mitigations
- **Folder**: Skills/defensive-windows-mitigations
- **Source**: sources/defensive-checklist/windows-mitigations.md
- **Mirrors**: offensive-windows-mitigations

## Trigger Phrases
Use this skill when the conversation involves any of:
`Windows mitigations, DEP ASLR check, LSA protection, RunAsPPL, Credential Guard, ASR rules, LSASS dump detection, PowerShell ConstrainedLanguageMode, Windows hardening checklist, MDE TVM compliance`

## Instructions for Claude

When this skill is active:
1. LSASS memory access = credential compromise; reset all passwords on affected host
2. ASR rule blocks = provide rule GUID reference table for triage
3. KQL: DeviceTvmSecureConfigurationAssessment for compliance gap identification
4. Hardening priority: LSA PPL → Credential Guard → ASR in Enforce → ConstrainedLanguageMode
5. LSA Protection tampered: hunt for credential dumping activity immediately

---

## Full Methodology

# Windows Security Mitigations

## Shortcut

- LSASS access via Sysmon EventID 10 with `GrantedAccess` containing `0x1010`/`0x1038` = Mimikatz.
- LSA `RunAsPPL` set to 0 = protection disabled; alert and investigate.
- Defender EventID 5001 = real-time protection disabled.
- ASR EventID 1121 = rule blocked attack; review what was blocked.

---

## Key Mitigations Reference

| Mitigation | Registry/Setting | Tamper Indicator |
|---|---|---|
| DEP | `HKLM\...\Execute` = 0 | Changed to 1 |
| LSA Protection | `HKLM\...\RunAsPPL` = 1 | Changed to 0 — critical |
| Credential Guard | Group Policy + UEFI | Disabled in GP |
| SEHOP | `DisableExceptionChainValidation` = 0 | Changed to 1 |

## ASR Rule Reference (Key Rules)

| Rule | GUID | Blocks |
|---|---|---|
| Office → child process | `d4f940ab-401b-4efc-aadc-ad5f3c50688a` | Macro payload |
| LSASS credential theft | `9e6c4e1f-7d60-472f-ba1a-a39ef669e4b0` | MiniDump |
| Executable from email | `be9ba2d9-53ea-4cdc-84e5-9b1eeee46550` | Email attachment |
| Abuse of signed drivers | `56a863a9-875e-4185-98a7-b882c64b5ce5` | BYOVD |

---

## KQL — MDE

### LSASS Access (Credential Dumping)

```kusto
DeviceEvents
| where ActionType == "LsassProcessAccess"
| where not(InitiatingProcessFileName in~ ("MsMpEng.exe", "mssense.exe", "csrss.exe"))
| project TimeGenerated, DeviceName, InitiatingProcessFileName,
          InitiatingProcessCommandLine, AdditionalFields
| order by TimeGenerated desc
```

### Compliance Assessment via TVM

```kusto
DeviceTvmSecureConfigurationAssessment
| where IsApplicable == 1
| where IsCompliant == 0
| where ConfigurationId in (
    "scid-2010",  // Credential Guard
    "scid-2030",  // LSA Protection
    "scid-2000",  // Defender Real-time Protection
    "scid-2060"   // Network protection
  )
| project DeviceName, ConfigurationName, ConfigurationId, OSPlatform
| order by DeviceName asc
```

### ASR Rule Blocks

```kusto
DeviceEvents
| where ActionType in (
    "AsrLsassCredentialTheftAudited",
    "AsrOfficeChildProcessAudited",
    "AsrOfficeMacroWin32ApiCallsAudited"
  )
| project TimeGenerated, DeviceName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by TimeGenerated desc
```

---

## Response Checklist

| Step | Action |
|---|---|
| 1 | LSASS access: treat as credential compromise; reset all passwords |
| 2 | Enable LSA Protection (RunAsPPL) if not active |
| 3 | Enable Credential Guard for domain-joined devices |
| 4 | Set all ASR rules to Enforce mode |
| 5 | Enable Defender tamper protection |

---

## MITRE ATT&CK

| Technique | ID | Coverage |
|---|---|---|
| LSASS Memory | T1003.001 | LSASS access detection |
| Disable Security Tools | T1562 | Mitigation tampering |
