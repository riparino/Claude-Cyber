# Windows Security Mitigations — Audit & Verification

## Shortcut

- Verify that all Windows exploit mitigations are enabled: DEP, ASLR, CFG, CET, SEHOP, ACG, Arbitrary Code Guard.
- Check Microsoft Defender Attack Surface Reduction (ASR) rules are in `Enforce` mode.
- Verify Protected Process Light (PPL) is applied to LSASS.
- Check PowerShell is configured to `ConstrainedLanguageMode` or blocked for users.
- Validate Credential Guard and LSA protection are enabled.

---

## Mitigation Reference

| Mitigation | What it prevents | Registry/Setting |
|---|---|---|
| DEP (Data Execution Prevention) | Shellcode on non-executable memory | `HKLM\SYSTEM\...\Execute` = 0 |
| ASLR | Deterministic ROP chains | `HKLM\SYSTEM\...\MoveImages` = 0xFFFFFFFF |
| SEHOP | SEH overwrite exploits | `HKLM\SYSTEM\...\DisableExceptionChainValidation` = 0 |
| CFG | Indirect call hijacking | Compiler + OS enforced |
| CET (Shadow Stack) | Return-oriented programming | CPU + OS feature |
| ACG | Just-in-time compiled shellcode | `SetProcessMitigationPolicy` |
| LSA Protection | LSASS memory dumping | `RunAsPPL` = 1 |
| Credential Guard | NTLM hash / Kerberos TGT theft | Hypervisor-based |
| LSASS audit | Detect dump attempts | `AuditLevel` = 8 |
| ASR Rules | Macro → shell, Office → child process | MDE policy |
| ConstrainedLanguageMode | PowerShell abuse | AppLocker/WDAC |

---

## ASR Rules Reference (Microsoft Defender)

| Rule | GUID | What it blocks |
|---|---|---|
| Block Office macros from spawning child processes | `d4f940ab-401b-4efc-aadc-ad5f3c50688a` | Office → cmd/PowerShell |
| Block Office from creating executable content | `3b576869-a4ec-4529-8536-b80a7769e899` | Office dropping PE files |
| Block credential stealing from LSASS | `9e6c4e1f-7d60-472f-ba1a-a39ef669e4b0` | MiniDump of LSASS |
| Block executable content from email | `be9ba2d9-53ea-4cdc-84e5-9b1eeee46550` | Email attachment execution |
| Block abuse of exploited vulnerable signed drivers | `56a863a9-875e-4185-98a7-b882c64b5ce5` | BYOVD |
| Block untrusted / unsigned executables from USB | `b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4` | USB delivery |

---

## Sigma Rules

### LSASS Memory Read Attempt (Credential Access)

```yaml
title: LSASS Memory Access for Credential Dumping
id: c0d1e2f3-a4b5-6789-cdef-012345678048
status: stable
description: >
  Detects processes accessing lsass.exe memory — Mimikatz and credential dumping
  tools read LSASS to extract password hashes and Kerberos tickets.
author: claude-blue
date: 2026-04-27
references:
  - https://attack.mitre.org/techniques/T1003/001/
logsource:
  product: windows
  service: sysmon
  definition: Sysmon EventID 10 (ProcessAccess) enabled
detection:
  selection:
    EventID: 10
    TargetImage|endswith: '\lsass.exe'
    GrantedAccess|contains:
      - '0x1010'
      - '0x1038'
      - '0x1FFFFF'
      - '0x143A'
  filter_known:
    SourceImage|endswith:
      - '\MsMpEng.exe'
      - '\mssense.exe'
      - '\csrss.exe'
  condition: selection and not filter_known
falsepositives:
  - Some endpoint security products (document SourceImage and allowlist)
level: critical
tags:
  - attack.t1003.001
  - attack.credential_access
```

### ASR Rule Triggered

```yaml
title: Defender ASR Rule Triggered (Attack Surface Reduction)
id: d1e2f3a4-b5c6-7890-defa-123456789049
status: stable
description: Detects Microsoft Defender ASR rule block events.
author: claude-blue
date: 2026-04-27
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 1121  # ASR block event
  condition: selection
falsepositives:
  - Legitimate business processes blocked by ASR (tune in audit mode first)
level: high
tags:
  - attack.defense_evasion
```

### LSA Protection Disabled (Registry)

```yaml
title: LSA Protection Disabled via Registry
id: e2f3a4b5-c6d7-8901-efab-234567890050
status: experimental
description: >
  Detects disabling of LSA protection (RunAsPPL) — enables LSASS memory
  access for credential dumping tools like Mimikatz.
author: claude-blue
date: 2026-04-27
logsource:
  product: windows
  category: registry_set
detection:
  selection:
    TargetObject|endswith: '\LSA\RunAsPPL'
    Details: 'DWORD (0x00000000)'
  condition: selection
falsepositives:
  - Intentional IT security configuration change (verify with change record)
level: critical
tags:
  - attack.t1562
  - attack.defense_evasion
```

---

## KQL — MDE Mitigation Compliance

### Devices with LSASS Protection Not Enforced

```kusto
DeviceEvents
| where ActionType == "LsassProcessAccess"
| where not(InitiatingProcessFileName in~ ("MsMpEng.exe", "mssense.exe", "csrss.exe"))
| project TimeGenerated, DeviceName, InitiatingProcessFileName,
          InitiatingProcessCommandLine, AdditionalFields
| order by TimeGenerated desc
```

### ASR Rule Blocks

```kusto
DeviceEvents
| where ActionType == "AsrLsassCredentialTheftAudited"
    or ActionType == "AsrOfficeChildProcessAudited"
    or ActionType == "AsrOfficeMacroWin32ApiCallsAudited"
| project TimeGenerated, DeviceName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine, AdditionalFields
| order by TimeGenerated desc
```

### Devices Missing Credential Guard

```kusto
DeviceInfo
| where OnboardingStatus == "Onboarded"
| extend CredentialGuard = tostring(parse_json(MachineGroup))
// Use DeviceTvmSecureConfigurationAssessment for detailed compliance
DeviceTvmSecureConfigurationAssessment
| where ConfigurationId in (
    "scid-2010",  // Credential Guard
    "scid-2030"   // LSA Protection
  )
| where IsApplicable == 1
| where IsCompliant == 0
| project DeviceName, ConfigurationId, ConfigurationName, OSPlatform
| order by DeviceName asc
```

---

## Response Checklist

| Step | Action |
|---|---|
| 1 | LSASS access detected: treat as credential compromise; reset all passwords on affected host |
| 2 | Enable LSA Protection (RunAsPPL) if not already enabled |
| 3 | Enable Credential Guard for domain-joined devices |
| 4 | Set all ASR rules to Enforce (not Audit) |
| 5 | Enable PowerShell ConstrainedLanguageMode via AppLocker or WDAC |
| 6 | Verify Defender tamper protection is enabled |

---

## MITRE ATT&CK

| Technique | ID | Coverage |
|---|---|---|
| OS Credential Dumping: LSASS Memory | T1003.001 | LSASS access detection |
| Disable or Modify Tools | T1562 | ASR/LSA protection tampering |
| Exploit Protection | T1203 | Mitigation bypass attempts |
