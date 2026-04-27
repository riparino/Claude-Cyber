# Security Mitigations — Audit, Verification & Detection

## Shortcut

- This skill covers OS + application security mitigations as detectable controls.
- Verify mitigations are active; detect tampering with security controls.
- Alert on mitigation bypass attempts: heap spray, ROP chains, CFG violations, stack pivot.
- Cross-reference with `defensive-windows-mitigations.md` for Windows-specific controls.

---

## Mitigation Coverage

| Category | Mitigation | Detection |
|---|---|---|
| Memory | DEP/NX, ASLR, SEHOP, CFG, CET | Violation events in WER |
| Credential | LSA PPL, Credential Guard, Protected Users | LSASS access events |
| Execution | WDAC, AppLocker, ASR Rules, ConstrainedLanguageMode | Block events |
| Network | Network isolation, SMB signing, LDAP signing | Protocol anomalies |
| Application | Stack canaries, SafeSEH, RELRO, PIE | Crash patterns |

---

## Sigma Rules

### Security Control Tampered Via Registry

```yaml
title: Security Mitigation Disabled Via Registry Modification
id: a0b1c2d3-e4f5-6789-abce-012345678058
status: experimental
description: >
  Detects registry modifications that disable Windows security mitigations
  including ASLR, DEP, SEHOP, and LSA Protection.
author: claude-blue
date: 2026-04-27
logsource:
  product: windows
  category: registry_set
detection:
  selection:
    TargetObject|contains:
      - '\MitigationOptions'
      - '\DisableExceptionChainValidation'
      - '\EnableCfg'
      - '\RunAsPPL'
      - '\DisableRestrictedAdmin'
    Details:
      - 'DWORD (0x00000000)'
      - 'DWORD (0x00000001)'  # Context-specific: 1 disables some, enables others
  condition: selection
falsepositives:
  - Authorized IT security configuration change (validate against ITSM)
level: high
tags:
  - attack.t1562
  - attack.defense_evasion
```

### Defender Tamper Protection Disabled

```yaml
title: Defender Tamper Protection or Real-Time Protection Disabled
id: b1c2d3e4-f5a6-7890-bcdf-123456789059
status: stable
description: >
  Detects attempts to disable Windows Defender components — often a precursor to
  malware persistence or credential theft.
author: claude-blue
date: 2026-04-27
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 5001    # Windows Defender real-time protection disabled
  condition: selection
falsepositives:
  - Authorized AV change with documented change ticket
level: critical
tags:
  - attack.t1562.001
```

---

## KQL — MDE Compliance

### Security Configuration Compliance Assessment

```kusto
DeviceTvmSecureConfigurationAssessment
| where IsApplicable == 1
| where IsCompliant == 0
| where ConfigurationId in (
    "scid-2010",  // Credential Guard
    "scid-2030",  // LSA Protection (RunAsPPL)
    "scid-2000",  // Defender Real-time Protection
    "scid-2060",  // Network protection
    "scid-2080"   // Controlled folder access
  )
| project DeviceName, ConfigurationName, ConfigurationId, OSPlatform, ConfigurationCategory
| summarize NonCompliantCount=count() by ConfigurationName, ConfigurationId
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
| 1 | Tamper protection disabled: investigate who disabled and why; re-enable |
| 2 | LSA Protection tampered: hunt for credential dumping activity |
| 3 | ASLR/DEP registry modified: identify process that made change; isolate host |
| 4 | Run compliance report against all endpoints; remediate non-compliant |

---

## MITRE ATT&CK

| Technique | ID | Coverage |
|---|---|---|
| Disable or Modify Tools | T1562.001 | Security software tampering |
| Impair Defenses | T1562 | Mitigation bypass |
