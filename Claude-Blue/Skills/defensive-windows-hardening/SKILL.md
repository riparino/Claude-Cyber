---
name: defensive-windows-hardening
description: "Windows security boundaries hardening and detection: UAC bypass via auto-elevate COM (fodhelper, eventvwr), SeDebugPrivilege escalation, Kerberos golden/silver ticket detection, integrity level violations, token impersonation. Sigma for UAC bypass, SeDebugPrivilege, Kerberos anomalies. KQL for MDE and SecurityEvent. Use for hardening and SOC triage."
---

# SKILL: Windows Security Boundaries

## Metadata
- **Skill Name**: defensive-windows-hardening
- **Folder**: Skills/defensive-windows-hardening
- **Source**: sources/defensive-checklist/windows-hardening.md
- **Mirrors**: offensive-windows-boundaries

## Trigger Phrases
Use this skill when the conversation involves any of:
`UAC bypass detection, fodhelper detection, SeDebugPrivilege detection, Kerberos golden ticket detection, silver ticket detection, token impersonation detection, Windows privilege escalation detection, UAC bypass Sigma, krbtgt reset`

## Instructions for Claude

When this skill is active:
1. UAC bypass via fodhelper/eventvwr = critical; identify payload executed with elevated privileges
2. Golden ticket: reset `krbtgt` password TWICE to invalidate all existing tickets
3. SeDebugPrivilege on non-admin process = likely credential theft preparation
4. KQL for SecurityEvent EventID 4768 (TGT) anomalies and MDE process creation
5. Harden: Credential Guard protects TGTs; Protected Users group prevents NTLM

---

## Full Methodology

# Windows Security Boundaries

## Shortcut

- `fodhelper.exe → cmd.exe` or `eventvwr.exe → cmd.exe` = UAC bypass; critical.
- EventID 4703 with `SeDebugPrivilege` enabled on non-security process = privilege escalation precursor.
- Kerberos TGT with 10-year lifetime = golden ticket (mimikatz default).
- Token impersonation: `ImpersonateLoggedOnUser` on higher-privilege token.

---

## Key Boundaries Reference

| Boundary | Bypass Indicator | Severity |
|---|---|---|
| UAC | Auto-elevate COM spawning cmd/PS | Critical |
| SeDebugPrivilege | Non-admin process with debug privilege | High |
| Kerberos TGT | Abnormal ticket lifetime (>10h) | Critical |
| Token impersonation | ImpersonateLoggedOnUser on higher token | High |
| LSA boundaries | Protected process access | Critical |

---

## KQL — MDE / SecurityEvent

### UAC Bypass via Auto-Elevate COM

```kusto
DeviceProcessEvents
| where InitiatingProcessFileName in~ (
    "fodhelper.exe", "eventvwr.exe", "sdclt.exe",
    "SilentCleanup.exe", "wsreset.exe"
  )
| where FileName in~ ("cmd.exe", "powershell.exe", "reg.exe")
| project TimeGenerated, DeviceName, AccountName, InitiatingProcessFileName,
          FileName, ProcessCommandLine
| order by TimeGenerated desc
```

### Kerberos: TGT Anomalies (Golden Ticket)

```kusto
SecurityEvent
| where EventID == 4768
| extend ServiceName = extract("Service Name:\\s+(\\S+)", 1, EventData)
| extend ClientAddress = extract("Client Address:\\s+::ffff:(\\S+)", 1, EventData)
// Flag TGT requests not from expected domain controller IP range
| project TimeGenerated, Computer, ServiceName, ClientAddress, EventData
| order by TimeGenerated desc
```

### SeDebugPrivilege Enabled on Non-Security Process

```kusto
DeviceEvents
| where ActionType == "TokenPrivilegesAdjusted"
| where AdditionalFields has "SeDebugPrivilege"
| where not(InitiatingProcessFileName in~ ("MsMpEng.exe", "mssense.exe"))
| project TimeGenerated, DeviceName, AccountName, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by TimeGenerated desc
```

---

## Response Checklist

| Step | Action |
|---|---|
| 1 | UAC bypass: identify payload launched with high IL; hunt persistence |
| 2 | Golden ticket: reset `krbtgt` password TWICE |
| 3 | SeDebugPrivilege: check what process was accessed post-elevation |
| 4 | Enable Credential Guard to protect Kerberos TGTs |
| 5 | Add domain admins to Protected Users group |

---

## MITRE ATT&CK

| Technique | ID | Coverage |
|---|---|---|
| Bypass UAC | T1548.002 | COM auto-elevate |
| Access Token Manipulation | T1134 | SeDebugPrivilege, impersonation |
| Golden Ticket | T1558.001 | Kerberos TGT anomaly |
