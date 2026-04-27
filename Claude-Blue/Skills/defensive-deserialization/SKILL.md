---
name: defensive-deserialization
description: "Deserialization attack detection checklist: Java magic byte detection (AC ED 00 05), JNDI injection patterns (Log4Shell CVE-2021-44228), .NET ViewState tampering, ysoserial gadget chain indicators, YARA for serialized payloads, KQL for MDE process spawn and outbound LDAP. Use for SOC triage and detection engineering."
---

# SKILL: Deserialization Attack Detection

## Metadata
- **Skill Name**: defensive-deserialization
- **Folder**: Skills/defensive-deserialization
- **Source**: sources/defensive-checklist/deserialization.md
- **Mirrors**: offensive-deserialization

## Trigger Phrases
Use this skill when the conversation involves any of:
`deserialization detection, Java deserialization alert, Log4Shell detection, JNDI injection detection, ysoserial detection, ViewState tampering, AC ED 00 05 detection, deserialization YARA, Log4j CVE-2021-44228, detect deserialization attack`

## Instructions for Claude

When this skill is active:
1. JNDI injection (Log4Shell) is critical severity — flag it first
2. Java process spawning shells = confirmed RCE via deserialization — initiate IR
3. YARA rules for magic bytes, gadget chains, and JNDI payloads
4. KQL for MDE process events (Java spawning shells) and outbound LDAP/RMI connections
5. Platform-specific hardening: Java (disable external entities), .NET (disable BinaryFormatter), PHP (avoid unserialize with user input)

---

## Full Methodology

# Deserialization Attack Detection

## Shortcut

- Alert on Java magic bytes `AC ED 00 05` / base64 `rO0AB` in HTTP POST bodies.
- Detect JNDI injection: `${jndi:` in any HTTP header or parameter — this is Log4Shell.
- Monitor Java app servers spawning command shells: critical severity, initiate IR.
- Check for outbound LDAP/RMI connections from Java processes (JNDI callback).
- .NET: alert on unusually large ViewState submissions.

---

## Detection Scope

| Platform | What to Detect |
|---|---|
| Java | Magic bytes, JNDI injection, ysoserial gadget chains, app server spawning shells |
| .NET | ViewState tampering, BinaryFormatter gadget chains, MachineKey brute force |
| PHP | `unserialize()` with user input, POP chain indicators |
| Log4Shell | `${jndi:` in any header/param — affects Log4j 2.x ≤2.17.0 |

---

## Sigma Rules

### Java Deserialization Magic Bytes in HTTP POST

```yaml
title: Java Deserialization Magic Bytes in HTTP Request
id: f8a9b0c1-d2e3-4567-fabc-567890123017
status: experimental
description: Java serialized object magic bytes in HTTP POST — deserialization attack indicator.
author: claude-blue
date: 2026-04-27
logsource:
  category: webserver
detection:
  selection:
    cs-method: 'POST'
    request_body|contains:
      - 'rO0AB'      # base64(AC ED 00 05) — Java serialized object
      - 'rO0ABX'
  condition: selection
falsepositives:
  - Legitimate Java RMI over HTTP
level: high
tags:
  - attack.t1190
```

### JNDI Injection (Log4Shell)

```yaml
title: JNDI Injection Patterns in HTTP Headers and Parameters
id: a9b0c1d2-e3f4-5678-abcd-678901234018
status: stable
description: Detects Log4Shell and similar JNDI RCE patterns including obfuscation variants.
references:
  - CVE-2021-44228
author: claude-blue
date: 2026-04-27
logsource:
  category: webserver
detection:
  selection:
    |contains:
      - '${jndi:'
      - '${j${::-n}di:'
      - '${j${lower:n}di:'
      - '${${lower:j}ndi:'
      - '%24%7Bjndi%3A'
      - '\u0024\u007Bjndi'
  condition: selection
falsepositives:
  - Authorized security scanner testing Log4Shell
level: critical
tags:
  - attack.t1190
  - cve.2021.44228
```

### Java App Server Spawning Shell

```yaml
title: Java Application Server Spawning Shell (Deserialization RCE)
id: c1d2e3f4-a5b6-7890-cdef-890123456020
status: experimental
description: High-confidence deserialization RCE — Java app server spawning command shell.
author: claude-blue
date: 2026-04-27
logsource:
  product: windows
  category: process_creation
detection:
  selection_java_parent:
    ParentImage|endswith:
      - '\java.exe'
      - '\javaw.exe'
    ParentCommandLine|contains:
      - 'catalina'
      - 'weblogic'
      - 'jboss'
      - 'websphere'
  selection_shell:
    Image|endswith:
      - '\cmd.exe'
      - '\powershell.exe'
      - '\certutil.exe'
      - '\net.exe'
  condition: selection_java_parent and selection_shell
falsepositives:
  - Build tooling under Java (document and baseline)
level: critical
tags:
  - attack.t1190
  - attack.t1059
```

---

## YARA — Deserialization Artifacts

```yara
rule Java_Serialized_Object {
    meta:
        description = "Java serialized object magic bytes"
    strings:
        $magic = { AC ED 00 05 }
    condition:
        $magic at 0
}

rule Ysoserial_Gadget_Chains {
    meta:
        description = "ysoserial gadget chain class references"
        reference = "https://github.com/frohoff/ysoserial"
    strings:
        $cc1 = "CommonsCollections" ascii
        $cc2 = "org.apache.commons.collections" ascii
        $s1  = "sun.reflect.annotation.AnnotationInvocationHandler" ascii
        $s2  = "com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl" ascii
    condition:
        2 of them
}

rule Log4Shell_JNDI_Payload {
    meta:
        description = "Log4Shell JNDI payload"
        cve = "CVE-2021-44228"
    strings:
        $jndi1 = "${jndi:" nocase ascii
        $ldap  = "ldap://" nocase ascii
        $rmi   = "rmi://" nocase ascii
    condition:
        $jndi1 and ($ldap or $rmi)
}
```

---

## KQL — Azure / Microsoft Sentinel

### MDE: Java Process Spawning Shells

```kusto
DeviceProcessEvents
| where InitiatingProcessFileName in~ ("java.exe", "javaw.exe")
| where InitiatingProcessCommandLine contains "catalina"
    or InitiatingProcessCommandLine contains "weblogic"
    or InitiatingProcessCommandLine contains "jboss"
| where FileName in~ ("cmd.exe", "powershell.exe", "certutil.exe", "net.exe")
| project TimeGenerated, DeviceName, InitiatingProcessFileName,
          InitiatingProcessCommandLine, FileName, ProcessCommandLine
| order by TimeGenerated desc
```

### MDE: JNDI Callback — Outbound LDAP/RMI from Java

```kusto
DeviceNetworkEvents
| where InitiatingProcessFileName in~ ("java.exe", "javaw.exe")
| where RemotePort in (389, 636, 1099, 1389)  // LDAP, LDAPS, RMI, alt-LDAP
| where RemoteIPType == "Public"
| project TimeGenerated, DeviceName, InitiatingProcessFileName,
          RemoteIP, RemotePort, RemoteUrl
| order by TimeGenerated desc
```

---

## Response Checklist

| Step | Action |
|---|---|
| 1 | JNDI injection detected: check for outbound LDAP/RMI callbacks |
| 2 | Java process spawning shell: confirmed RCE — isolate immediately |
| 3 | Identify Log4j version: upgrade to ≥2.17.0 |
| 4 | .NET: rotate MachineKey; enable ViewState MAC; disable BinaryFormatter |
| 5 | Hunt persistence: new files, scheduled tasks, services post-exploitation |
| 6 | Collect memory dump before remediation |

---

## MITRE ATT&CK

| Technique | ID | Coverage |
|---|---|---|
| Exploit Public-Facing Application | T1190 | Deserialization RCE |
| Command and Scripting Interpreter | T1059 | Gadget chain to shell |
| Web Shell | T1505.003 | Post-deserialization webshell |
