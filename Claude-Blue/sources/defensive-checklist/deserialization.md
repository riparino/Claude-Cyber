# Deserialization Attack Detection

## Shortcut

- Alert on Java deserialization magic bytes (`AC ED 00 05`) in HTTP POST bodies received by Java web applications.
- Monitor for ysoserial and similar gadget chain tool artifacts: process names, YARA signatures on disk.
- Detect .NET `BinaryFormatter`, `LosFormatter`, `ObjectStateFormatter` usage via process telemetry (these were deprecated for security reasons).
- Watch for PHP `unserialize()` call sites with user-controlled input — Semgrep SAST can flag these.
- Alert on web process spawning shells following deserialization endpoints being called (same as RCE detection but scoped to known deserialization endpoints).

---

## Detection Scope

| Platform | What to Detect |
|---|---|
| Java | `AC ED 00 05` magic bytes in POST, ysoserial gadget chains, JNDI injection (Log4Shell) |
| .NET | BinaryFormatter usage, ViewState tampering, MachineKey exposure |
| PHP | `unserialize()` with user input, POP chain gadgets, Phar deserialization |
| Python | `pickle.loads()` with untrusted input |
| Ruby | YAML.load with untrusted input (gadget chains) |

---

## Log Sources

| Source | Content | Platform |
|---|---|---|
| Web server access logs | POST requests to vulnerable endpoints | Any |
| MDE DeviceProcessEvents | Process spawn from Java/app server | MDE |
| MDE DeviceNetworkEvents | JNDI callback, reverse shell | MDE |
| Sysmon EventID 1, 3 | Process creation, network connection | Windows |
| Azure Application Gateway WAF | Deserialization-specific rules | Azure |
| DNS logs / Sentinel DNS | JNDI/LDAP callback resolution | Azure |

---

## Sigma Rules

### Java Deserialization Magic Bytes in HTTP POST

```yaml
title: Java Deserialization Magic Bytes in HTTP Request Body
id: f8a9b0c1-d2e3-4567-fabc-567890123017
status: experimental
description: >
  Detects Java serialized object magic bytes (0xAC 0xED 0x00 0x05) or their
  base64 equivalent in HTTP POST request bodies — indicator of Java deserialization attack.
author: claude-blue
date: 2026-04-27
logsource:
  category: webserver
detection:
  selection_magic_bytes:
    cs-method: 'POST'
    request_body|contains:
      - 'rO0AB'      # base64 of AC ED 00 05 (Java serialized)
      - 'rO0ABX'
  selection_ysoserial_indicators:
    request_body|contains:
      - 'CommonsCollections'
      - 'org.apache.commons'
      - 'sun.reflect.annotation'
  condition: 1 of selection_*
falsepositives:
  - Legitimate Java RMI applications using serialization
level: high
tags:
  - attack.t1190
  - attack.t1059
```

### JNDI Injection Pattern (Log4Shell variants)

```yaml
title: JNDI Injection Patterns in HTTP Headers and Parameters
id: a9b0c1d2-e3f4-5678-abcd-678901234018
status: stable
description: >
  Detects JNDI injection patterns in HTTP headers and parameters, covering
  Log4Shell (CVE-2021-44228) and similar JNDI-based RCE vulnerabilities.
  Includes obfuscation bypass patterns.
author: claude-blue
date: 2026-04-27
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2021-44228
logsource:
  category: webserver
detection:
  selection_jndi:
    |contains:
      - '${jndi:'
      - '${j${::-n}di:'
      - '${j${lower:n}di:'
      - '${${lower:j}ndi:'
      - '%24%7Bjndi%3A'    # URL encoded
      - '\u0024\u007Bjndi'  # unicode escaped
  condition: selection_jndi
falsepositives:
  - Security scanner testing for Log4Shell
level: critical
tags:
  - attack.t1190
  - attack.t1059
  - cve.2021.44228
```

### .NET ViewState Tampering (Blacklist Bypass)

```yaml
title: ASP.NET ViewState Tampering or MachineKey Brute Force
id: b0c1d2e3-f4a5-6789-bcde-789012345019
status: experimental
description: >
  Detects unusually large ViewState values or ViewState submitted without MAC validation —
  indicator of .NET deserialization gadget chain via ViewState.
author: claude-blue
date: 2026-04-27
logsource:
  category: webserver
detection:
  selection_large_viewstate:
    cs-method: 'POST'
    request_body|contains: '__VIEWSTATE'
    # Flag ViewState values over 10KB (tune per application baseline)
    cs-bytes|gte: 10000
  selection_no_mac:
    request_body|contains: '__VIEWSTATE'
    request_body|not contains: '__VIEWSTATEGENERATOR'
  condition: 1 of selection_*
falsepositives:
  - Pages with large grid controls (tune threshold per application)
level: medium
tags:
  - attack.t1190
```

### Java Process Spawning Shell (Post-Deserialization RCE)

```yaml
title: Java Application Server Spawning Shell (Deserialization RCE)
id: c1d2e3f4-a5b6-7890-cdef-890123456020
status: experimental
description: >
  Detects Java application servers (Tomcat, WebLogic, JBoss, WebSphere) spawning
  command shells — high-fidelity indicator of deserialization RCE exploitation.
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
      - 'glassfish'
      - 'wildfly'
  selection_shell:
    Image|endswith:
      - '\cmd.exe'
      - '\powershell.exe'
      - '\wscript.exe'
      - '\certutil.exe'
      - '\net.exe'
  condition: selection_java_parent and selection_shell
falsepositives:
  - Build scripts or DevOps tooling running under Java (document and baseline)
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
        author = "claude-blue"
    strings:
        $magic = { AC ED 00 05 }
    condition:
        $magic at 0
}

rule Ysoserial_Gadget_Chains {
    meta:
        description = "Detects ysoserial tool output / gadget chain class names"
        author = "claude-blue"
        reference = "https://github.com/frohoff/ysoserial"
    strings:
        $cc1  = "CommonsCollections" ascii
        $cc2  = "org.apache.commons.collections" ascii
        $s1   = "sun.reflect.annotation.AnnotationInvocationHandler" ascii
        $s2   = "org.springframework.core.SerializableTypeWrapper" ascii
        $s3   = "com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl" ascii
    condition:
        2 of them
}

rule Log4Shell_JNDI_Payload {
    meta:
        description = "Log4Shell JNDI payload patterns"
        author = "claude-blue"
        cve = "CVE-2021-44228"
    strings:
        $jndi1 = "${jndi:" nocase ascii
        $jndi2 = "${j${" nocase ascii
        $ldap  = "ldap://" nocase ascii
        $rmi   = "rmi://" nocase ascii
    condition:
        ($jndi1 or $jndi2) and ($ldap or $rmi)
}

rule DotNet_Deserialization_ViewState_Gadget {
    meta:
        description = "Potential .NET deserialization payload via ViewState"
    strings:
        $vs    = "__VIEWSTATE" ascii
        $type  = "System.Windows.Data.ObjectDataProvider" ascii wide
        $type2 = "System.Activities.Presentation.WorkflowDesigner" ascii wide
    condition:
        $vs and ($type or $type2)
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
| where FileName in~ ("cmd.exe", "powershell.exe", "wscript.exe", "certutil.exe", "net.exe")
| project TimeGenerated, DeviceName, InitiatingProcessFileName,
          InitiatingProcessCommandLine, FileName, ProcessCommandLine
| order by TimeGenerated desc
```

### MDE: JNDI Callback — Outbound LDAP/RMI from Java Process

```kusto
DeviceNetworkEvents
| where InitiatingProcessFileName in~ ("java.exe", "javaw.exe")
| where RemotePort in (389, 636, 1099, 1389)  // LDAP, LDAPS, RMI, alt-LDAP
| where RemoteIPType == "Public"
| project TimeGenerated, DeviceName, InitiatingProcessFileName,
          RemoteIP, RemotePort, RemoteUrl, InitiatingProcessCommandLine
| order by TimeGenerated desc
```

### Sentinel: JNDI Injection in Log Analytics (Custom Table)

```kusto
// If web logs are ingested via AMA or custom connector
CommonSecurityLog
| where RequestURL contains "${jndi:" or RequestURL contains "${j${"
    or AdditionalExtensions contains "${jndi:"
| project TimeGenerated, SourceIP, DestinationIP, RequestURL, AdditionalExtensions
| order by TimeGenerated desc
```

### Azure WAF: Java/Deserialization Attack Rules

```kusto
AzureDiagnostics
| where ResourceType == "APPLICATIONGATEWAYS"
| where OperationName == "ApplicationGatewayFirewall"
| where ruleGroup_s in (
    "REQUEST-944-APPLICATION-ATTACK-JAVA",
    "REQUEST-933-APPLICATION-ATTACK-PHP"
  )
| project TimeGenerated, clientIP_s, requestUri_s, ruleId_s, message_s, action_s
| order by TimeGenerated desc
```

---

## Response Checklist

| Step | Action |
|---|---|
| 1 | Identify deserialization endpoint — which class/method received the payload |
| 2 | Check for JNDI callback DNS/LDAP (indicates Log4Shell-style) |
| 3 | Check for process spawn from Java/app server: shell execution confirmation |
| 4 | Isolate affected application server if active exploitation confirmed |
| 5 | Patch: upgrade Log4j (≥2.17.0), update Java app server, disable dangerous formatters |
| 6 | .NET: rotate MachineKey; enable ViewState MAC validation; disable BinaryFormatter |
| 7 | Hunt for persistence: new files, scheduled tasks, services created post-exploitation |

---

## MITRE ATT&CK

| Technique | ID | Coverage |
|---|---|---|
| Exploit Public-Facing Application | T1190 | Deserialization RCE entry point |
| Command and Scripting Interpreter | T1059 | Shell execution via gadget chain |
| Web Shell | T1505.003 | Webshell dropped post-deserialization |
| JNDI Injection / Log4Shell | T1190 | CVE-2021-44228 specific |
