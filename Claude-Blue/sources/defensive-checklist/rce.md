# RCE Detection

## Shortcut

- Alert on web server processes (IIS `w3wp.exe`, Apache `httpd`, nginx, Tomcat, PHP-FPM) spawning unexpected child processes — this is the single highest-signal indicator of web-based RCE.
- Monitor for webshell access patterns: direct HTTP requests to `.php`, `.aspx`, `.jsp` files in upload directories or webroot that have never been accessed before.
- Detect command injection in web request parameters: semicolons, pipe characters, backticks, `$()`, `&&`, `||` in parameter values that also hit web application errors.
- Alert on outbound connections from web server processes to public IPs on unusual ports (reverse shell indicators).
- YARA scan upload directories and webroot for webshell patterns.

---

## Detection Scope

| Vector | What to Detect |
|---|---|
| Web process spawning | Child process from web server parent (highest fidelity) |
| Command injection | Shell metacharacters in request params |
| Webshell access | HTTP requests to newly created/modified scripts |
| Reverse shell | Web process initiating outbound TCP to attacker |
| File creation | New executable/script written by web process |
| Deserialization-triggered RCE | Java/PHP/.NET gadget chain process spawn |

---

## Log Sources

| Source | Content | Platform |
|---|---|---|
| Sysmon EventID 1 | Process creation with parent | Windows |
| MDE DeviceProcessEvents | Full process lineage | MDE |
| MDE DeviceNetworkEvents | Outbound connections from processes | MDE |
| MDE DeviceFileEvents | File creation/modification | MDE |
| Web server access logs | HTTP requests to file paths | Any |
| Azure Application Gateway WAF | WAF rule hits | Azure |
| Linux auditd / Syslog | execve calls, network activity | Linux |

---

## Sigma Rules

### Web Server Process Spawning System Utility

```yaml
title: Web Server Process Spawning System Utilities (RCE Indicator)
id: b8c9d0e1-f2a3-4567-bcde-567890123007
status: experimental
description: >
  Detects web application server processes spawning system utilities — high-fidelity
  indicator of remote code execution via command injection, deserialization, or webshell.
author: claude-blue
date: 2026-04-27
logsource:
  product: windows
  category: process_creation
detection:
  selection_web_parent:
    ParentImage|endswith:
      - '\w3wp.exe'
      - '\httpd.exe'
      - '\tomcat.exe'
      - '\java.exe'
      - '\node.exe'
      - '\python.exe'
      - '\ruby.exe'
      - '\php-cgi.exe'
      - '\php.exe'
  selection_suspicious_child:
    Image|endswith:
      - '\cmd.exe'
      - '\powershell.exe'
      - '\wscript.exe'
      - '\cscript.exe'
      - '\mshta.exe'
      - '\certutil.exe'
      - '\bitsadmin.exe'
      - '\wmic.exe'
      - '\regsvr32.exe'
      - '\rundll32.exe'
      - '\net.exe'
      - '\net1.exe'
      - '\whoami.exe'
      - '\ipconfig.exe'
      - '\systeminfo.exe'
  condition: selection_web_parent and selection_suspicious_child
falsepositives:
  - Application health check scripts (document and baseline)
  - Legitimate admin scripts running under IIS app pool
level: critical
tags:
  - attack.t1190
  - attack.t1059
  - attack.execution
```

### Command Injection Metacharacters in HTTP Parameters

```yaml
title: Command Injection Metacharacters in HTTP Request Parameters
id: c9d0e1f2-a3b4-5678-cdef-678901234008
status: experimental
description: >
  Detects shell metacharacters commonly used in command injection attacks
  within HTTP GET/POST parameters.
author: claude-blue
date: 2026-04-27
logsource:
  category: webserver
detection:
  selection_metacharacters:
    cs-uri-query|contains:
      - ';ls'
      - ';id'
      - ';whoami'
      - '|id'
      - '|whoami'
      - '`id`'
      - '$(id)'
      - '&&id'
      - '||id'
      - ';cat /etc/passwd'
      - ';net user'
      - ';dir '
  selection_encoded:
    cs-uri-query|contains:
      - '%3Bls'
      - '%3Bid'
      - '%7Cid'
      - '%60id%60'
      - '%24%28id%29'
  condition: 1 of selection_*
falsepositives:
  - Developer testing
level: high
tags:
  - attack.t1190
  - attack.t1059
```

### Webshell File Creation by Web Process

```yaml
title: Webshell Written by Web Server Process
id: d0e1f2a3-b4c5-6789-defa-789012345009
status: experimental
description: >
  Detects web server processes creating new script files in web-accessible directories —
  indicator of file upload exploitation leading to webshell deployment.
author: claude-blue
date: 2026-04-27
logsource:
  product: windows
  category: file_event
detection:
  selection_web_writer:
    Image|endswith:
      - '\w3wp.exe'
      - '\httpd.exe'
      - '\java.exe'
      - '\php.exe'
      - '\node.exe'
  selection_script_extension:
    TargetFilename|endswith:
      - '.php'
      - '.php5'
      - '.phtml'
      - '.aspx'
      - '.asp'
      - '.jsp'
      - '.jspx'
      - '.cfm'
      - '.shtml'
  condition: selection_web_writer and selection_script_extension
falsepositives:
  - Legitimate CMS or framework file generation (document and baseline)
level: high
tags:
  - attack.t1505.003
  - attack.persistence
```

### Outbound Network From Web Server Process (Reverse Shell)

```yaml
title: Reverse Shell Indicator - Outbound Connection from Web Process
id: e1f2a3b4-c5d6-7890-efab-890123456010
status: experimental
description: >
  Detects web server processes initiating outbound TCP connections to public IPs —
  indicator of reverse shell callback following RCE exploitation.
author: claude-blue
date: 2026-04-27
logsource:
  product: windows
  category: network_connection
detection:
  selection_web_process:
    Image|endswith:
      - '\w3wp.exe'
      - '\httpd.exe'
      - '\java.exe'
      - '\php.exe'
      - '\node.exe'
      - '\python.exe'
  selection_outbound:
    Initiated: 'true'
  filter_known_ports:
    DestinationPort:
      - 80
      - 443
      - 8080
      - 8443
  condition: selection_web_process and selection_outbound and not filter_known_ports
falsepositives:
  - Legitimate app callbacks on custom ports (document)
level: high
tags:
  - attack.t1059
  - attack.command_and_control
```

---

## YARA — Webshell Detection

```yara
rule Webshell_Generic_PHP {
    meta:
        description = "Generic PHP webshell detection"
        author = "claude-blue"
        severity = "critical"
    strings:
        $eval = /eval\s*\(/ nocase
        $base64 = "base64_decode" nocase
        $system = /system\s*\(/ nocase
        $exec = /exec\s*\(/ nocase
        $passthru = "passthru" nocase
        $shell_exec = "shell_exec" nocase
        $cmd_input = /\$_(GET|POST|REQUEST|COOKIE)\s*\[/ nocase
    condition:
        ($eval or $base64) and 2 of ($system, $exec, $passthru, $shell_exec) and $cmd_input
}

rule Webshell_ASPX_Generic {
    meta:
        description = "Generic ASPX webshell detection"
        author = "claude-blue"
        severity = "critical"
    strings:
        $process = "System.Diagnostics.Process" ascii wide
        $start = ".Start(" ascii wide
        $cmd = "cmd.exe" nocase ascii wide
        $request = "Request[" ascii wide
        $b64 = "Convert.FromBase64String" ascii wide
    condition:
        $process and $start and ($cmd or $request or $b64)
}

rule Webshell_JSP_Generic {
    meta:
        description = "Generic JSP webshell detection"
        author = "claude-blue"
        severity = "critical"
    strings:
        $runtime = "Runtime.getRuntime()" ascii
        $exec = ".exec(" ascii
        $request = "request.getParameter" ascii
        $cmd = "cmd" nocase ascii
    condition:
        $runtime and $exec and $request
}

rule China_Chopper_Webshell {
    meta:
        description = "China Chopper-style one-line webshell"
        author = "claude-blue"
        reference = "T1505.003"
    strings:
        $asp_variant  = /<%eval\s*request\s*\(/  nocase
        $php_variant  = /<?php\s*@?eval\s*\(\$_(POST|GET|REQUEST)/  nocase
    condition:
        any of them
}
```

---

## KQL — Azure / Microsoft Sentinel

### MDE: Web Process Spawning Suspicious Child

```kusto
DeviceProcessEvents
| where InitiatingProcessFileName in~ (
    "w3wp.exe", "httpd.exe", "java.exe", "node.exe",
    "python.exe", "ruby.exe", "php-cgi.exe", "php.exe", "tomcat.exe"
  )
| where FileName in~ (
    "cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe",
    "certutil.exe", "bitsadmin.exe", "whoami.exe", "net.exe",
    "net1.exe", "ipconfig.exe", "systeminfo.exe", "mshta.exe"
  )
| project TimeGenerated, DeviceName, InitiatingProcessFileName,
          FileName, ProcessCommandLine, InitiatingProcessCommandLine,
          InitiatingProcessParentFileName
| order by TimeGenerated desc
```

### MDE: Webshell File Creation Events

```kusto
DeviceFileEvents
| where InitiatingProcessFileName in~ ("w3wp.exe", "httpd.exe", "java.exe", "php.exe")
| where FileName endswith ".php" or FileName endswith ".aspx" or FileName endswith ".jsp"
    or FileName endswith ".asp" or FileName endswith ".jspx"
| project TimeGenerated, DeviceName, InitiatingProcessFileName,
          FileName, FolderPath, SHA256, ActionType
| order by TimeGenerated desc
```

### MDE: Outbound Connections from Web Processes (Reverse Shell)

```kusto
DeviceNetworkEvents
| where InitiatingProcessFileName in~ (
    "w3wp.exe", "httpd.exe", "java.exe", "node.exe", "python.exe", "php.exe"
  )
| where RemoteIPType == "Public"
| where RemotePort !in (80, 443, 8080, 8443)
| project TimeGenerated, DeviceName, InitiatingProcessFileName,
          RemoteIP, RemotePort, RemoteUrl, LocalPort
| order by TimeGenerated desc
```

### Azure WAF RCE Rule Hits (OWASP CRS 932xxx)

```kusto
AzureDiagnostics
| where ResourceType == "APPLICATIONGATEWAYS"
| where OperationName == "ApplicationGatewayFirewall"
| where ruleId_s startswith "932"  // Remote Command Execution rules
| project TimeGenerated, clientIP_s, requestUri_s, ruleId_s, message_s, action_s
| order by TimeGenerated desc
```

---

## Response Checklist

| Step | Action |
|---|---|
| 1 | Confirm RCE vector: command injection, deserialization, file upload, or known CVE |
| 2 | Check for webshell deployed: scan webroot with YARA rules above |
| 3 | Check for reverse shell callbacks: outbound from web process to public IP |
| 4 | Isolate affected web server if active compromise confirmed |
| 5 | Collect memory dump and disk image before remediation |
| 6 | Review all files created/modified by web process in last 7 days |
| 7 | Hunt for lateral movement: check `DeviceNetworkEvents` for internal scanning |
| 8 | Patch vulnerability; verify with DAST re-scan |

---

## MITRE ATT&CK

| Technique | ID | Coverage |
|---|---|---|
| Exploit Public-Facing Application | T1190 | Web-based RCE trigger |
| Web Shell | T1505.003 | Persistent webshell deployment |
| Command and Scripting Interpreter | T1059 | Command injection execution |
| Ingress Tool Transfer | T1105 | Download of tools via RCE |
| Reverse Shell / C2 | T1071 | Outbound C2 from web process |
