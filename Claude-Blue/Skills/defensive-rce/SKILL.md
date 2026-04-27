---
name: defensive-rce
description: "RCE detection checklist: web server process spawn monitoring (highest-fidelity), command injection metacharacter detection, webshell creation and execution detection, reverse shell callbacks, YARA webshell signatures, and KQL for MDE DeviceProcessEvents/DeviceNetworkEvents. Use for SOC triage and detection engineering."
---

# SKILL: Remote Code Execution Detection

## Metadata
- **Skill Name**: defensive-rce
- **Folder**: Skills/defensive-rce
- **Source**: sources/defensive-checklist/rce.md
- **Mirrors**: offensive-rce

## Trigger Phrases
Use this skill when the conversation involves any of:
`RCE detection, remote code execution alert, webshell detection, command injection detection, web process spawn, reverse shell detection, YARA webshell, detect RCE KQL, w3wp.exe child process, detect command injection`

## Instructions for Claude

When this skill is active:
1. Load and apply the full detection methodology below as your operational checklist
2. Highest-priority signal: web server process spawning system utilities — treat as critical
3. Provide Sigma rules for process/network events; KQL for MDE DeviceProcessEvents/DeviceNetworkEvents; YARA for webshell file detection
4. Map to MITRE ATT&CK T1190, T1505.003, T1059
5. Always include response steps covering isolation decision criteria

---

## Full Methodology

# RCE Detection

## Shortcut

- Alert on web server processes (`w3wp.exe`, `httpd`, `java.exe`, PHP-FPM) spawning child processes — this is the single highest-signal RCE indicator.
- YARA scan upload directories and webroot for webshell patterns.
- Monitor HTTP requests directly to script files in upload directories.
- Alert on outbound connections from web processes to public IPs on non-standard ports (reverse shell).
- Detect command injection metacharacters (`;id`, `|whoami`, `$(id)`) in request parameters.

---

## Detection Scope

| Vector | What to Detect |
|---|---|
| Web process spawning | Child process from web server parent (highest fidelity) |
| Command injection | Shell metacharacters in request params |
| Webshell access | HTTP requests to newly created/modified scripts |
| Reverse shell | Web process initiating outbound TCP to attacker |
| File creation | New executable/script written by web process |

---

## Log Sources

| Source | Content | Platform |
|---|---|---|
| Sysmon EventID 1 | Process creation with parent | Windows |
| MDE DeviceProcessEvents | Full process lineage | MDE |
| MDE DeviceNetworkEvents | Outbound connections | MDE |
| MDE DeviceFileEvents | File creation in webroot | MDE |
| Web server access logs | HTTP requests | Any |
| Azure Application Gateway WAF | WAF CRS 932xxx rule hits | Azure |

---

## Sigma Rules

### Web Server Process Spawning System Utility

```yaml
title: Web Server Process Spawning System Utilities (RCE Indicator)
id: b8c9d0e1-f2a3-4567-bcde-567890123007
status: experimental
description: High-fidelity RCE indicator — web process spawning system utilities.
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
      - '\php-cgi.exe'
      - '\php.exe'
  selection_suspicious_child:
    Image|endswith:
      - '\cmd.exe'
      - '\powershell.exe'
      - '\wscript.exe'
      - '\certutil.exe'
      - '\bitsadmin.exe'
      - '\whoami.exe'
      - '\net.exe'
      - '\net1.exe'
      - '\systeminfo.exe'
  condition: selection_web_parent and selection_suspicious_child
falsepositives:
  - Documented health check scripts; baseline expected behavior
level: critical
tags:
  - attack.t1190
  - attack.t1059
```

### Command Injection Metacharacters in HTTP Parameters

```yaml
title: Command Injection Metacharacters in HTTP Parameters
id: c9d0e1f2-a3b4-5678-cdef-678901234008
status: experimental
description: Detects shell metacharacters used in command injection attacks.
author: claude-blue
date: 2026-04-27
logsource:
  category: webserver
detection:
  selection:
    cs-uri-query|contains:
      - ';id'
      - ';whoami'
      - '|id'
      - '|whoami'
      - '`id`'
      - '$(id)'
      - '&&id'
      - ';cat /etc/passwd'
      - ';net user'
  condition: selection
falsepositives:
  - Developer testing
level: high
tags:
  - attack.t1190
  - attack.t1059
```

### Webshell File Created by Web Process

```yaml
title: Web Server Process Writing Script File to Web Directory
id: d0e1f2a3-b4c5-6789-defa-789012345009
status: experimental
description: Detects web server processes creating script files — webshell deployment.
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
  selection_script_ext:
    TargetFilename|endswith:
      - '.php'
      - '.aspx'
      - '.asp'
      - '.jsp'
      - '.jspx'
  condition: selection_web_writer and selection_script_ext
falsepositives:
  - CMS auto-updates (baseline)
level: high
tags:
  - attack.t1505.003
```

---

## YARA — Webshell Detection

```yara
rule Webshell_Generic_PHP {
    meta:
        description = "Generic PHP webshell — eval with user input and system calls"
        author = "claude-blue"
        severity = "critical"
    strings:
        $eval  = /eval\s*\(/ nocase
        $b64   = "base64_decode" nocase
        $sys   = /system\s*\(/ nocase
        $exec  = /exec\s*\(/ nocase
        $shell = "shell_exec" nocase
        $input = /\$_(GET|POST|REQUEST|COOKIE)\s*\[/ nocase
    condition:
        ($eval or $b64) and 2 of ($sys, $exec, $shell) and $input
}

rule Webshell_ASPX_Generic {
    meta:
        description = "Generic ASPX webshell"
        severity = "critical"
    strings:
        $proc  = "System.Diagnostics.Process" ascii wide
        $start = ".Start(" ascii wide
        $cmd   = "cmd.exe" nocase ascii wide
        $req   = "Request[" ascii wide
    condition:
        $proc and $start and ($cmd or $req)
}

rule China_Chopper {
    meta:
        description = "China Chopper one-line webshell"
    strings:
        $asp = /<%eval\s*request\s*\(/ nocase
        $php = /<?php\s*@?eval\s*\(\$_(POST|GET|REQUEST)/ nocase
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
    "python.exe", "ruby.exe", "php-cgi.exe", "php.exe"
  )
| where FileName in~ (
    "cmd.exe", "powershell.exe", "wscript.exe",
    "certutil.exe", "whoami.exe", "net.exe", "net1.exe"
  )
| project TimeGenerated, DeviceName, InitiatingProcessFileName,
          FileName, ProcessCommandLine, InitiatingProcessCommandLine
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
          RemoteIP, RemotePort, RemoteUrl
| order by TimeGenerated desc
```

### MDE: Webshell File Creation Events

```kusto
DeviceFileEvents
| where InitiatingProcessFileName in~ ("w3wp.exe", "httpd.exe", "java.exe", "php.exe")
| where FileName endswith ".php" or FileName endswith ".aspx"
    or FileName endswith ".jsp" or FileName endswith ".asp"
| project TimeGenerated, DeviceName, InitiatingProcessFileName,
          FileName, FolderPath, SHA256, ActionType
| order by TimeGenerated desc
```

---

## Response Checklist

| Step | Action |
|---|---|
| 1 | Confirm RCE vector: command injection, deserialization, file upload, or known CVE |
| 2 | Check for webshell: YARA scan webroot; review file creation events |
| 3 | Check for reverse shell: outbound from web process on non-standard port |
| 4 | Isolate web server if active exploitation confirmed |
| 5 | Collect memory dump + disk image before remediation |
| 6 | Review all files created/modified by web process in last 7 days |
| 7 | Hunt for lateral movement: `DeviceNetworkEvents` for internal scanning from web server |
| 8 | Patch vulnerability; verify with DAST re-scan |

---

## MITRE ATT&CK

| Technique | ID | Coverage |
|---|---|---|
| Exploit Public-Facing Application | T1190 | Web-based RCE trigger |
| Web Shell | T1505.003 | Webshell deployment |
| Command and Scripting Interpreter | T1059 | Command injection execution |
| Ingress Tool Transfer | T1105 | Tool download via RCE |

---

## References & Verified Sources

**MITRE ATT&CK**
- T1190 Exploit Public-Facing Application: https://attack.mitre.org/techniques/T1190/
- T1059 Command and Scripting Interpreter: https://attack.mitre.org/techniques/T1059/
- T1505.003 Web Shell: https://attack.mitre.org/techniques/T1505/003/
- T1105 Ingress Tool Transfer: https://attack.mitre.org/techniques/T1105/

**Detection tables / docs**
- `DeviceProcessEvents` schema: https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceprocessevents-table
- `DeviceNetworkEvents` schema: https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicenetworkevents-table
- Sysmon Event ID 1 (process create): https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon
- Azure WAF (App Gateway) logs: https://learn.microsoft.com/en-us/azure/web-application-firewall/ag/web-application-firewall-logs

**Detection content**
- SigmaHQ web/process_creation rules: https://github.com/SigmaHQ/sigma/tree/master/rules/windows/process_creation
- Microsoft Sentinel "WebShell" hunting queries: https://github.com/Azure/Azure-Sentinel/tree/master/Hunting%20Queries
- Florian Roth webshell YARA rules: https://github.com/Neo23x0/signature-base/tree/master/yara

**Reference incidents (CVE)**
- Log4Shell — CVE-2021-44228: https://nvd.nist.gov/vuln/detail/CVE-2021-44228
- Spring4Shell — CVE-2022-22965: https://nvd.nist.gov/vuln/detail/CVE-2022-22965
- ProxyShell — CVE-2021-34473: https://nvd.nist.gov/vuln/detail/CVE-2021-34473
- MOVEit — CVE-2023-34362: https://nvd.nist.gov/vuln/detail/CVE-2023-34362
- Confluence OGNL — CVE-2022-26134: https://nvd.nist.gov/vuln/detail/CVE-2022-26134
