# File Upload Abuse Detection

## Shortcut

- YARA scan upload directories for webshell signatures — this is the primary detection for file upload exploitation.
- Alert on web server processes creating executable/script files in upload directories or webroot.
- Monitor HTTP requests directly to upload directory paths: `GET /uploads/*.php`, `GET /uploads/*.aspx` — legitimate files in upload dirs should never be executed.
- Check for MIME type mismatches in WAF logs: `Content-Type: image/jpeg` with file extension `.php`.
- Alert on new files with double extensions: `shell.php.jpg`, `cmd.aspx.png`.

---

## Detection Scope

| Vector | What to Detect |
|---|---|
| Webshell creation | Script files written to upload directories |
| Webshell execution | HTTP requests to uploaded script files |
| MIME bypass | Content-Type mismatch with filename extension |
| Extension bypass | Double extensions, null bytes in filenames |
| Polyglot files | Valid image that also executes as script |
| Large file upload | Potential ZIP slip or archive bomb |

---

## Log Sources

| Source | Content | Platform |
|---|---|---|
| MDE DeviceFileEvents | File creation in web directories | MDE |
| Web server access logs | HTTP requests to upload paths | Any |
| Azure Application Gateway WAF | MIME mismatch, rule hits | Azure |
| Sysmon EventID 11 (FileCreate) | File creation events | Windows |
| File integrity monitoring | Changes in webroot | Any |
| AV / EDR file scan | Malicious file on write | Any |

---

## Sigma Rules

### HTTP Request to Uploaded Script File (Webshell Execution)

```yaml
title: HTTP Request to Script File in Upload Directory
id: b4c5d6e7-f8a9-0123-bcde-123456789013
status: experimental
description: >
  Detects direct HTTP GET/POST requests to script files in upload or media directories —
  indicator of webshell execution following a file upload attack.
author: claude-blue
date: 2026-04-27
logsource:
  category: webserver
detection:
  selection_upload_path:
    cs-uri-stem|contains:
      - '/uploads/'
      - '/upload/'
      - '/files/'
      - '/media/'
      - '/images/'
      - '/img/'
      - '/static/'
      - '/assets/'
      - '/content/'
      - '/attachments/'
  selection_script_extension:
    cs-uri-stem|endswith:
      - '.php'
      - '.php5'
      - '.phtml'
      - '.aspx'
      - '.asp'
      - '.jsp'
      - '.jspx'
      - '.cfm'
      - '.shtml'
  condition: selection_upload_path and selection_script_extension
falsepositives:
  - Applications that legitimately serve script files from these paths (audit and allowlist)
level: critical
tags:
  - attack.t1505.003
  - attack.persistence
```

### File Upload with MIME/Extension Mismatch

```yaml
title: File Upload Content-Type Mismatch with Dangerous Extension
id: c5d6e7f8-a9b0-1234-cdef-234567890014
status: experimental
description: >
  Detects file uploads where Content-Type claims an image/document but
  the filename uses a script extension — common upload restriction bypass.
author: claude-blue
date: 2026-04-27
logsource:
  category: webserver
detection:
  selection_image_ct:
    cs-method: 'POST'
    cs(Content-Type)|contains:
      - 'image/jpeg'
      - 'image/png'
      - 'image/gif'
      - 'application/pdf'
  selection_script_ext:
    cs-uri-query|endswith:
      - '.php'
      - '.aspx'
      - '.jsp'
      - '.asp'
  condition: selection_image_ct and selection_script_ext
falsepositives:
  - None expected for this combination
level: high
tags:
  - attack.t1505.003
```

### Double Extension in Uploaded Filename

```yaml
title: Double Extension in Uploaded Filename
id: d6e7f8a9-b0c1-2345-defa-345678901015
status: experimental
description: >
  Detects filename patterns in upload requests with double extensions commonly
  used to bypass extension allowlist filters.
author: claude-blue
date: 2026-04-27
logsource:
  category: webserver
detection:
  selection:
    cs-uri-query|re: '\.(php|aspx?|jsp|cfm|cgi|shtml)\.(jpg|jpeg|png|gif|pdf|doc|txt)'
  condition: selection
falsepositives:
  - Edge case legitimate filenames
level: high
tags:
  - attack.t1505.003
```

### Webshell File Created by Web Server Process

```yaml
title: Web Server Process Writing Script File to Web Directory
id: e7f8a9b0-c1d2-3456-efab-456789012016
status: experimental
description: >
  Detects web server processes creating script files — indicates successful
  file upload exploitation or RCE leading to webshell deployment.
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
  selection_dangerous_extension:
    TargetFilename|endswith:
      - '.php'
      - '.php5'
      - '.phtml'
      - '.aspx'
      - '.asp'
      - '.jsp'
      - '.jspx'
  condition: selection_web_writer and selection_dangerous_extension
falsepositives:
  - CMS auto-updates, plugin installations (baseline expected behavior)
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
        $eval      = /eval\s*\(/ nocase
        $b64       = "base64_decode" nocase
        $system    = /system\s*\(/ nocase
        $exec      = /exec\s*\(/ nocase
        $passthru  = "passthru" nocase
        $shell     = "shell_exec" nocase
        $input     = /\$_(GET|POST|REQUEST|COOKIE)\s*\[/ nocase
    condition:
        ($eval or $b64) and 2 of ($system, $exec, $passthru, $shell) and $input
}

rule Webshell_ASPX_Generic {
    meta:
        description = "Generic ASPX webshell using Process.Start"
        severity = "critical"
    strings:
        $proc   = "System.Diagnostics.Process" ascii wide
        $start  = ".Start(" ascii wide
        $cmd    = "cmd.exe" nocase ascii wide
        $req    = "Request[" ascii wide
        $b64    = "Convert.FromBase64String" ascii wide
    condition:
        $proc and $start and ($cmd or $req or $b64)
}

rule Webshell_JSP_Runtime {
    meta:
        description = "JSP webshell using Runtime.exec"
        severity = "critical"
    strings:
        $runtime = "Runtime.getRuntime()" ascii
        $exec    = ".exec(" ascii
        $request = "request.getParameter" ascii
    condition:
        $runtime and $exec and $request
}

rule China_Chopper {
    meta:
        description = "China Chopper one-line webshell variants"
        reference   = "T1505.003"
    strings:
        $asp  = /<%eval\s*request\s*\(/ nocase
        $php  = /<?php\s*@?eval\s*\(\$_(POST|GET|REQUEST)/ nocase
    condition:
        any of them
}

rule Webshell_ReGeorg_Tunnel {
    meta:
        description = "reGeorg web tunnel / SOCKS proxy webshell"
    strings:
        $s1 = "reGeorg" ascii
        $s2 = "Georg says" ascii
        $s3 = "Response.AddHeader" ascii
        $s4 = "X-CMD" ascii
    condition:
        2 of them
}

rule Upload_Archive_Suspicious {
    meta:
        description = "ZIP/tar containing script files — potential ZIP slip or webshell delivery"
    strings:
        $zip_magic = { 50 4B 03 04 }
        $php_in_zip = ".php" ascii
        $aspx_in_zip = ".aspx" ascii
    condition:
        $zip_magic at 0 and ($php_in_zip or $aspx_in_zip)
}
```

---

## KQL — Azure / Microsoft Sentinel

### MDE: Script Files Created in Web Directories

```kusto
DeviceFileEvents
| where FolderPath contains "\\inetpub\\" or FolderPath contains "/var/www/"
    or FolderPath contains "\\wwwroot\\" or FolderPath contains "/htdocs/"
| where FileName endswith ".php" or FileName endswith ".aspx" or FileName endswith ".asp"
    or FileName endswith ".jsp" or FileName endswith ".jspx"
| where ActionType == "FileCreated" or ActionType == "FileModified"
| project TimeGenerated, DeviceName, FolderPath, FileName, SHA256,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by TimeGenerated desc
```

### Web Server Access Log: Requests to Upload Directories

```kusto
// Requires web access log ingestion to Log Analytics (e.g., via AMA/IIS logs)
W3CIISLog
| where csUriStem contains "/uploads/" or csUriStem contains "/files/" or csUriStem contains "/media/"
| where csUriStem endswith ".php" or csUriStem endswith ".aspx" or csUriStem endswith ".jsp"
| project TimeGenerated, cIP, csMethod, csUriStem, scStatus, csUserAgent
| order by TimeGenerated desc
```

### Azure WAF: File Upload Rule Hits

```kusto
AzureDiagnostics
| where ResourceType == "APPLICATIONGATEWAYS"
| where OperationName == "ApplicationGatewayFirewall"
| where ruleGroup_s == "REQUEST-933-APPLICATION-ATTACK-PHP"
    or ruleGroup_s == "REQUEST-944-APPLICATION-ATTACK-JAVA"
    or message_s contains "upload"
| project TimeGenerated, clientIP_s, requestUri_s, ruleId_s, message_s, action_s
| order by TimeGenerated desc
```

---

## Response Checklist

| Step | Action |
|---|---|
| 1 | YARA scan all files in upload/webroot directories immediately |
| 2 | Check web access logs for `GET /uploads/*.php` or `POST` to uploaded file paths |
| 3 | Identify webshell file: creation time, hash, content |
| 4 | Check for commands executed via webshell: child processes, network connections |
| 5 | Pull all web access log entries matching that file path → extract attacker IPs |
| 6 | Isolate if active exploitation confirmed; preserve memory and disk |
| 7 | Remove webshell; audit all recently uploaded files |
| 8 | Harden upload handler: allowlist extensions, store outside webroot, strip execute permissions |

---

## Hardening Reference

- **Store uploads outside webroot**: `/var/uploads/` not `/var/www/html/uploads/`
- **No execute permissions**: `chmod a-x` on upload directories
- **Extension allowlist**: only `.jpg`, `.png`, `.pdf` — never script extensions
- **Content-Type validation**: server-side re-check MIME, not just Content-Type header
- **Rename on upload**: use UUID filename + explicit extension from allowlist
- **Antivirus scan on write**: integrate AV scanning before file is accepted

---

## MITRE ATT&CK

| Technique | ID | Coverage |
|---|---|---|
| Web Shell | T1505.003 | Primary — webshell deployment via upload |
| Exploit Public-Facing Application | T1190 | File upload leading to RCE |
| Ingress Tool Transfer | T1105 | Attacker uploading additional tools |
