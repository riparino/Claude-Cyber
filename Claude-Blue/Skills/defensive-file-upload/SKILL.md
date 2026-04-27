---
name: defensive-file-upload
description: "File upload abuse detection checklist: YARA webshell signatures (PHP, ASPX, JSP, China Chopper, reGeorg), HTTP requests to script files in upload directories, MIME/extension mismatch detection, MDE DeviceFileEvents monitoring, webshell creation by web processes. Use for SOC triage, endpoint detection, and DFIR."
---

# SKILL: File Upload Abuse Detection

## Metadata
- **Skill Name**: defensive-file-upload
- **Folder**: Skills/defensive-file-upload
- **Source**: sources/defensive-checklist/file-upload.md
- **Mirrors**: offensive-file-upload

## Trigger Phrases
Use this skill when the conversation involves any of:
`file upload detection, webshell detection, YARA webshell, file upload abuse, malicious upload, detect webshell, PHP webshell YARA, ASPX webshell detection, upload directory monitoring, MDE file upload detection`

## Instructions for Claude

When this skill is active:
1. YARA is the primary detection mechanism — provide webshell rules immediately
2. Sigma rules for HTTP request monitoring and file creation events
3. KQL for MDE DeviceFileEvents (webshell creation) and W3CIISLog (webshell execution)
4. Response checklist must include YARA scan instruction as first step
5. Map to MITRE T1505.003 (Web Shell)

---

## Full Methodology

# File Upload Abuse Detection

## Shortcut

- YARA scan upload directories and webroot for webshell patterns — this is the primary detection.
- Alert on web server processes creating script files in web-accessible directories.
- Monitor HTTP requests to script files within upload directories: `GET /uploads/*.php` is never legitimate.
- Watch for MIME type mismatches: `Content-Type: image/jpeg` + filename `.php`.
- Alert on double extensions in filenames: `shell.php.jpg`.

---

## Detection Scope

| Vector | What to Detect |
|---|---|
| Webshell creation | Script files written to upload directories |
| Webshell execution | HTTP requests to uploaded script files |
| MIME bypass | Content-Type mismatch with script extension |
| Extension bypass | Double extensions, null bytes in filenames |
| ZIP slip | Archive containing script files |

---

## Log Sources

| Source | Content | Platform |
|---|---|---|
| MDE DeviceFileEvents | File creation in web directories | MDE |
| Web server access logs / W3CIISLog | HTTP requests to upload paths | Any/Azure |
| Azure Application Gateway WAF | MIME mismatch, upload rule hits | Azure |
| Sysmon EventID 11 | FileCreate in webroot | Windows |

---

## Sigma Rules

### HTTP Request to Script in Upload Directory (Webshell Execution)

```yaml
title: HTTP Request to Script File in Upload Directory
id: b4c5d6e7-f8a9-0123-bcde-123456789013
status: experimental
description: Webshell execution indicator — script file request in upload/media directory.
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
      - '/attachments/'
  selection_script_ext:
    cs-uri-stem|endswith:
      - '.php'
      - '.php5'
      - '.phtml'
      - '.aspx'
      - '.asp'
      - '.jsp'
      - '.jspx'
  condition: selection_upload_path and selection_script_ext
falsepositives:
  - Apps that legitimately serve scripts from these paths (allowlist)
level: critical
tags:
  - attack.t1505.003
```

### Web Process Writing Script File

```yaml
title: Web Server Process Writing Script File to Web Directory
id: e7f8a9b0-c1d2-3456-efab-456789012016
status: experimental
description: Webshell deployment — web process creating script file.
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
  - CMS plugin installation (baseline)
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
        severity = "critical"
        author = "claude-blue"
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
        description = "Generic ASPX webshell via Process.Start"
        severity = "critical"
    strings:
        $proc  = "System.Diagnostics.Process" ascii wide
        $start = ".Start(" ascii wide
        $cmd   = "cmd.exe" nocase ascii wide
        $req   = "Request[" ascii wide
        $b64   = "Convert.FromBase64String" ascii wide
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
        description = "China Chopper one-line webshell"
        reference   = "T1505.003"
    strings:
        $asp = /<%eval\s*request\s*\(/ nocase
        $php = /<?php\s*@?eval\s*\(\$_(POST|GET|REQUEST)/ nocase
    condition:
        any of them
}

rule Webshell_ReGeorg_Tunnel {
    meta:
        description = "reGeorg web tunnel proxy"
    strings:
        $s1 = "reGeorg" ascii
        $s2 = "Georg says" ascii
        $s3 = "X-CMD" ascii
    condition:
        2 of them
}
```

---

## KQL — Azure / Microsoft Sentinel

### MDE: Script Files Created in Web Directories

```kusto
DeviceFileEvents
| where FolderPath contains "\\inetpub\\" or FolderPath contains "/var/www/"
    or FolderPath contains "\\wwwroot\\" or FolderPath contains "/htdocs/"
| where FileName endswith ".php" or FileName endswith ".aspx"
    or FileName endswith ".asp" or FileName endswith ".jsp"
| where ActionType in ("FileCreated", "FileModified")
| project TimeGenerated, DeviceName, FolderPath, FileName, SHA256,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by TimeGenerated desc
```

### Web Access Log: Script Requests in Upload Dirs

```kusto
W3CIISLog
| where csUriStem contains "/uploads/" or csUriStem contains "/files/" or csUriStem contains "/media/"
| where csUriStem endswith ".php" or csUriStem endswith ".aspx" or csUriStem endswith ".jsp"
| project TimeGenerated, cIP, csMethod, csUriStem, scStatus, csUserAgent
| order by TimeGenerated desc
```

---

## Response Checklist

| Step | Action |
|---|---|
| 1 | YARA scan all files in upload directories immediately |
| 2 | Check web access logs for requests to uploaded script file paths |
| 3 | Identify webshell: creation time, hash, content, attacker IPs |
| 4 | Check for commands executed via webshell: child processes, network |
| 5 | Isolate if active exploitation confirmed |
| 6 | Remove webshell; audit all recently uploaded files |
| 7 | Harden: store uploads outside webroot, no execute permissions, extension allowlist |

---

## Hardening Reference

- **Store uploads outside webroot**: prevent direct HTTP execution
- **No execute permissions** on upload directories: `chmod a-x`
- **Extension allowlist**: only `.jpg`, `.png`, `.pdf` — never script extensions
- **UUID rename on upload**: eliminate attacker-chosen filenames
- **AV scan on write**: integrate before accepting file

---

## MITRE ATT&CK

| Technique | ID | Coverage |
|---|---|---|
| Web Shell | T1505.003 | Primary — webshell via upload |
| Exploit Public-Facing Application | T1190 | Upload leading to RCE |
