---
name: defensive-xss
description: "XSS detection checklist: WAF log analysis, Sigma rules for script injection patterns, KQL for Azure WAF/Application Gateway, CSP violation monitoring, blind XSS callback detection, response steps, and hardening verification. Use for SOC triage, detection engineering, and blue team XSS coverage."
---

# SKILL: XSS Detection

## Metadata
- **Skill Name**: defensive-xss
- **Folder**: Skills/defensive-xss
- **Source**: sources/defensive-checklist/xss.md
- **Mirrors**: offensive-xss

## Trigger Phrases
Use this skill when the conversation involves any of:
`XSS detection, cross-site scripting alert, XSS Sigma rule, CSP violation, blind XSS callback, XSS WAF rule, detect XSS, XSS KQL, JavaScript injection detection, DOM XSS hunting`

## Instructions for Claude

When this skill is active:
1. Load and apply the full detection methodology below as your operational checklist
2. Provide Sigma rules for generic SIEM platforms; KQL for Azure-native tables (Sentinel, MDE, Defender)
3. For each detection, state: what it catches, false positive risk, and severity rating
4. Map findings to MITRE ATT&CK technique IDs
5. Suggest hardening steps and next detection gaps to cover

---

## Full Methodology

# XSS Detection

## Shortcut

- Check WAF/web server logs for script injection patterns, suspicious parameter values, and encoded payloads.
- Validate CSP headers are configured and enforced; look for `unsafe-inline` and `unsafe-eval` as detection gaps.
- Deploy out-of-band XSS callback infrastructure (XSS Hunter or equivalent) to catch blind XSS from admin panels or internal tooling.
- Correlate JavaScript-heavy errors in client-side telemetry with suspicious input sequences.
- Review `Content-Security-Policy-Report-Only` logs for policy violations as early-warning signals.

---

## Detection Scope

XSS attacks target the client via server-delivered content. Defenders should monitor:
1. **Inbound payloads** — detect attack strings before they are stored or reflected
2. **Storage events** — detect when malicious content enters a database
3. **Execution callbacks** — detect when stored XSS fires in victim browsers (blind XSS)
4. **CSP violations** — detect policy bypass attempts and missing CSP coverage

---

## Log Sources

| Source | Content | Platform |
|---|---|---|
| Azure Application Gateway / WAF | HTTP request/response logs, WAF rule hits | Azure |
| Azure Front Door | WAF logs, access logs | Azure |
| Web server access logs (Apache/nginx/IIS) | Raw HTTP request lines | Any |
| Sysmon EventID 3 (network) | Outbound callbacks from servers | Windows |
| Browser CSP Report endpoints | `csp-report` JSON POSTs | Application |
| Microsoft Defender for Endpoint | `DeviceNetworkEvents`, `DeviceEvents` | MDE |

---

## Sigma Rules

### Detect XSS Patterns in Web Request Parameters

```yaml
title: XSS Attack Patterns in HTTP Request Parameters
id: a1b2c3d4-e5f6-7890-abcd-ef1234567890
status: experimental
description: >
  Detects common XSS payloads in HTTP GET/POST parameters via web server access logs.
  Covers script tags, event handlers, javascript: URI scheme, and common bypass patterns.
author: claude-blue
date: 2026-04-27
logsource:
  category: webserver
detection:
  selection_script_tags:
    cs-uri-query|contains:
      - '<script'
      - '%3cscript'
      - '%3Cscript'
      - '\x3cscript'
  selection_event_handlers:
    cs-uri-query|contains:
      - 'onerror='
      - 'onload='
      - 'onclick='
      - 'onmouseover='
      - 'onfocus='
      - 'onblur='
      - 'onkeypress='
  selection_javascript_uri:
    cs-uri-query|contains:
      - 'javascript:'
      - 'javascript%3a'
      - 'javascript%3A'
      - 'vbscript:'
  selection_data_uri:
    cs-uri-query|contains:
      - 'data:text/html'
      - 'data%3atext%2fhtml'
  selection_dom_sinks:
    cs-uri-query|contains:
      - 'document.cookie'
      - 'document.write'
      - 'innerHTML'
      - 'eval('
  condition: 1 of selection_*
falsepositives:
  - Security scanning tools
  - Developers testing locally
  - WAF testing
level: medium
tags:
  - attack.initial_access
  - attack.t1189
  - attack.t1059.007
```

### Detect Blind XSS Out-of-Band Callback Payloads

```yaml
title: Blind XSS Payload Indicators in HTTP Requests
id: b2c3d4e5-f6a7-8901-bcde-f12345678901
status: experimental
description: >
  Detects payloads commonly used for blind XSS testing — XSS Hunter-style
  payloads and script src exfiltration patterns targeting external hosts.
author: claude-blue
date: 2026-04-27
logsource:
  category: webserver
detection:
  selection_oob_hosts:
    cs-uri-query|contains:
      - '.xss.ht'
      - 'xsshunter.com'
      - 'burpcollaborator.net'
      - 'interact.sh'
      - 'canarytokens.com'
  selection_script_src_external:
    cs-uri-query|re: '<script[^>]*src\s*=\s*["\']?https?://'
  condition: 1 of selection_*
falsepositives:
  - Legitimate external script references in content editors
level: high
tags:
  - attack.t1059.007
```

### Detect XSS WAF Bypass via Encoding

```yaml
title: XSS WAF Bypass via Encoding Techniques
id: c3d4e5f6-a7b8-9012-cdef-012345678902
status: experimental
description: >
  Detects common XSS WAF bypass encoding patterns: double URL encoding,
  Unicode escaping, HTML entity encoding mixed with tag syntax.
author: claude-blue
date: 2026-04-27
logsource:
  category: webserver
detection:
  selection_double_encode:
    cs-uri-query|contains:
      - '%253c'
      - '%253e'
      - '%2522'
  selection_unicode:
    cs-uri-query|contains:
      - '\u003c'
      - '\u003e'
      - '&#x3c;'
      - '&#60;'
  condition: 1 of selection_*
falsepositives:
  - Legitimate encoded content in rich text editors
level: medium
tags:
  - attack.t1059.007
  - attack.defense_evasion
```

---

## KQL — Azure / Microsoft Sentinel

### Azure WAF XSS Rule Hits

```kusto
AzureDiagnostics
| where ResourceType == "APPLICATIONGATEWAYS"
| where OperationName == "ApplicationGatewayFirewall"
| where action_s in ("Matched", "Blocked")
| where ruleId_s startswith "941"  // OWASP CRS XSS ruleset
| project TimeGenerated, clientIP_s, requestUri_s, ruleId_s, ruleGroup_s,
          message_s, action_s, hostname_s
| order by TimeGenerated desc
```

### Azure Front Door WAF XSS Blocks

```kusto
AzureDiagnostics
| where ResourceType == "FRONTDOORS"
| where Category == "FrontdoorWebApplicationFirewallLog"
| where action_s in ("Block", "Log")
| where ruleName_s contains "XSS" or ruleName_s contains "941"
| summarize HitCount=count() by clientIP_s, ruleName_s, requestUri_s
| order by HitCount desc
```

### MDE: Unexpected Outbound Network from Web Server Processes

```kusto
DeviceNetworkEvents
| where InitiatingProcessFileName in~ ("w3wp.exe", "php-cgi.exe", "node.exe", "python.exe", "ruby.exe")
| where RemoteIPType == "Public"
| where RemotePort in (80, 443, 8080, 8443)
| where InitiatingProcessCommandLine !contains "update" and InitiatingProcessCommandLine !contains "install"
| project TimeGenerated, DeviceName, InitiatingProcessFileName,
          InitiatingProcessCommandLine, RemoteIP, RemotePort, RemoteUrl
| order by TimeGenerated desc
```

---

## Response Checklist

| Step | Action |
|---|---|
| 1 | Identify XSS type: stored (DB) vs reflected (URL param) vs DOM (client-side) |
| 2 | Determine if payload executed — check XSS Hunter callbacks, CSP violation reports |
| 3 | Stored XSS: locate storage point, purge payload, audit other stored fields |
| 4 | Blind XSS fired from admin panel → assume admin session compromise; rotate creds |
| 5 | Review affected users' session activity in `SigninLogs` for post-exploitation anomalies |
| 6 | Validate CSP is `enforce` mode, not `Report-Only`; remove `unsafe-inline`/`unsafe-eval` |
| 7 | Enable WAF in prevention mode if still in detection; tune noisy rules |

---

## Hardening Reference

- **CSP**: `Content-Security-Policy: default-src 'self'; script-src 'self' 'nonce-{random}'; object-src 'none'`
- **Output encoding**: HTML encode `< > " ' &` on all user-supplied output
- **DOM sinks**: Never assign user input to `innerHTML`, `document.write`, `eval`, `setTimeout(string)`
- **Cookies**: `HttpOnly; Secure; SameSite=Strict` — limits session exfil even if XSS fires
- **SRI**: `<script integrity="sha256-..." crossorigin="anonymous">` for all third-party scripts

---

## MITRE ATT&CK

| Technique | ID | Coverage |
|---|---|---|
| Drive-by Compromise | T1189 | Stored/reflected XSS targeting users |
| JavaScript Execution | T1059.007 | XSS payload execution |
| Steal Web Session Cookie | T1539 | `document.cookie` exfil |
| Phishing: Spear Phishing Link | T1566.002 | Reflected XSS as phishing lure |
