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

### Detect Blind XSS Out-of-Band Callback Attempts

```yaml
title: Blind XSS Payload Indicators in HTTP Requests
id: b2c3d4e5-f6a7-8901-bcde-f12345678901
status: experimental
description: >
  Detects payloads commonly used for blind XSS testing — specifically XSS Hunter-style
  payloads and script src exfiltration patterns targeting external hosts.
author: claude-blue
date: 2026-04-27
logsource:
  category: webserver
detection:
  selection_xsshunter:
    cs-uri-query|contains:
      - '.xss.ht'
      - 'xsshunter.com'
      - 'xsscanary'
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

### Detect WAF Rule Bypass Attempts (Encoding)

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
      - '%253c'        # double-encoded <
      - '%253e'        # double-encoded >
      - '%2522'        # double-encoded "
      - '%%3c'
  selection_unicode:
    cs-uri-query|contains:
      - '\u003c'       # unicode <
      - '\u003e'       # unicode >
      - '\u0022'       # unicode "
      - '&#x3c;'
      - '&#60;'
  condition: 1 of selection_*
falsepositives:
  - Legitimate encoded content in rich text editors
  - Internationalization edge cases
level: medium
tags:
  - attack.t1059.007
  - attack.defense_evasion
```

---

## KQL — Azure Application Gateway / WAF

### Azure WAF XSS Rule Hits

```kusto
AzureDiagnostics
| where ResourceType == "APPLICATIONGATEWAYS"
| where OperationName == "ApplicationGatewayFirewall"
| where action_s == "Matched" or action_s == "Blocked"
| where ruleId_s startswith "9"  // OWASP CRS XSS rules (941xxx)
    or ruleId_s startswith "941"
| project TimeGenerated, clientIP_s, requestUri_s, ruleId_s, ruleGroup_s,
          message_s, action_s, hostname_s
| order by TimeGenerated desc
```

### Azure Front Door WAF XSS Blocks

```kusto
AzureDiagnostics
| where ResourceType == "FRONTDOORS"
| where Category == "FrontdoorWebApplicationFirewallLog"
| where action_s == "Block" or action_s == "Log"
| where ruleName_s contains "XSS" or ruleName_s contains "941"
| summarize count() by clientIP_s, ruleName_s, requestUri_s
| order by count_ desc
```

### MDE: Network Callbacks from Server-Side XSS Execution

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

### Sentinel: CSP Violation Reports (if forwarded to Log Analytics)

```kusto
// Requires custom table ingestion from your CSP report endpoint
// Table name will vary — example assumes CSPReports_CL
CSPReports_CL
| where violated_directive_s contains "script-src" or violated_directive_s contains "default-src"
| where blocked_uri_s !startswith "self" and blocked_uri_s != "eval" and blocked_uri_s != "inline"
| summarize ViolationCount=count() by blocked_uri_s, document_uri_s, violated_directive_s
| order by ViolationCount desc
```

---

## Response Checklist

| Step | Action |
|---|---|
| 1 | Identify source of XSS: stored (DB) vs reflected (URL) vs DOM (client) |
| 2 | Determine if payload executed in any user browser (check XSS Hunter callbacks, CSP reports) |
| 3 | If stored XSS: identify the storage location and purge payload from DB |
| 4 | If blind XSS fires from admin panel: assume admin session compromise → rotate credentials |
| 5 | Review affected users' session activity in `SigninLogs` for anomalies |
| 6 | Validate CSP is enforced (not `Report-Only`); add `nonce` or `hash` to eliminate `unsafe-inline` |
| 7 | Enable WAF in prevention mode if in detection mode; tune false positive rules |
| 8 | Review `X-XSS-Protection` header status (deprecated but still useful for older browsers) |

---

## Hardening Reference

- **CSP**: `Content-Security-Policy: default-src 'self'; script-src 'self' 'nonce-{random}'; object-src 'none'`
- **Output encoding**: HTML encode `< > " ' &` in all user-supplied content
- **DOM XSS**: Never pass user input to `innerHTML`, `document.write`, `eval`, `setTimeout(string)`
- **HTTPOnly + Secure cookies**: Prevents session token exfil even if XSS fires
- **Subresource Integrity (SRI)**: `<script src="..." integrity="sha256-..." crossorigin="anonymous">`

---

## MITRE ATT&CK

| Technique | ID | Relevance |
|---|---|---|
| Drive-by Compromise | T1189 | Stored/reflected XSS used to attack users visiting the app |
| JavaScript Execution | T1059.007 | XSS payload execution in victim browser |
| Steal Web Session Cookie | T1539 | Session hijack via `document.cookie` exfil |
| Phishing: Spear Phishing Link | T1566.002 | Reflected XSS link sent as phishing lure |
