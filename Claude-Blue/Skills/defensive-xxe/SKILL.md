---
name: defensive-xxe
description: "XXE detection checklist: DOCTYPE/ENTITY in XML requests, OOB callback monitoring, file:// URI read attempts, XInclude patterns, Sigma rules for XML injection, YARA for XXE payloads, KQL for Azure WAF and MDE network callbacks. Use for detection engineering and SOC triage."
---

# SKILL: XXE Detection

## Metadata
- **Skill Name**: defensive-xxe
- **Folder**: Skills/defensive-xxe
- **Source**: sources/defensive-checklist/xxe.md
- **Mirrors**: offensive-xxe

## Trigger Phrases
Use this skill when the conversation involves any of:
`XXE detection, XML external entity alert, DOCTYPE injection detection, ENTITY injection Sigma, OOB XXE detection, file:// XXE, detect XXE, XXE KQL, XML injection detection, XInclude detection`

## Instructions for Claude

When this skill is active:
1. Load and apply the full detection methodology below
2. `file:///etc/passwd` and `file:///windows/win.ini` in XML = critical severity
3. Sigma rules for DOCTYPE, ENTITY, XInclude patterns and OOB testing infrastructure
4. KQL for Azure WAF (921xxx rules) and DNS/network OOB callbacks
5. Primary hardening: disable external entity resolution in XML parser — provide platform-specific code

---

## Full Methodology

# XXE Detection

## Shortcut

- Alert on HTTP POST bodies containing `<!DOCTYPE` or `<!ENTITY`.
- Detect OOB XXE callbacks: DNS/HTTP requests to Burp Collaborator, interact.sh, canarytokens.
- Watch for `file://` URI in XML entity definitions — reads local files.
- Monitor WAF logs for OWASP CRS 921xxx rule hits.
- Check outbound DNS/HTTP from application server after XML processing requests.

---

## Detection Scope

| Vector | What to Detect |
|---|---|
| DOCTYPE/ENTITY in XML | Inline entity definitions |
| OOB XXE callbacks | DNS/HTTP to OOB infrastructure |
| File read attempts | `file://` URI in entities |
| SSRF via XXE | Internal IP in entity URLs |
| XInclude | `<xi:include` in XML |

---

## Sigma Rules

### DOCTYPE/ENTITY in XML HTTP Request

```yaml
title: XML External Entity Injection - DOCTYPE or ENTITY
id: f4a5b6c7-d8e9-0123-fabc-123456789023
status: experimental
description: Detects DOCTYPE declarations and ENTITY definitions in HTTP POST bodies.
author: claude-blue
date: 2026-04-27
logsource:
  category: webserver
detection:
  selection_doctype:
    cs-method: 'POST'
    request_body|contains:
      - '<!DOCTYPE'
      - '<!ENTITY'
  selection_external:
    request_body|contains:
      - 'SYSTEM "file://'
      - 'SYSTEM "http://'
      - 'SYSTEM "ftp://'
  selection_xinclude:
    request_body|contains:
      - 'xmlns:xi="http://www.w3.org/2001/XInclude"'
      - '<xi:include'
  condition: 1 of selection_*
falsepositives:
  - SOAP services using DOCTYPE (very rare; document)
level: high
tags:
  - attack.t1190
```

### XXE OOB Callback Infrastructure

```yaml
title: XXE OOB Callback Infrastructure in XML
id: a5b6c7d8-e9f0-1234-abcd-234567890024
status: experimental
description: Known OOB testing infrastructure in XML entity definitions.
author: claude-blue
date: 2026-04-27
logsource:
  category: webserver
detection:
  selection:
    request_body|contains:
      - 'burpcollaborator.net'
      - 'interact.sh'
      - 'canarytokens.com'
      - 'oast.me'
      - 'oastify.com'
  condition: selection
falsepositives:
  - Authorized security testing
level: high
tags:
  - attack.t1190
```

### Local File Read via XXE

```yaml
title: XXE Local File Read Attempt via file:// URI
id: b6c7d8e9-f0a1-2345-bcde-345678901025
status: experimental
description: XXE targeting local sensitive files via file:// entity.
author: claude-blue
date: 2026-04-27
logsource:
  category: webserver
detection:
  selection:
    request_body|contains:
      - 'file:///etc/passwd'
      - 'file:///etc/shadow'
      - 'file:///proc/self/environ'
      - 'file:///windows/win.ini'
      - 'file://C:/windows/win.ini'
  condition: selection
falsepositives:
  - None expected
level: critical
tags:
  - attack.t1190
  - attack.t1552
```

---

## KQL — Azure / Microsoft Sentinel

### Azure WAF XXE Rule Hits

```kusto
AzureDiagnostics
| where ResourceType == "APPLICATIONGATEWAYS"
| where OperationName == "ApplicationGatewayFirewall"
| where ruleId_s startswith "921"
    or message_s contains "DOCTYPE"
    or message_s contains "ENTITY"
| project TimeGenerated, clientIP_s, requestUri_s, ruleId_s, message_s, action_s
| order by TimeGenerated desc
```

### DNS: OOB XXE Callback Resolution

```kusto
DnsEvents
| where QueryType in ("A", "AAAA")
| where Name contains "burpcollaborator.net" or Name contains "interact.sh"
    or Name contains "oast.me" or Name contains "oastify.com"
| project TimeGenerated, Computer, Name, QueryType, IPAddresses
| order by TimeGenerated desc
```

### MDE: Unexpected Outbound from XML-Processing Services

```kusto
DeviceNetworkEvents
| where InitiatingProcessFileName in~ ("java.exe", "w3wp.exe", "python.exe", "node.exe")
| where RemoteIPType == "Public"
| where RemotePort in (80, 443, 53, 8080)
| project TimeGenerated, DeviceName, InitiatingProcessFileName,
          RemoteIP, RemotePort, RemoteUrl
| order by TimeGenerated desc
```

---

## Response Checklist

| Step | Action |
|---|---|
| 1 | Confirm XXE: identify endpoint and what entity was defined |
| 2 | Check DNS/HTTP logs for OOB callbacks (confirms exploitation) |
| 3 | Check response for leaked file content (in-band XXE) |
| 4 | Identify what files/services were reached via entity resolution |
| 5 | Rotate secrets accessible to the application process |
| 6 | Fix: disable external entity resolution in XML parser |
| 7 | Validate fix: send `<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://canary">]>` — no callback = fixed |

---

## Hardening Reference

- **Java**: `factory.setFeature("http://xml.org/sax/features/external-general-entities", false)`
- **.NET**: `XmlReaderSettings.DtdProcessing = DtdProcessing.Prohibit`
- **Python**: use `defusedxml` library
- **PHP**: `LIBXML_NONET` flag or `libxml_disable_entity_loader(true)` (PHP ≤8.0)
- **WAF**: custom rule blocking `<!ENTITY` or `<!DOCTYPE` in POST bodies

---

## MITRE ATT&CK

| Technique | ID | Coverage |
|---|---|---|
| Exploit Public-Facing Application | T1190 | XXE entry point |
| Credentials in Files | T1552.001 | Local file read via XXE |
| SSRF via XXE | T1190 | XXE to internal service access |
