# XXE Detection

## Shortcut

- Alert on HTTP POST requests with `Content-Type: application/xml` or `text/xml` that contain `<!DOCTYPE` or `<!ENTITY` declarations.
- Detect OOB XXE callback attempts: external entity URLs in XML body pointing to Burp Collaborator, `interact.sh`, or your own canary infrastructure.
- Watch for `file://` URI scheme in XML entity definitions — these attempt to read local files.
- Monitor WAF logs for XXE-specific OWASP CRS rules (921xxx).
- Check DNS and HTTP logs for unexpected requests from your application server to external hosts after XML processing.

---

## Detection Scope

| Vector | What to Detect |
|---|---|
| DOCTYPE/ENTITY in XML | Inline entity definitions — rare in legitimate APIs |
| OOB XXE callbacks | DNS/HTTP requests to external OOB infrastructure |
| File read attempts | `file://` URI in entity definitions |
| SSRF via XXE | Internal IP targets in entity URLs |
| SVG/DOCX/Office XXE | XML-based file formats used as attack carriers |
| XInclude | `<xi:include` in XML — alternative XXE without DOCTYPE |

---

## Log Sources

| Source | Content | Platform |
|---|---|---|
| Web server access logs | POST bodies with XML | Any |
| Azure Application Gateway WAF | XXE rule hits | Azure |
| DNS logs | OOB callback resolutions | Any |
| MDE DeviceNetworkEvents | HTTP callbacks from XML processing | MDE |
| Proxy / SWG | Outbound requests triggered by XML parsing | Any |

---

## Sigma Rules

### DOCTYPE/ENTITY in XML HTTP Request

```yaml
title: XML External Entity Injection - DOCTYPE or ENTITY in Request
id: f4a5b6c7-d8e9-0123-fabc-123456789023
status: experimental
description: >
  Detects XXE attack patterns in HTTP POST request bodies: DOCTYPE declarations
  and ENTITY definitions that indicate external entity injection attempts.
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
  selection_external_entity:
    request_body|contains:
      - 'SYSTEM "file://'
      - "SYSTEM 'file://"
      - 'SYSTEM "http://'
      - 'SYSTEM "https://'
      - 'SYSTEM "ftp://'
  selection_xinclude:
    request_body|contains:
      - 'xmlns:xi="http://www.w3.org/2001/XInclude"'
      - '<xi:include'
  condition: 1 of selection_*
falsepositives:
  - SOAP services that legitimately use DOCTYPE (very rare, document exceptions)
level: high
tags:
  - attack.t1190
  - attack.t1552
```

### XXE OOB Callback Indicators in XML

```yaml
title: XXE Out-of-Band Callback Infrastructure in XML Request
id: a5b6c7d8-e9f0-1234-abcd-234567890024
status: experimental
description: >
  Detects known OOB XXE testing infrastructure hostnames in XML entity definitions —
  indicators of active XXE exploitation or security testing.
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
      - 'xxe.sh'
      - 'oast.me'
      - 'oastify.com'
  condition: selection
falsepositives:
  - Security testing by authorized team
level: high
tags:
  - attack.t1190
```

### File Read via XXE (file:// URI)

```yaml
title: XXE Local File Read Attempt via file:// URI
id: b6c7d8e9-f0a1-2345-bcde-345678901025
status: experimental
description: >
  Detects XXE local file read attempts via file:// URI scheme in XML entity definitions.
  Targets include /etc/passwd, /etc/shadow, and Windows SAM/SYSTEM files.
author: claude-blue
date: 2026-04-27
logsource:
  category: webserver
detection:
  selection:
    request_body|contains:
      - 'file:///etc/passwd'
      - 'file:///etc/shadow'
      - 'file:///etc/hostname'
      - 'file:///proc/self/environ'
      - 'file:///windows/win.ini'
      - 'file:///windows/system32/drivers/etc/hosts'
      - 'file://C:/windows/win.ini'
      - 'file://C:/boot.ini'
  condition: selection
falsepositives:
  - None expected for these specific paths
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
| where ruleId_s startswith "921"  // XXE / XML-related CRS rules
    or message_s contains "DOCTYPE"
    or message_s contains "ENTITY"
| project TimeGenerated, clientIP_s, requestUri_s, ruleId_s, message_s, action_s
| order by TimeGenerated desc
```

### MDE: Unexpected Outbound HTTP from XML-Processing Services

```kusto
DeviceNetworkEvents
| where InitiatingProcessFileName in~ ("java.exe", "w3wp.exe", "python.exe", "ruby.exe", "node.exe")
| where RemoteIPType == "Public"
| where RemotePort in (80, 443, 8080, 53)
| where InitiatingProcessCommandLine !contains "update"
// Narrow to XML processing context if process names are known
| project TimeGenerated, DeviceName, InitiatingProcessFileName,
          RemoteIP, RemotePort, RemoteUrl
| order by TimeGenerated desc
```

### DNS: OOB XXE Callback Resolution

```kusto
// Requires DNS log ingestion to Sentinel
DnsEvents
| where QueryType == "A" or QueryType == "AAAA"
| where Name contains "burpcollaborator.net" or Name contains "interact.sh"
    or Name contains "oast.me" or Name contains "oastify.com"
| project TimeGenerated, Computer, Name, QueryType, IPAddresses
| order by TimeGenerated desc
```

---

## Response Checklist

| Step | Action |
|---|---|
| 1 | Confirm XXE: identify endpoint and what DOCTYPE/ENTITY was submitted |
| 2 | Check for OOB callbacks in DNS/HTTP logs (OOB XXE confirms exploitation) |
| 3 | Check response bodies for file content leaked (in-band XXE) |
| 4 | Identify what files or internal services were reached via entity resolution |
| 5 | Rotate any secrets that were accessible to the application process |
| 6 | Fix: disable external entity resolution in XML parser configuration |
| 7 | Validate fix with test: `<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://your-canary">]>` |

---

## Hardening Reference

- **Disable external entities** in XML parser:
  - Java (SAXParser): `factory.setFeature("http://xml.org/sax/features/external-general-entities", false)`
  - .NET: `XmlReaderSettings.DtdProcessing = DtdProcessing.Prohibit`
  - Python: use `defusedxml` library instead of standard `xml`
  - PHP: `libxml_disable_entity_loader(true)` (PHP ≤8.0), or use `LIBXML_NONET` flag
- **Use JSON** where possible — eliminates XML entity surface
- **WAF custom rule**: block any POST body containing `<!ENTITY` or `<!DOCTYPE`

---

## MITRE ATT&CK

| Technique | ID | Coverage |
|---|---|---|
| Exploit Public-Facing Application | T1190 | XXE entry point |
| Unsecured Credentials: Credentials in Files | T1552.001 | File read via XXE (/etc/passwd) |
| Server-Side Request Forgery (via XXE) | T1190 | XXE → SSRF to internal services |
