# HTTP Request Smuggling — Detection & Defense

## Overview
HTTP/1.1 request desync via conflicting Transfer-Encoding and Content-Length headers. CL.TE and TE.CL variants. Sigma for desync indicators. KQL for Azure Application Gateway anomalies and "smuggled" downstream requests.

## Shortcut

- CL.TE: front-end uses `Content-Length`, back-end uses `Transfer-Encoding`. Attacker controls what back-end reads as the "next request start."
- TE.CL: front-end uses `Transfer-Encoding`, back-end uses `Content-Length`. Leftover body bytes poison next request.
- Detection: response to attacker's malformed request returned to different client's response cycle.
- Observable: unexplained 400/401 responses on regular user requests; timeout loops; access control bypasses.

---

## Attack Variants

### CL.TE (Classic)
```
POST / HTTP/1.1
Host: target.com
Content-Length: 13
Transfer-Encoding: chunked

0

SMUGGLED
```

### TE.CL
```
POST / HTTP/1.1
Host: target.com
Transfer-Encoding: chunked
Content-Length: 3

8
SMUGGLED
0
```

### Obfuscated TE Header
```
Transfer-Encoding: xchunked
Transfer-Encoding: chunked
Transfer-Encoding:\tchunked
X-Transfer-Encoding: chunked  (some middleware forwards)
```

---

## Sigma Rules

```yaml
title: HTTP Request Smuggling - Both Transfer-Encoding and Content-Length
id: a1b2c345-6789-abcd-ef01-2345678901cd
status: experimental
description: Detects HTTP requests with both Transfer-Encoding and Content-Length headers (desync indicator)
logsource:
  category: webserver
detection:
  selection:
    cs-header|contains:
      - "Transfer-Encoding:"
    cs-header|contains:
      - "Content-Length:"
  condition: selection
falsepositives:
  - Some legitimate proxies/clients; filter by unusual sequences
level: medium
tags:
  - attack.t1599
```

```yaml
title: Obfuscated Transfer-Encoding Header
id: b2c3d456-7890-bcde-f012-3456789012de
status: experimental
description: Detects obfuscated Transfer-Encoding headers used in request smuggling
logsource:
  category: webserver
detection:
  selection:
    cs-header|re: 'Transfer-Encoding\s*:\s*(xchunked|identity\s*\r?\n\s*chunked|\tchunked)'
  condition: selection
falsepositives:
  - Misconfigured clients
level: high
tags:
  - attack.t1599
```

---

## KQL — Azure Application Gateway

### Repeated 400/500 Responses to Same IP

```kusto
AzureDiagnostics
| where ResourceType == "APPLICATIONGATEWAYS"
| where httpStatusCode_d in (400, 413, 501, 505)
| summarize ErrorCount=count() by clientIP_s, bin(TimeGenerated, 5m)
| where ErrorCount > 10
| order by ErrorCount desc
```

### Transfer-Encoding + Content-Length in Same Request

```kusto
AzureDiagnostics
| where ResourceType == "APPLICATIONGATEWAYS"
| where Message contains "Transfer-Encoding" and Message contains "Content-Length"
| project TimeGenerated, clientIP_s, requestUri_s, httpStatusCode_d, Message
| order by TimeGenerated desc
```

### Abnormal Chunked Encoding

```kusto
W3CIISLog
| where csMethod == "POST"
| where csHeaders contains "Transfer-Encoding: chunked"
| where toint(scStatus) between (400 .. 599)
| project TimeGenerated, cIP, csUriStem, csHeaders, scStatus
| order by TimeGenerated desc
```

---

## Hardening

| Control | Implementation |
|---|---|
| Normalize at WAF | Reject requests with both CL and TE |
| Use HTTP/2 | End-to-end HTTP/2 eliminates CL.TE desync |
| Validate TE | Reject obfuscated or non-standard TE values |
| Upstream sync | Ensure front-end and back-end use same header precedence |

---

## MITRE ATT&CK

| Technique | ID | Notes |
|---|---|---|
| Exploitation of Public-Facing Application | T1190 | Request desync leading to ACL bypass |
| Adversary-in-the-Middle | T1557 | Poisoning other users' requests |
