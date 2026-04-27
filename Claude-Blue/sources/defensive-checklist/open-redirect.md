# Open Redirect Detection

## Shortcut

- Alert on redirect/return URL parameters pointing to external domains: `redirect=https://evil.com`.
- Detect encoded/obfuscated external redirect parameters: URL double-encoded, `//evil.com` (protocol-relative), `@` notation.
- Monitor for high volume of redirect parameter usage from a single IP (redirect phishing infrastructure probing).
- Open redirect is primarily used as a stepping stone for phishing and OAuth abuse — check if the request chain continues to a credential harvesting page.

---

## Detection Scope

| Vector | What to Detect |
|---|---|
| External redirect via parameter | `?redirect=`, `?url=`, `?next=`, `?return=` pointing to external host |
| Protocol-relative bypass | `//evil.com` as redirect value |
| Encoded bypass | `%2F%2Fevil.com`, double-encoded |
| @ notation | `https://legit.com@evil.com` |
| OAuth redirect abuse | Open redirect chained with OAuth `redirect_uri` |

---

## Sigma Rules

### External URL in Redirect Parameter

```yaml
title: Open Redirect - External Host in Redirect Parameter
id: f6a7b8c9-d0e1-2345-fabc-890123456035
status: experimental
description: >
  Detects redirect/return URL parameters pointing to external domains.
  Frequently used in phishing attacks and OAuth token theft chains.
author: claude-blue
date: 2026-04-27
logsource:
  category: webserver
detection:
  selection_param:
    cs-uri-query|contains:
      - 'redirect='
      - 'redirect_uri='
      - 'return='
      - 'returnTo='
      - 'next='
      - 'url='
      - 'target='
      - 'goto='
      - 'continue='
  selection_external:
    cs-uri-query|re: '(?:redirect|return|returnTo|next|url|target|goto|continue)=https?://(?!yourdomain\.com|accounts\.yourdomain\.com)'
  condition: selection_param and selection_external
falsepositives:
  - Federated login to known partner domains (allowlist)
level: high
tags:
  - attack.t1566
  - attack.defense_evasion
```

### Protocol-Relative Redirect Bypass

```yaml
title: Open Redirect Protocol-Relative URL Bypass
id: a7b8c9d0-e1f2-3456-abcd-901234567036
status: experimental
description: >
  Detects protocol-relative redirect values (//evil.com) which bypass
  simple "must start with /" server-side validation.
author: claude-blue
date: 2026-04-27
logsource:
  category: webserver
detection:
  selection:
    cs-uri-query|re: '(?:redirect|return|next|url|target)=%2F%2F|(?:redirect|return|next|url|target)=//'
  condition: selection
falsepositives:
  - None expected in production
level: high
tags:
  - attack.t1566
```

---

## KQL — Azure / Microsoft Sentinel

### Application Gateway: External Redirect Parameters

```kusto
AzureDiagnostics
| where ResourceType == "APPLICATIONGATEWAYS"
| where OperationName == "ApplicationGatewayAccess"
| where requestUri_s contains "redirect=" or requestUri_s contains "returnTo="
    or requestUri_s contains "next=" or requestUri_s contains "continue="
| where requestUri_s !contains "yourdomain.com"
| project TimeGenerated, clientIP_s, requestUri_s, httpStatus_d, userAgent_s
| order by TimeGenerated desc
```

### MDE: Browser Navigation to Phishing Post-Redirect

```kusto
DeviceNetworkEvents
| where RemoteUrl contains "redirect=" or RemoteUrl contains "returnTo="
| where not(RemoteUrl has_any ("yourdomain.com", "login.microsoftonline.com"))
| project TimeGenerated, DeviceName, RemoteUrl, InitiatingProcessFileName
| order by TimeGenerated desc
```

---

## Response Checklist

| Step | Action |
|---|---|
| 1 | Identify if the redirect was used for phishing — check if users clicked it |
| 2 | Check downstream URL the user was redirected to |
| 3 | If credentials were submitted to phishing page: treat as compromise, reset credentials |
| 4 | Fix: use allowlist of permitted redirect destinations server-side |
| 5 | Never use user-controlled redirect values — use server-side opaque redirect IDs |

---

## Hardening Reference

- **Allowlist permitted redirect domains**: validate against a server-side list only
- **Avoid user-controlled redirect params**: use session-stored `returnTo` value instead
- **Relative paths only**: if redirecting within app, only allow paths starting with `/`

---

## MITRE ATT&CK

| Technique | ID | Coverage |
|---|---|---|
| Phishing | T1566 | Open redirect as phishing vector |
| Steal Application Access Token | T1528 | Open redirect in OAuth chain |
