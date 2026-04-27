---
name: defensive-open-redirect
description: "Open redirect detection: external domain in redirect parameters, protocol-relative bypass (//evil.com), encoded bypass patterns. Sigma rules for redirect parameter anomalies, KQL for Azure Application Gateway and MDE network events. Used as phishing and OAuth token theft vector. Use for SOC triage and web application security."
---

# SKILL: Open Redirect Detection

## Metadata
- **Skill Name**: defensive-open-redirect
- **Folder**: Skills/defensive-open-redirect
- **Source**: sources/defensive-checklist/open-redirect.md
- **Mirrors**: offensive-open-redirect

## Trigger Phrases
Use this skill when the conversation involves any of:
`open redirect detection, detect URL redirect abuse, redirect parameter phishing, open redirect Sigma, redirect_uri external domain, open redirect KQL, open redirect bypass detection`

## Instructions for Claude

When this skill is active:
1. Alert on redirect/return URL parameters pointing to external domains — primary detection signal
2. Detect bypass variants: `//evil.com` (protocol-relative), double-encoded, `@` notation
3. Open redirect is most dangerous when chained with OAuth `redirect_uri` — check for OAuth context
4. KQL for Azure Application Gateway access logs and MDE network events
5. Fix: use server-side allowlist of permitted redirect destinations; never trust user-supplied URLs

---

## Full Methodology

# Open Redirect Detection

## Shortcut

- `redirect=https://` pointing to non-allowlisted domain = flag.
- `//evil.com` (protocol-relative) = common `startsWith('/')` bypass.
- Open redirect in OAuth flow = critical (auth code theft vector).

---

## Detection: Key Signals

| Vector | Indicator | Severity |
|---|---|---|
| External redirect param | `?redirect=https://external.com` | High |
| Protocol-relative | `?return=//evil.com` | High |
| OAuth chain | Open redirect in `redirect_uri` | Critical |
| Encoded bypass | `%2F%2Fevil.com` | High |

---

## Sigma Rules (Summary)

1. **External redirect param**: `redirect=|return=|next=|url=` with non-allowlisted HTTPS URL → high
2. **Protocol-relative**: `redirect=%2F%2F` or `redirect=//` → high

See `sources/defensive-checklist/open-redirect.md` for full Sigma YAML with allowlist regex.

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

### MDE: Browser Navigation Following Redirect

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
| 1 | Determine if redirect was used for phishing — check click-through |
| 2 | Identify destination URL users were redirected to |
| 3 | If credentials submitted to phishing page: treat as compromise |
| 4 | Fix: server-side allowlist of permitted redirect destinations |
| 5 | For OAuth: lock `redirect_uri` to exact pre-registered values |

---

## MITRE ATT&CK

| Technique | ID | Coverage |
|---|---|---|
| Phishing | T1566 | Open redirect as phishing delivery |
| Steal Application Access Token | T1528 | Open redirect in OAuth chain |
