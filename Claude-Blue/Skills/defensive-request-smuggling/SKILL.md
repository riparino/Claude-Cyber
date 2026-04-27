---
name: defensive-request-smuggling
description: "HTTP request smuggling detection: CL.TE and TE.CL desync, obfuscated Transfer-Encoding headers. Sigma for conflicting CL+TE headers. KQL for Azure Application Gateway 400/500 anomalies and header conflicts. Use for SOC triage and HTTP proxy hardening."
---

# SKILL: Request Smuggling Detection

## Metadata
- **Skill Name**: defensive-request-smuggling
- **Folder**: Skills/defensive-request-smuggling
- **Source**: sources/defensive-checklist/request-smuggling.md
- **Mirrors**: offensive-request-smuggling

## Trigger Phrases
Use this skill when the conversation involves any of:
`request smuggling detection, HTTP desync detection, CL.TE detection, TE.CL detection, Transfer-Encoding Content-Length conflict, HTTP 400 anomaly, chunked encoding bypass, request smuggling Sigma`

## Instructions for Claude

When this skill is active:
1. Both CL and TE headers in same request = desync risk; flag and investigate
2. Obfuscated TE: `Transfer-Encoding: xchunked` or tab-prefixed = bypass attempt
3. Repeated 400/413 from same IP = probe for desync; investigate
4. Fix: normalize at WAF (reject requests with both headers); prefer end-to-end HTTP/2
5. CL.TE impacts downstream users; check for access control bypass via poisoned next request

---

## Full Methodology

# HTTP Request Smuggling Detection

## Shortcut

- Both `Content-Length` and `Transfer-Encoding` in same request = desync indicator.
- Obfuscated TE (tab, extra space, `xchunked`) = bypass attempt.
- Repeated 400s from same IP on `/` = desync probing.
- Victim gets attacker's response = observable as unexpected 401/403 on benign request.

---

## Key Detection Signals

| Signal | Indicator | Severity |
|---|---|---|
| CL+TE conflict | Both headers in same request | High |
| Obfuscated TE | Non-standard TE value | High |
| 400 storm | >10 errors from same IP in 5m | Medium |
| Access bypass | User gets 401 without any auth failure | High |

---

## KQL — Azure Application Gateway

### Repeated 400/500 Responses (Desync Probing)

```kusto
AzureDiagnostics
| where ResourceType == "APPLICATIONGATEWAYS"
| where httpStatusCode_d in (400, 413, 501, 505)
| summarize ErrorCount=count() by clientIP_s, bin(TimeGenerated, 5m)
| where ErrorCount > 10
| order by ErrorCount desc
```

### Header Conflict Detection

```kusto
AzureDiagnostics
| where ResourceType == "APPLICATIONGATEWAYS"
| where Message contains "Transfer-Encoding" and Message contains "Content-Length"
| project TimeGenerated, clientIP_s, requestUri_s, httpStatusCode_d, Message
| order by TimeGenerated desc
```

---

## Response Checklist

| Step | Action |
|---|---|
| 1 | CL+TE conflict: check WAF logs for downstream impact |
| 2 | Enable WAF rule to reject conflicting headers |
| 3 | Upgrade to HTTP/2 end-to-end (eliminates CL.TE) |
| 4 | Ensure front-end and back-end agree on header precedence |
| 5 | Investigate unexplained 401/403 responses on legitimate users |

---

## MITRE ATT&CK

| Technique | ID | Coverage |
|---|---|---|
| Exploit Public-Facing Application | T1190 | Desync for access control bypass |
| Adversary-in-the-Middle | T1557 | Poisoning other users' requests |
