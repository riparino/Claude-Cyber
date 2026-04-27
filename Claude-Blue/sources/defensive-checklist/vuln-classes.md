# Vulnerability Classes — Detection Catalog

## Overview
Cross-reference index of detection methods per vulnerability class. Maps each CWE/class to detection format (Sigma, KQL, YARA), key IOCs, and MITRE technique.

## Shortcut

- Any unknown process spawned from web server = RCE candidate.
- `UNION SELECT` in any HTTP parameter = SQLi.
- `<script>` in HTTP response body = Reflected/Stored XSS.
- `file://` or `dict://` in URL parameter = SSRF.
- Crash in `w3wp.exe`/`java.exe` without subsequent restart = exploitation indicator.

---

## Detection Catalog

| Vuln Class | CWE | Primary Signal | Detection Format | Key IOC |
|---|---|---|---|---|
| SQL Injection | CWE-89 | UNION/SELECT in request | Sigma/KQL WAF | `--`, `UNION SELECT`, `OR 1=1` |
| XSS | CWE-79 | `<script>` in response | Sigma/KQL WAF | `<script>`, `onerror=`, `javascript:` |
| RCE | CWE-78/CWE-94 | Shell child process from app | KQL/Sigma | `cmd.exe`, `bash` spawned from `w3wp.exe` |
| SSRF | CWE-918 | Outbound HTTP to internal IP | KQL/Sigma | Requests to `169.254.x.x`, `10.x.x.x` |
| XXE | CWE-611 | DOCTYPE/ENTITY in XML body | Sigma/WAF | `<!DOCTYPE`, `SYSTEM "file://` |
| File Upload | CWE-434 | Uploaded then executed | KQL/YARA | `.php`/`.aspx` uploaded then accessed |
| Deserialization | CWE-502 | Java/PHP magic bytes | YARA/KQL | `aced0005` (Java), `O:` (PHP) |
| Path Traversal | CWE-22 | `../` sequences in URI | Sigma/WAF | `../../../../etc/passwd` |
| SSTI | CWE-94 | Template escape characters | Sigma/KQL | `{{7*7}}`, `${7*7}`, `<%= 7*7 %>` |
| IDOR | CWE-639 | Cross-user resource access | KQL | Sequential ID enumeration |
| Open Redirect | CWE-601 | External URL in redirect param | Sigma/KQL | `?redirect=https://evil.com` |
| HPP | CWE-235 | Duplicate parameters | Sigma | `?id=1&id=2` |
| Race Condition | CWE-362 | Parallel identical requests | KQL | >3 same TX requests in 1s |
| JWT | — | `alg:none` or weak secret | KQL/Sigma | `"alg":"none"` in JWT header |
| OAuth | — | AiTM / redirect abuse | KQL | Unexpected OAuth callback IPs |
| Request Smuggling | CWE-444 | CL+TE header conflict | Sigma/KQL | Both headers present |
| GraphQL | — | Introspection / batch attack | Sigma/KQL | `__schema` from external |

---

## Cross-Reference: Sigma Skill Map

| Skill File | CWE Coverage |
|---|---|
| defensive-sqli | CWE-89 |
| defensive-xss | CWE-79 |
| defensive-rce | CWE-78, CWE-94 |
| defensive-ssrf | CWE-918 |
| defensive-xxe | CWE-611 |
| defensive-file-upload | CWE-434 |
| defensive-deserialization | CWE-502 |
| defensive-ssti | CWE-94 |
| defensive-idor | CWE-639 |
| defensive-open-redirect | CWE-601 |
| defensive-parameter-pollution | CWE-235 |
| defensive-race-condition | CWE-362 |
| defensive-request-smuggling | CWE-444 |
| defensive-graphql | — (GraphQL-specific) |

---

## Unified KQL — All WAF Rule Hits (Top Attackers)

```kusto
AzureDiagnostics
| where ResourceType == "APPLICATIONGATEWAYS"
| where OperationName == "ApplicationGatewayFirewall"
| where action_s == "Blocked"
| summarize
    BlockCount=count(),
    UniqueRules=dcount(ruleId_s),
    RuleIds=make_set(ruleId_s)
  by clientIP_s
| order by BlockCount desc
```

---

## MITRE ATT&CK Cross-Reference

| Class | Technique | ID |
|---|---|---|
| SQLi | Exploit Public-Facing App | T1190 |
| XSS | Drive-by Compromise | T1189 |
| RCE | Server Software Component | T1505 |
| SSRF | Server-Side Proxy Abuse | T1090 |
| Deserialization | Exploit Public-Facing App | T1190 |
| File Upload | Server Software Component | T1505.003 |
