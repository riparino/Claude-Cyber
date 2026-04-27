---
name: defensive-vuln-classes
description: "Detection catalog across all vulnerability classes: cross-reference of CWE, detection format (Sigma/KQL/YARA), key IOCs, and MITRE techniques. Use as the master index to navigate to specific defensive skills, or for coverage gap analysis. Maps each vuln class to its corresponding defensive skill."
---

# SKILL: Vulnerability Classes Detection Catalog

## Metadata
- **Skill Name**: defensive-vuln-classes
- **Folder**: Skills/defensive-vuln-classes
- **Source**: sources/defensive-checklist/vuln-classes.md
- **Mirrors**: offensive-vuln-classes

## Trigger Phrases
Use this skill when the conversation involves any of:
`vulnerability class detection, detection catalog, CWE detection mapping, MITRE detection mapping, which skill to use, vuln detection cross-reference, security coverage gap analysis, all vulnerability detections`

## Instructions for Claude

When this skill is active:
1. Use this as the master index — map the vulnerability to the specific defensive skill and invoke it
2. Unknown process from web server = RCE; invoke defensive-rce immediately
3. `<script>` in response or WAF 941xxx = XSS; invoke defensive-xss
4. For coverage gap analysis: check if all CWEs in catalog have detection coverage
5. KQL: unified WAF query across all rule groups to identify top attack vectors

---

## Full Methodology

# Vulnerability Classes Detection Catalog

## Master Skill Index

| Vuln Class | CWE | Defensive Skill | Key IOC |
|---|---|---|---|
| SQL Injection | CWE-89 | defensive-sqli | `UNION SELECT`, `OR 1=1`, `--` |
| XSS | CWE-79 | defensive-xss | `<script>`, `onerror=`, `javascript:` |
| RCE | CWE-78/94 | defensive-rce | Shell spawned from app process |
| SSRF | CWE-918 | defensive-ssrf | Outbound HTTP to `169.254.x.x`/`10.x` |
| XXE | CWE-611 | defensive-xxe | `<!DOCTYPE`, `SYSTEM "file://` |
| File Upload | CWE-434 | defensive-file-upload | Webshell written then accessed |
| Deserialization | CWE-502 | defensive-deserialization | Java `aced0005`, PHP `O:` |
| SSTI | CWE-94 | defensive-ssti | `{{7*7}}`, `${7*7}` |
| IDOR | CWE-639 | defensive-idor | Sequential ID enumeration |
| Open Redirect | CWE-601 | defensive-open-redirect | `?redirect=https://evil.com` |
| HPP | CWE-235 | defensive-parameter-pollution | Duplicate params |
| Race Condition | CWE-362 | defensive-race-condition | >3 identical TX requests in 1s |
| JWT Abuse | — | defensive-jwt | `"alg":"none"`, weak HMAC |
| OAuth Abuse | — | defensive-oauth | Redirect abuse, AiTM |
| GraphQL | — | defensive-graphql | `__schema` introspection |
| Request Smuggling | CWE-444 | defensive-request-smuggling | CL+TE conflict |
| Path Traversal | CWE-22 | defensive-rce | `../` in URI |

---

## KQL — Unified WAF Coverage

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

## MITRE ATT&CK Coverage Summary

| Class | Technique | ID |
|---|---|---|
| SQLi, RCE, SSRF | Exploit Public-Facing App | T1190 |
| XSS | Drive-by Compromise | T1189 |
| File Upload, Deserialization | Server Software Component | T1505.003 |
| Keylogger | Input Capture | T1056.001 |
