---
name: defensive-waf-hardening
description: "WAF configuration, tuning, and gap analysis: Azure WAF CRS OWASP 3.2, mode progression (Detection to Prevention), FP tuning, custom rules, encoded payload blind spots. Sigma for WAF bypass attempts. KQL for rule coverage analysis and top blocked IPs. Use for security architecture review and WAF posture management."
---

# SKILL: WAF Hardening

## Metadata
- **Skill Name**: defensive-waf-hardening
- **Folder**: Skills/defensive-waf-hardening
- **Source**: sources/defensive-checklist/waf-hardening.md
- **Mirrors**: offensive-waf-bypass

## Trigger Phrases
Use this skill when the conversation involves any of:
`WAF hardening, WAF tuning, WAF false positive, WAF Detection mode, WAF Prevention mode, Azure WAF CRS, WAF gap analysis, WAF rule bypass, WAF custom rules, OWASP 3.2 WAF`

## Instructions for Claude

When this skill is active:
1. WAF in Detection mode = logging only; transition to Prevention after FP tuning
2. Azure WAF CRS: XSS 941xxx, SQLi 942xxx, RCE 932xxx, SSRF 934xxx, Java 944xxx
3. KQL: identify top fired rules and top blocked IPs; scope exclusions per argument, not globally
4. Double-encoded payloads bypass CRS — enable full decode inspection
5. Custom rules for app-specific patterns complement OOTB CRS coverage

---

## Full Methodology

# WAF Hardening

## Shortcut

- Detection → Prevention transition: tune for 2–4 weeks; add scoped exclusions; then Prevention.
- Scoped exclusions only: `RequestArgNames` / `RequestHeaderNames`, never global.
- Top WAF gaps: double-encoding, large JSON body, non-standard content types.
- Bot protection: enable in WAF to block automated scanning.

---

## CRS Rule Groups (Azure)

| Group | IDs | Covers |
|---|---|---|
| REQUEST-941 | 941xxx | XSS |
| REQUEST-942 | 942xxx | SQL Injection |
| REQUEST-932 | 932xxx | RCE / OS Command |
| REQUEST-921 | 921xxx | Protocol Attack / XXE |
| REQUEST-944 | 944xxx | Java / Deserialization |

---

## KQL — Azure WAF

### Rules Matching (Detection Mode Exposure)

```kusto
AzureDiagnostics
| where ResourceType == "APPLICATIONGATEWAYS"
| where OperationName == "ApplicationGatewayFirewall"
| where action_s == "Matched"
| where ruleId_s startswith "942" or ruleId_s startswith "941" or ruleId_s startswith "932"
| summarize MatchCount=count() by ruleId_s, clientIP_s, bin(TimeGenerated, 1h)
| order by MatchCount desc
```

### Top Blocked IPs

```kusto
AzureDiagnostics
| where ResourceType == "APPLICATIONGATEWAYS"
| where OperationName == "ApplicationGatewayFirewall"
| where action_s == "Blocked"
| summarize BlockCount=count() by clientIP_s
| top 20 by BlockCount desc
```

---

## Response Checklist

| Step | Action |
|---|---|
| 1 | Check current mode (Detection vs Prevention) |
| 2 | Review top matched rules; identify FPs |
| 3 | Add scoped exclusions (not global) for FP patterns |
| 4 | Enable Prevention mode |
| 5 | Enable bot protection and rate limiting custom rules |

---

## MITRE ATT&CK

| Technique | ID | Coverage |
|---|---|---|
| Impair Defenses | T1562 | WAF disabled/bypass |
| Obfuscated Files | T1027 | Encoded payload detection |
