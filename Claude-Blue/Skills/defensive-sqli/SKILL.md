---
name: defensive-sqli
description: "SQL injection detection checklist: WAF log analysis, Sigma rules for SQLi patterns and automated tool fingerprinting, KQL for Azure WAF/SQL audit logs, YARA for sqlmap artifacts, database server process spawn detection, and response steps. Use for SOC triage and detection engineering."
---

# SKILL: SQL Injection Detection

## Metadata
- **Skill Name**: defensive-sqli
- **Folder**: Skills/defensive-sqli
- **Source**: sources/defensive-checklist/sqli.md
- **Mirrors**: offensive-sqli

## Trigger Phrases
Use this skill when the conversation involves any of:
`SQL injection detection, SQLi alert, SQLi Sigma rule, detect sqlmap, database error detection, xp_cmdshell detection, SQLi WAF rule, KQL SQL injection, UNION SELECT detection, time-based SQLi detection`

## Instructions for Claude

When this skill is active:
1. Load and apply the full detection methodology below as your operational checklist
2. Provide Sigma rules for generic SIEM; KQL for Azure-native (Sentinel, Azure SQL Audit, MDE)
3. YARA rules for tool artifacts and webshells where applicable
4. Map to MITRE ATT&CK; flag critical-severity indicators (DB server spawning shells)
5. Suggest triage priority: process spawn > tool fingerprint > payload in params > error confirmation

---

## Full Methodology

# SQL Injection Detection

## Shortcut

- Review WAF logs for SQL keyword patterns; filter blocked first then tune toward `Matched` (allowed but logged).
- Look for database error messages in HTTP responses — these confirm injectable parameters.
- Detect automated tooling by user-agent fingerprints (sqlmap, ghauri) and high-rate requests with incremental mutations.
- Monitor DB server process logs for `xp_cmdshell`, `LOAD_FILE`, `COPY FROM PROGRAM`, `pg_read_file`.
- Alert on DB server processes spawning child shells — this is critical severity.

---

## Detection Scope

| Target | What to Detect |
|---|---|
| Web requests | SQLi syntax in GET/POST params, headers, cookies |
| HTTP responses | Database error messages confirming injection |
| WAF telemetry | OWASP CRS SQLi ruleset (942xxx) hits |
| DB server logs | Abnormal queries, OS execution attempts |
| Process events | DB server spawning child processes (RCE) |
| Network | OOB DNS/HTTP callbacks from SQLi payloads |

---

## Log Sources

| Source | Content | Platform |
|---|---|---|
| Azure Application Gateway WAF | WAF rule hits, blocked requests | Azure |
| Azure Front Door WAF | WAF logs | Azure |
| Web server access logs | Raw HTTP requests | Any |
| MSSQL Audit / Extended Events | Query execution, login events | Windows/Azure SQL |
| MySQL / PostgreSQL general query log | Executed queries | Any |
| Sysmon EventID 1 (process create) | DB server spawning shells | Windows |
| MDE DeviceProcessEvents | Process lineage from DB server | MDE |

---

## Sigma Rules

### SQLi Payload Patterns in HTTP Requests

```yaml
title: SQL Injection Attack Patterns in HTTP Parameters
id: d4e5f6a7-b8c9-0123-defa-123456789003
status: experimental
description: Detects SQL injection payloads in HTTP request parameters.
author: claude-blue
date: 2026-04-27
logsource:
  category: webserver
detection:
  selection_union:
    cs-uri-query|contains:
      - 'UNION SELECT'
      - 'union select'
      - 'union%20select'
  selection_comments:
    cs-uri-query|contains:
      - "' --"
      - "' #"
      - "' OR 1=1"
      - "' OR '1'='1"
  selection_time_based:
    cs-uri-query|contains:
      - 'SLEEP('
      - 'WAITFOR DELAY'
      - 'pg_sleep('
  selection_error_based:
    cs-uri-query|contains:
      - 'extractvalue('
      - 'updatexml('
      - 'floor(rand('
  selection_stacked:
    cs-uri-query|contains:
      - "'; DROP"
      - "'; EXEC"
  condition: 1 of selection_*
falsepositives:
  - SQL in documentation forms
  - Security scanners
level: medium
tags:
  - attack.t1190
```

### SQLi Automated Tool User-Agent

```yaml
title: SQL Injection Automated Tool User-Agent Detection
id: e5f6a7b8-c9d0-1234-efab-234567890004
status: stable
description: Detects HTTP requests from known SQL injection automation tools.
author: claude-blue
date: 2026-04-27
logsource:
  category: webserver
detection:
  selection:
    cs(User-Agent)|contains:
      - 'sqlmap'
      - 'ghauri'
      - 'havij'
      - 'Absinthe'
      - 'pangolin'
  condition: selection
falsepositives:
  - None expected
level: high
tags:
  - attack.t1190
```

### Database Server Spawning Child Shell

```yaml
title: Database Server Process Spawning Child Shell
id: f6a7b8c9-d0e1-2345-fabc-345678901005
status: experimental
description: >
  Detects database server processes spawning shells — indicator of xp_cmdshell,
  COPY FROM PROGRAM, or UDF abuse.
author: claude-blue
date: 2026-04-27
logsource:
  product: windows
  category: process_creation
detection:
  selection_db_parent:
    ParentImage|endswith:
      - '\sqlservr.exe'
      - '\mysqld.exe'
      - '\postgres.exe'
      - '\mongod.exe'
  selection_shell_child:
    Image|endswith:
      - '\cmd.exe'
      - '\powershell.exe'
      - '\wscript.exe'
      - '\certutil.exe'
      - '\net.exe'
  condition: selection_db_parent and selection_shell_child
falsepositives:
  - Legitimate DB maintenance scripts (audit and whitelist)
level: critical
tags:
  - attack.t1190
  - attack.t1059
```

### Database Error in HTTP Response

```yaml
title: Database Error Message in HTTP Response Body
id: a7b8c9d0-e1f2-3456-abcd-456789012006
status: experimental
description: Detects database error messages in HTTP responses confirming injectable parameters.
author: claude-blue
date: 2026-04-27
logsource:
  category: proxy
detection:
  selection:
    response_body|contains:
      - 'You have an error in your SQL syntax'
      - 'ORA-00933'
      - 'Microsoft OLE DB Provider for SQL Server'
      - 'Unclosed quotation mark after the character string'
      - 'pg_query(): Query failed'
      - 'sqlite3.OperationalError'
  condition: selection
falsepositives:
  - Development environments with verbose error pages
level: high
tags:
  - attack.t1190
```

---

## YARA — SQLmap & xp_cmdshell Artifacts

```yara
rule SQLmap_Tool_Artifacts {
    meta:
        description = "Detects sqlmap tool files or output artifacts"
        author = "claude-blue"
        date = "2026-04-27"
    strings:
        $s1 = "sqlmap" nocase
        $s2 = "automatic SQL injection" nocase
        $s3 = "--dbs" ascii
        $s4 = "--dump" ascii
        $s5 = "tamper=" ascii
    condition:
        2 of ($s*)
}

rule SQLi_xp_cmdshell_Abuse {
    meta:
        description = "Detects webshell or script enabling and using xp_cmdshell"
        severity = "critical"
    strings:
        $xp = "xp_cmdshell" nocase ascii wide
        $sp = "sp_configure" nocase ascii wide
        $reconfigure = "RECONFIGURE" nocase ascii wide
    condition:
        $xp and ($sp or $reconfigure)
}
```

---

## KQL — Azure / Microsoft Sentinel

### Azure WAF SQLi Rule Hits

```kusto
AzureDiagnostics
| where ResourceType == "APPLICATIONGATEWAYS"
| where OperationName == "ApplicationGatewayFirewall"
| where action_s in ("Matched", "Blocked")
| where ruleId_s startswith "942"  // OWASP CRS SQLi ruleset
| summarize HitCount=count() by clientIP_s, ruleId_s, requestUri_s, action_s
| order by HitCount desc
```

### MDE: Database Process Spawning Shells

```kusto
DeviceProcessEvents
| where InitiatingProcessFileName in~ ("sqlservr.exe", "mysqld.exe", "postgres.exe")
| where FileName in~ ("cmd.exe", "powershell.exe", "wscript.exe", "net.exe", "certutil.exe")
| project TimeGenerated, DeviceName, InitiatingProcessFileName,
          FileName, ProcessCommandLine, InitiatingProcessCommandLine
| order by TimeGenerated desc
```

### Azure SQL Audit: Dangerous Statement Patterns

```kusto
AzureDiagnostics
| where ResourceType == "SERVERS/DATABASES"
| where Category == "SQLSecurityAuditEvents"
| where statement_s contains "xp_cmdshell"
    or statement_s contains "OPENROWSET"
    or statement_s contains "BULK INSERT"
    or statement_s contains "sp_configure"
| project TimeGenerated, server_instance_name_s, database_name_s,
          client_ip_s, application_name_s, statement_s
| order by TimeGenerated desc
```

### High-Rate Parameter Fuzzing Detection

```kusto
AzureDiagnostics
| where ResourceType == "APPLICATIONGATEWAYS"
| where OperationName == "ApplicationGatewayAccess"
| summarize RequestCount=count(), DistinctParams=dcount(originalRequestUriWithArgs_s)
    by clientIP_s, requestUri_s, bin(TimeGenerated, 5m)
| where RequestCount > 100 and DistinctParams > 20
| order by RequestCount desc
```

---

## Response Checklist

| Step | Action |
|---|---|
| 1 | Identify injection vector: parameter, request type, DB backend |
| 2 | Check for DB error in response (confirms exploitability) |
| 3 | Scope: single IP or distributed campaign? Check for tool UA |
| 4 | Check for DB server process spawning — if confirmed: initiate IR (critical) |
| 5 | Review DB audit logs for bulk `SELECT`, schema enumeration, `DUMP` queries |
| 6 | Rotate DB credentials and API keys if data exfil suspected |
| 7 | Patch SQLi vector; verify with DAST re-scan |

---

## MITRE ATT&CK

| Technique | ID | Coverage |
|---|---|---|
| Exploit Public-Facing Application | T1190 | SQLi against web app |
| OS Command Execution via DB | T1059 | xp_cmdshell, COPY FROM PROGRAM |
| Data from Information Repositories | T1213 | DB dump via UNION SELECT |
| Credentials in Files | T1552.001 | Password hash dump |
