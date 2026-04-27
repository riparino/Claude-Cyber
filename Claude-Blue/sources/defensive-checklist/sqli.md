# SQL Injection Detection

## Shortcut

- Review WAF logs for SQL keyword patterns in request parameters; filter `action_s == "Blocked"` first then tune toward detection of `action_s == "Matched"` (allowed but logged).
- Look for database error messages in HTTP responses (500 errors with SQL syntax in body) — these confirm injectable parameters.
- Detect automated SQLi tooling by user-agent fingerprints (sqlmap, ghauri, havij) and high request rates to the same endpoint with incremental parameter mutations.
- Monitor database server process logs for unexpected `xp_cmdshell`, `LOAD_FILE`, `COPY FROM PROGRAM`, or `pg_read_file` invocations.
- Alert on authentication bypass patterns: login requests returning 200 with atypical response size after `' OR 1=1` style input.

---

## Detection Scope

| Target | What to Detect |
|---|---|
| Web requests | SQLi syntax in GET/POST params, headers, cookies |
| HTTP responses | Database error messages confirming injection |
| WAF telemetry | Rule hits for OWASP CRS SQLi ruleset (942xxx) |
| DB server logs | Abnormal queries, OS execution attempts, bulk data reads |
| Process events | DB server spawning child processes (RCE via SQLi) |
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

### SQLi Payload Patterns in HTTP Request Parameters

```yaml
title: SQL Injection Attack Patterns in HTTP Parameters
id: d4e5f6a7-b8c9-0123-defa-123456789003
status: experimental
description: >
  Detects SQL injection payloads in HTTP request parameters including UNION-based,
  boolean-blind, time-based, and error-based patterns.
author: claude-blue
date: 2026-04-27
logsource:
  category: webserver
detection:
  selection_union:
    cs-uri-query|contains:
      - 'UNION SELECT'
      - 'union select'
      - 'UNION+SELECT'
      - 'union%20select'
      - 'union%2bselect'
  selection_comment_terminators:
    cs-uri-query|contains:
      - "' --"
      - "' #"
      - "';--"
      - "'/*"
      - "1' OR '1'='1"
      - "' OR 1=1"
      - "' OR '1'='1"
  selection_time_based:
    cs-uri-query|contains:
      - 'SLEEP('
      - 'WAITFOR DELAY'
      - 'pg_sleep('
      - 'BENCHMARK('
  selection_error_based:
    cs-uri-query|contains:
      - 'extractvalue('
      - 'updatexml('
      - 'floor(rand('
      - 'exp(~('
  selection_stacked:
    cs-uri-query|contains:
      - "'; DROP"
      - "'; INSERT"
      - "'; UPDATE"
      - "'; EXEC"
  condition: 1 of selection_*
falsepositives:
  - SQL-related documentation or code samples submitted through forms
  - Security scanners
level: medium
tags:
  - attack.t1190
  - attack.initial_access
```

### SQLi Automated Tool Fingerprinting (sqlmap / ghauri)

```yaml
title: SQL Injection Automated Tool User-Agent Detection
id: e5f6a7b8-c9d0-1234-efab-234567890004
status: stable
description: >
  Detects HTTP requests from known SQL injection automation tools via User-Agent strings.
  sqlmap, ghauri, havij, and similar tools have distinct UA patterns.
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
      - 'BSQL Hacker'
  condition: selection
falsepositives:
  - None expected for these specific strings
level: high
tags:
  - attack.t1190
  - attack.discovery
```

### Database Server Spawning Child Process (RCE via SQLi)

```yaml
title: Database Server Process Spawning Child Shell
id: f6a7b8c9-d0e1-2345-fabc-345678901005
status: experimental
description: >
  Detects database server processes spawning command shells — indicator of
  xp_cmdshell execution (MSSQL), COPY FROM PROGRAM (PostgreSQL), or UDF abuse (MySQL).
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
      - '\cscript.exe'
      - '\mshta.exe'
      - '\certutil.exe'
      - '\net.exe'
  condition: selection_db_parent and selection_shell_child
falsepositives:
  - Legitimate DB maintenance scripts that launch cmd.exe (rare; audit these)
level: critical
tags:
  - attack.t1190
  - attack.execution
  - attack.t1059
```

### Database Error in HTTP Response (Confirmed Injection Point)

```yaml
title: Database Error Message in HTTP Response Body
id: a7b8c9d0-e1f2-3456-abcd-456789012006
status: experimental
description: >
  Detects database error messages leaked in HTTP responses, confirming an injectable
  parameter. Requires response body inspection (NGFW, proxy, WAF with full inspection).
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
      - 'Syntax error or access violation'
      - 'mysql_fetch_array()'
  condition: selection
falsepositives:
  - Development environments with verbose error pages
level: high
tags:
  - attack.t1190
```

---

## YARA — SQLmap & SQLi Tool Artifacts

```yara
rule SQLmap_Tool_Artifacts {
    meta:
        description = "Detects sqlmap tool files or output artifacts"
        author = "claude-blue"
        date = "2026-04-27"
        reference = "https://github.com/sqlmapproject/sqlmap"
    strings:
        $s1 = "sqlmap" nocase
        $s2 = "automatic SQL injection" nocase
        $s3 = "--dbs" ascii
        $s4 = "--dump" ascii
        $s5 = "tamper=" ascii
        $path1 = "/sqlmap/" ascii
        $path2 = "\\sqlmap\\" ascii
    condition:
        2 of ($s*) or 1 of ($path*)
}

rule SQLi_WebShell_MSSQL_xp_cmdshell {
    meta:
        description = "Detects webshell or script using MSSQL xp_cmdshell"
        author = "claude-blue"
        severity = "critical"
    strings:
        $xp = "xp_cmdshell" nocase ascii wide
        $exec = "EXEC " nocase ascii wide
        $sp = "sp_configure" nocase ascii wide
        $reconfigure = "RECONFIGURE" nocase ascii wide
    condition:
        $xp and ($exec or $sp or $reconfigure)
}
```

---

## KQL — Azure / Microsoft Sentinel

### Azure WAF SQLi Blocks

```kusto
AzureDiagnostics
| where ResourceType == "APPLICATIONGATEWAYS"
| where OperationName == "ApplicationGatewayFirewall"
| where action_s in ("Matched", "Blocked")
| where ruleId_s startswith "942"  // OWASP CRS SQLi ruleset
| summarize HitCount=count() by clientIP_s, ruleId_s, requestUri_s, action_s
| order by HitCount desc
```

### MDE: Database Server Spawning Processes

```kusto
DeviceProcessEvents
| where InitiatingProcessFileName in~ ("sqlservr.exe", "mysqld.exe", "postgres.exe")
| where FileName in~ ("cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe", "net.exe", "certutil.exe")
| project TimeGenerated, DeviceName, InitiatingProcessFileName,
          FileName, ProcessCommandLine, InitiatingProcessCommandLine
| order by TimeGenerated desc
```

### Sentinel: High-Volume Parameter Fuzzing (SQLi Automation)

```kusto
AzureDiagnostics
| where ResourceType == "APPLICATIONGATEWAYS"
| where OperationName == "ApplicationGatewayAccess"
| summarize RequestCount=count(), DistinctParams=dcount(originalRequestUriWithArgs_s)
    by clientIP_s, requestUri_s, bin(TimeGenerated, 5m)
| where RequestCount > 100 and DistinctParams > 20
| order by RequestCount desc
```

### Azure SQL: Suspicious Query Patterns (requires Azure SQL Audit)

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

---

## Response Checklist

| Step | Action |
|---|---|
| 1 | Identify injection vector: parameter name, request type, DB backend |
| 2 | Check if error-based confirmation exposed DB schema or version info |
| 3 | Review WAF logs for scope: single IP or distributed campaign |
| 4 | Check for DB server process spawning (xp_cmdshell, COPY FROM PROGRAM) |
| 5 | If OS execution confirmed: treat as full RCE → initiate IR |
| 6 | Review DB audit logs for `SELECT`, `UNION`, bulk `DUMP` queries |
| 7 | Rotate DB credentials and API keys if exfil suspected |
| 8 | Patch underlying SQLi vector; verify with DAST re-scan |

---

## MITRE ATT&CK

| Technique | ID | Coverage |
|---|---|---|
| Exploit Public-Facing Application | T1190 | SQLi against web app |
| OS Command Execution via DB | T1059 | xp_cmdshell, COPY FROM PROGRAM |
| Data from Information Repositories | T1213 | DB dump via UNION SELECT |
| Credentials in Files | T1552.001 | Password hash dump via SQLi |
