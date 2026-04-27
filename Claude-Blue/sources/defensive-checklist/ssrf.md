# SSRF Detection

## Shortcut

- Alert on HTTP requests to cloud metadata endpoints from web application processes: `169.254.169.254` (AWS/Azure IMDS), `metadata.google.internal`, `100.100.100.200` (Alibaba).
- Detect requests to internal RFC1918 ranges (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`) originating from web application processes.
- Monitor for `file://` URI scheme in request parameters — these are never legitimate from a web application.
- Watch WAF logs for SSRF-specific bypass patterns: URL encoding, `@`-notation (`http://attacker@169.254.169.254`), IPv6 notation.
- Check Azure IMDS access logs and alert on any metadata service calls from application identities with unexpected scopes.

---

## Detection Scope

| Vector | What to Detect |
|---|---|
| Cloud metadata access | Requests to IMDS endpoints (169.254.169.254) |
| Internal scanning | Web app making requests to RFC1918 addresses |
| Protocol abuse | file://, gopher://, dict:// in URL params |
| DNS rebinding | Rapid DNS changes + connection to resolved internal IP |
| Filter bypass | URL encoding, redirect chains, IPv6 notation in params |

---

## Log Sources

| Source | Content | Platform |
|---|---|---|
| Azure Application Gateway WAF | WAF rule hits, request params | Azure |
| Azure NSG Flow Logs | Network flows from app subnets | Azure |
| Azure Monitor (IMDS access) | Metadata service calls with identity | Azure |
| MDE DeviceNetworkEvents | Outbound from web processes | MDE |
| Web server access logs | Request parameters | Any |
| Proxy / SWG logs | Outbound HTTP requests from servers | Any |

---

## Sigma Rules

### SSRF Payload Patterns in HTTP Parameters

```yaml
title: SSRF Payload Patterns in HTTP Request Parameters
id: f2a3b4c5-d6e7-8901-fabc-901234567011
status: experimental
description: >
  Detects SSRF payloads in HTTP parameters targeting cloud metadata services,
  internal IP ranges, and dangerous URI schemes.
author: claude-blue
date: 2026-04-27
logsource:
  category: webserver
detection:
  selection_imds:
    cs-uri-query|contains:
      - '169.254.169.254'
      - 'metadata.google.internal'
      - '100.100.100.200'
      - 'fd00:ec2::254'    # AWS IMDSv6
  selection_internal_ips:
    cs-uri-query|re: '(10\.\d+\.\d+\.\d+|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+)'
  selection_dangerous_schemes:
    cs-uri-query|contains:
      - 'file://'
      - 'gopher://'
      - 'dict://'
      - 'ldap://'
      - 'ftp://'
      - 'sftp://'
  selection_localhost:
    cs-uri-query|contains:
      - 'localhost'
      - '127.0.0.1'
      - '0.0.0.0'
      - '::1'
      - '0177.0.0.1'   # octal bypass
  condition: 1 of selection_*
falsepositives:
  - Load balancer health checks
  - Internal API integrations (document expected destinations)
level: high
tags:
  - attack.t1552.005
  - attack.t1590
```

### SSRF Filter Bypass Patterns

```yaml
title: SSRF WAF Filter Bypass Techniques in HTTP Parameters
id: a3b4c5d6-e7f8-9012-abcd-012345678012
status: experimental
description: >
  Detects SSRF bypass patterns including @ notation, IP encoding variants,
  and DNS rebinding indicators.
author: claude-blue
date: 2026-04-27
logsource:
  category: webserver
detection:
  selection_at_bypass:
    cs-uri-query|re: 'https?://[^@]+@169\.254'
  selection_ip_encoding:
    cs-uri-query|contains:
      - '0x7f000001'      # 127.0.0.1 hex
      - '2130706433'      # 127.0.0.1 decimal
      - '017700000001'    # 127.0.0.1 octal
  selection_ipv6:
    cs-uri-query|contains:
      - '[::ffff:127.0.0.1]'
      - '[::1]'
      - '[0:0:0:0:0:ffff:7f00:0001]'
  condition: 1 of selection_*
falsepositives:
  - Rare; IPv6 addresses in legitimate API parameters
level: high
tags:
  - attack.t1552.005
```

---

## KQL — Azure / Microsoft Sentinel

### Azure IMDS Access from Application Identity (Unexpected Scope)

```kusto
// Detect Azure IMDS metadata calls — requires Azure Monitor VM insights or custom collection
// Alert on access from unexpected service principals or managed identities
AzureActivity
| where OperationNameValue contains "MICROSOFT.COMPUTE/VIRTUALMACHINES"
| where ActivityStatusValue == "Success"
| where Caller !in (datatable(Caller: string) ["known-service-principal@tenant.com"])
| project TimeGenerated, Caller, OperationNameValue, ResourceGroup, Resource
| order by TimeGenerated desc
```

### MDE: Web Process Connecting to IMDS or Internal Ranges

```kusto
DeviceNetworkEvents
| where InitiatingProcessFileName in~ (
    "w3wp.exe", "httpd.exe", "java.exe", "node.exe",
    "python.exe", "ruby.exe", "php.exe"
  )
| where RemoteIP == "169.254.169.254"
    or RemoteIP startswith "10."
    or RemoteIP startswith "192.168."
    or (RemoteIP startswith "172." and toint(split(RemoteIP, ".")[1]) between (16 .. 31))
| project TimeGenerated, DeviceName, InitiatingProcessFileName,
          InitiatingProcessCommandLine, RemoteIP, RemotePort, RemoteUrl
| order by TimeGenerated desc
```

### Azure NSG Flow Logs: App Subnet Reaching Internal Services

```kusto
AzureNetworkAnalytics_CL
| where SubType_s == "FlowLog"
| where SrcIP_s in~ (network_app_subnets)  // parameterize with your app subnet CIDRs
| where DestIP_s == "169.254.169.254"
    or DestPort_d in (2375, 2376, 6443, 8443, 9200, 5601, 27017)  // common internal services
| project TimeGenerated, SrcIP_s, DestIP_s, DestPort_d, FlowStatus_s
| order by TimeGenerated desc
```

### Azure WAF SSRF Rule Hits

```kusto
AzureDiagnostics
| where ResourceType == "APPLICATIONGATEWAYS"
| where OperationName == "ApplicationGatewayFirewall"
| where ruleId_s startswith "934"  // Server-Side Request Forgery rules
    or message_s contains "SSRF"
    or message_s contains "169.254"
| project TimeGenerated, clientIP_s, requestUri_s, ruleId_s, message_s, action_s
| order by TimeGenerated desc
```

---

## Response Checklist

| Step | Action |
|---|---|
| 1 | Confirm target: IMDS, internal service, or external redirect chain |
| 2 | If IMDS accessed: check if credentials were returned (Azure MSI token exfil) |
| 3 | Review Azure Activity Logs for anomalous API calls from the MSI/Service Principal |
| 4 | Rotate any Managed Identity credentials that may have been exposed |
| 5 | Check for lateral movement: requests to internal IPs from application |
| 6 | Implement egress filtering: web app should only reach expected destinations |
| 7 | Block cloud metadata endpoint at WAF; add custom OWASP rule for 169.254.169.254 |
| 8 | Require `IMDSv2` (requires header `Metadata: true` + PUT token flow) on all Azure VMs |

---

## Hardening Reference

- **Azure**: Enforce IMDSv2 only — prevents SSRF from harvesting credentials with simple GET
- **Allowlist outbound**: Web application server egress should target only known APIs
- **WAF custom rule**: Block any request parameter containing `169.254.169.254`, `metadata.google.internal`
- **Private DNS**: Block internal DNS from resolving IMDS hostnames externally
- **Network segmentation**: App subnet → backend only; not to management plane

---

## MITRE ATT&CK

| Technique | ID | Coverage |
|---|---|---|
| Unsecured Credentials: Cloud Instance Metadata API | T1552.005 | IMDS credential theft via SSRF |
| Gather Victim Network Information | T1590 | Internal network scanning via SSRF |
| Exploit Public-Facing Application | T1190 | SSRF as initial access vector |
