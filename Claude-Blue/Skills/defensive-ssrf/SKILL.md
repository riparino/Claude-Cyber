---
name: defensive-ssrf
description: "SSRF detection checklist: cloud metadata endpoint monitoring (169.254.169.254), internal IP range requests from web processes, Sigma rules for SSRF payloads and bypass patterns, KQL for Azure IMDS access and MDE network events, hardening via IMDSv2 enforcement and egress filtering. Use for SOC triage and cloud security."
---

# SKILL: SSRF Detection

## Metadata
- **Skill Name**: defensive-ssrf
- **Folder**: Skills/defensive-ssrf
- **Source**: sources/defensive-checklist/ssrf.md
- **Mirrors**: offensive-ssrf

## Trigger Phrases
Use this skill when the conversation involves any of:
`SSRF detection, server-side request forgery alert, IMDS access detection, cloud metadata detection, 169.254.169.254 detection, SSRF Sigma rule, internal IP request detection, SSRF KQL, detect SSRF Azure`

## Instructions for Claude

When this skill is active:
1. Load and apply the full detection methodology below as your operational checklist
2. Prioritize IMDS access detection — credential theft via SSRF is critical severity
3. Sigma for WAF/web logs; KQL for Azure NSG flows, MDE `DeviceNetworkEvents`, Azure Activity
4. Include IMDSv2 enforcement as primary hardening recommendation for Azure environments
5. Map to MITRE T1552.005 (cloud metadata API)

---

## Full Methodology

# SSRF Detection

## Shortcut

- Alert on web app requests to cloud metadata endpoints: `169.254.169.254` (Azure/AWS IMDS).
- Detect requests to internal RFC1918 ranges originating from web application processes.
- Watch for `file://`, `gopher://`, `dict://` URI schemes in request parameters.
- Check Azure IMDS access logs for unexpected managed identity calls.
- Monitor DNS for resolution of internal hostnames triggered by web application requests.

---

## Detection Scope

| Vector | What to Detect |
|---|---|
| Cloud metadata access | Requests to IMDS endpoints |
| Internal scanning | Web app connecting to RFC1918 addresses |
| Protocol abuse | file://, gopher://, dict:// in URL params |
| Filter bypass | URL encoding, `@`-notation, IPv6, octal IP |

---

## Log Sources

| Source | Content | Platform |
|---|---|---|
| Azure Application Gateway WAF | WAF rule hits, request params | Azure |
| Azure NSG Flow Logs | Network flows from app subnets | Azure |
| MDE DeviceNetworkEvents | Outbound from web processes | MDE |
| Web server access logs | Request parameters | Any |
| DNS logs | OOB callback / internal hostname resolution | Any |

---

## Sigma Rules

### SSRF Payload Patterns in HTTP Parameters

```yaml
title: SSRF Payload Patterns in HTTP Request Parameters
id: f2a3b4c5-d6e7-8901-fabc-901234567011
status: experimental
description: Detects SSRF payloads targeting cloud metadata, internal IPs, and dangerous URI schemes.
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
  selection_internal:
    cs-uri-query|re: '(10\.\d+\.\d+\.\d+|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+)'
  selection_schemes:
    cs-uri-query|contains:
      - 'file://'
      - 'gopher://'
      - 'dict://'
      - 'ldap://'
  selection_localhost:
    cs-uri-query|contains:
      - 'localhost'
      - '127.0.0.1'
      - '0.0.0.0'
      - '::1'
  condition: 1 of selection_*
falsepositives:
  - Load balancer health checks (document expected destinations)
level: high
tags:
  - attack.t1552.005
  - attack.t1590
```

### SSRF Filter Bypass Patterns

```yaml
title: SSRF WAF Bypass Techniques in HTTP Parameters
id: a3b4c5d6-e7f8-9012-abcd-012345678012
status: experimental
description: Detects IP encoding bypass patterns for SSRF filters.
author: claude-blue
date: 2026-04-27
logsource:
  category: webserver
detection:
  selection:
    cs-uri-query|contains:
      - '0x7f000001'
      - '2130706433'
      - '[::ffff:127.0.0.1]'
      - '[::1]'
  condition: selection
falsepositives:
  - IPv6 in legitimate API parameters (rare)
level: high
tags:
  - attack.t1552.005
```

---

## KQL — Azure / Microsoft Sentinel

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

### Azure NSG Flow Logs: App Subnet Reaching IMDS

```kusto
AzureNetworkAnalytics_CL
| where SubType_s == "FlowLog"
| where DestIP_s == "169.254.169.254"
    or DestPort_d in (389, 636, 5985, 5986, 2375, 9200)  // LDAP, WinRM, Docker, ES
| project TimeGenerated, SrcIP_s, DestIP_s, DestPort_d, FlowStatus_s, NSGName_s
| order by TimeGenerated desc
```

### Azure WAF SSRF Rule Hits

```kusto
AzureDiagnostics
| where ResourceType == "APPLICATIONGATEWAYS"
| where OperationName == "ApplicationGatewayFirewall"
| where ruleId_s startswith "934"
    or message_s contains "169.254"
    or message_s contains "SSRF"
| project TimeGenerated, clientIP_s, requestUri_s, ruleId_s, message_s, action_s
| order by TimeGenerated desc
```

---

## Response Checklist

| Step | Action |
|---|---|
| 1 | Confirm target: IMDS, internal service, or external redirect chain |
| 2 | If IMDS hit: check Azure Activity Logs for anomalous API calls from that managed identity |
| 3 | Rotate managed identity credentials if credential exfil suspected |
| 4 | Check for lateral movement: requests to other internal IPs from app |
| 5 | Implement egress filtering: app server → only expected API destinations |
| 6 | Add WAF custom rule blocking `169.254.169.254` in any parameter |
| 7 | Enforce IMDSv2 (requires `Metadata: true` header + PUT token) on all Azure VMs |

---

## Hardening Reference

- **Azure IMDSv2**: Block instance metadata from any process that doesn't use the PUT-token flow
- **Egress filtering**: App subnet should only reach expected API endpoints (allowlist)
- **WAF custom rule**: Block params containing `169.254.169.254`, `metadata.google.internal`
- **Managed Identity scoping**: Least-privilege roles only; monitor for unexpected API usage

---

## MITRE ATT&CK

| Technique | ID | Coverage |
|---|---|---|
| Unsecured Credentials: Cloud Instance Metadata API | T1552.005 | IMDS credential theft |
| Gather Victim Network Information | T1590 | Internal network scanning |
| Exploit Public-Facing Application | T1190 | SSRF as entry vector |
