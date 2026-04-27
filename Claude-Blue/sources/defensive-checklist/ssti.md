# SSTI Detection

## Shortcut

- Check WAF logs for template expression syntax in request parameters: `{{`, `${`, `<#`, `{%`, `#{}`.
- Detect mathematical expression evaluation as blind SSTI probe: `{{7*7}}` returning `49` confirms Jinja2/Twig; `${7*7}` → Freemarker/Thymeleaf.
- Alert on web process spawning shells following requests to template rendering endpoints.
- Monitor for `{{config}}`, `{{self.__dict__}}`, `__class__.__mro__` in request parameters — these are Python/Jinja2 object traversal patterns used for RCE escalation.
- SSTI often affects user profile fields, email templates, and report generation endpoints — focus monitoring there.

---

## Detection Scope

| Engine | Patterns to Detect |
|---|---|
| Jinja2 (Python) | `{{7*7}}`, `{{config}}`, `__class__.__mro__`, `__subclasses__()` |
| Twig (PHP) | `{{7*7}}`, `{{_self.env}}`, `{{/etc/passwd\|file_get_contents}}` |
| Freemarker (Java) | `${7*7}`, `<#assign`, `freemarker.template.utility.Execute` |
| Velocity (Java) | `#set($x=7*7)$x`, `$class.inspect` |
| Smarty (PHP) | `{php}`, `{$smarty.version}` |
| ERB (Ruby) | `<%= 7*7 %>`, `<%= system('id') %>` |
| Pebble (Java) | `{{7*7}}` |

---

## Log Sources

| Source | Content | Platform |
|---|---|---|
| Web server access logs | Request parameters with template syntax | Any |
| Azure Application Gateway WAF | WAF rule hits | Azure |
| MDE DeviceProcessEvents | App server spawning shells | MDE |
| Application error logs | Template rendering exceptions | Any |

---

## Sigma Rules

### SSTI Template Syntax in HTTP Parameters

```yaml
title: Server-Side Template Injection Patterns in HTTP Parameters
id: d2e3f4a5-b6c7-8901-defa-901234567021
status: experimental
description: >
  Detects server-side template injection test patterns in HTTP request parameters,
  covering Jinja2, Twig, Freemarker, Velocity, ERB, Pebble, and Smarty syntax.
author: claude-blue
date: 2026-04-27
logsource:
  category: webserver
detection:
  selection_delimiters:
    cs-uri-query|contains:
      - '{{'         # Jinja2, Twig, Pebble
      - '}}'
      - '${{'
      - '${7*7}'
      - '#{7*7}'     # Spring EL
      - '<#assign'   # Freemarker
      - '#set('      # Velocity
      - '{%'         # generic
  selection_math_probe:
    cs-uri-query|re: '\{\{[0-9]+\*[0-9]+\}\}'   # {{N*N}}
  selection_python_traversal:
    cs-uri-query|contains:
      - '__class__'
      - '__mro__'
      - '__subclasses__'
      - '__builtins__'
      - 'lipsum'           # Jinja2 globals
      - 'cycler'
      - 'joiner'
  selection_java_exec:
    cs-uri-query|contains:
      - 'freemarker.template.utility.Execute'
      - 'freemarker.template.utility.ObjectConstructor'
      - 'org.springframework.expression'
      - 'Runtime.exec'
  condition: 1 of selection_*
falsepositives:
  - Applications that accept code or template content as input (document)
level: high
tags:
  - attack.t1190
  - attack.t1059
```

### SSTI WAF Bypass (Encoding)

```yaml
title: SSTI WAF Bypass via Encoding in HTTP Parameters
id: e3f4a5b6-c7d8-9012-efab-012345678022
status: experimental
description: >
  Detects encoded SSTI payloads attempting to bypass WAF template syntax filters.
author: claude-blue
date: 2026-04-27
logsource:
  category: webserver
detection:
  selection:
    cs-uri-query|contains:
      - '%7B%7B'       # URL encoded {{
      - '%7D%7D'       # URL encoded }}
      - '%24%7B'       # URL encoded ${
      - '&#123;&#123;' # HTML entity {{
  condition: selection
falsepositives:
  - Rich text editors that encode user content
level: medium
tags:
  - attack.t1190
```

---

## KQL — Azure / Microsoft Sentinel

### Azure WAF SSTI Rule Hits

```kusto
AzureDiagnostics
| where ResourceType == "APPLICATIONGATEWAYS"
| where OperationName == "ApplicationGatewayFirewall"
| where message_s contains "template" or message_s contains "injection"
    or ruleGroup_s contains "ATTACK-GENERAL"
    or requestUri_s contains "{{" or requestUri_s contains "${{"
| project TimeGenerated, clientIP_s, requestUri_s, ruleId_s, message_s, action_s
| order by TimeGenerated desc
```

### MDE: App Server Spawning Shell (Post-SSTI RCE)

```kusto
DeviceProcessEvents
| where InitiatingProcessFileName in~ ("python.exe", "python3", "ruby", "java.exe", "node.exe", "php.exe")
| where InitiatingProcessCommandLine contains "flask" or InitiatingProcessCommandLine contains "django"
    or InitiatingProcessCommandLine contains "jinja" or InitiatingProcessCommandLine contains "template"
| where FileName in~ ("cmd.exe", "powershell.exe", "sh", "bash", "whoami", "id")
| project TimeGenerated, DeviceName, InitiatingProcessFileName,
          InitiatingProcessCommandLine, FileName, ProcessCommandLine
| order by TimeGenerated desc
```

---

## Response Checklist

| Step | Action |
|---|---|
| 1 | Confirm template engine: probe with `{{7*7}}` → `49` (Jinja2/Twig) or `${7*7}` → `49` (Freemarker) |
| 2 | Identify affected endpoint and parameter |
| 3 | Check for process spawn from web app: shell execution confirmation |
| 4 | If RCE confirmed: isolate, collect artifacts, initiate IR |
| 5 | Fix: never pass user input directly to template renderer |
| 6 | Use sandboxed environments or static template analysis |

---

## Hardening Reference

- **Never render user input as template**: pass user data as template variables, not as the template itself
- **Jinja2**: use `jinja2.sandbox.SandboxedEnvironment` for untrusted input rendering
- **Freemarker**: disable `freemarker.template.utility.Execute`; set `Configuration.setNewBuiltinClassResolver(TemplateClassResolver.SAFER_RESOLVER)`
- **Input validation**: reject `{{`, `${`, `<#`, `#set`, `<%=` from user-supplied strings

---

## MITRE ATT&CK

| Technique | ID | Coverage |
|---|---|---|
| Exploit Public-Facing Application | T1190 | SSTI entry point |
| Command and Scripting Interpreter | T1059 | Template expression to OS exec |
| Server Software Component | T1505 | Persistent access via SSTI in template files |
