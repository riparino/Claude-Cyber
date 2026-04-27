---
name: defensive-ssti
description: "SSTI detection checklist: template expression syntax detection in HTTP parameters (Jinja2, Twig, Freemarker, Velocity, ERB), WAF bypass encoding patterns, Python object traversal indicators, KQL for Azure WAF and MDE process events. Use for detection engineering and SOC triage."
---

# SKILL: SSTI Detection

## Metadata
- **Skill Name**: defensive-ssti
- **Folder**: Skills/defensive-ssti
- **Source**: sources/defensive-checklist/ssti.md
- **Mirrors**: offensive-ssti

## Trigger Phrases
Use this skill when the conversation involves any of:
`SSTI detection, server-side template injection alert, Jinja2 injection detection, template injection Sigma, detect SSTI, {{7*7}} detection, Freemarker injection detection, template injection KQL`

## Instructions for Claude

When this skill is active:
1. Load and apply the full detection methodology below
2. Sigma rules cover template delimiters, math probes, Python class traversal, and Java exec patterns
3. KQL targets Azure WAF logs and MDE process events for post-SSTI RCE confirmation
4. Highlight engine-specific hardening (Jinja2 sandbox, Freemarker resolver restrictions)
5. Map to MITRE T1190 and T1059

---

## Full Methodology

# SSTI Detection

## Shortcut

- Check WAF/web logs for `{{`, `${`, `<#`, `#{}` in request parameters.
- Math probe confirmation: `{{7*7}}` returning `49` confirms Jinja2/Twig.
- Alert on Python class traversal: `__class__.__mro__`, `__subclasses__`, `__builtins__` in params.
- Monitor for web process spawning shells following template rendering endpoint requests.
- Focus on user profile, email template, and report generation endpoints — common SSTI surfaces.

---

## Detection Scope

| Engine | Patterns |
|---|---|
| Jinja2 (Python) | `{{7*7}}`, `__class__.__mro__`, `__subclasses__()`, `lipsum` |
| Twig (PHP) | `{{7*7}}`, `{{_self.env}}` |
| Freemarker (Java) | `${7*7}`, `freemarker.template.utility.Execute` |
| Velocity (Java) | `#set($x=7*7)$x` |
| ERB (Ruby) | `<%= 7*7 %>`, `<%= system('id') %>` |

---

## Sigma Rules

### Template Syntax in HTTP Parameters

```yaml
title: Server-Side Template Injection Patterns in HTTP Parameters
id: d2e3f4a5-b6c7-8901-defa-901234567021
status: experimental
description: Detects SSTI patterns across Jinja2, Twig, Freemarker, Velocity, ERB, Pebble.
author: claude-blue
date: 2026-04-27
logsource:
  category: webserver
detection:
  selection_delimiters:
    cs-uri-query|contains:
      - '{{'
      - '}}'
      - '${{'
      - '${7*7}'
      - '#{7*7}'
      - '<#assign'
      - '#set('
  selection_math_probe:
    cs-uri-query|re: '\{\{[0-9]+\*[0-9]+\}\}'
  selection_python_traversal:
    cs-uri-query|contains:
      - '__class__'
      - '__mro__'
      - '__subclasses__'
      - '__builtins__'
      - 'lipsum'
  selection_java_exec:
    cs-uri-query|contains:
      - 'freemarker.template.utility.Execute'
      - 'Runtime.exec'
  condition: 1 of selection_*
falsepositives:
  - Applications accepting code/template content as input (document)
level: high
tags:
  - attack.t1190
  - attack.t1059
```

### SSTI Encoding Bypass

```yaml
title: SSTI WAF Bypass via Encoding
id: e3f4a5b6-c7d8-9012-efab-012345678022
status: experimental
description: Detects URL/HTML encoded SSTI delimiters attempting to bypass WAF filters.
author: claude-blue
date: 2026-04-27
logsource:
  category: webserver
detection:
  selection:
    cs-uri-query|contains:
      - '%7B%7B'       # {{
      - '%7D%7D'       # }}
      - '%24%7B'       # ${
      - '&#123;&#123;'
  condition: selection
falsepositives:
  - Rich text editors
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
    or requestUri_s contains "{{" or requestUri_s contains "${{"
    or requestUri_s contains "__class__"
| project TimeGenerated, clientIP_s, requestUri_s, ruleId_s, message_s, action_s
| order by TimeGenerated desc
```

### MDE: App Server Spawning Shell Post-SSTI

```kusto
DeviceProcessEvents
| where InitiatingProcessFileName in~ ("python.exe", "python3", "ruby", "java.exe", "node.exe", "php.exe")
| where FileName in~ ("cmd.exe", "powershell.exe", "sh", "bash", "whoami.exe", "id")
| project TimeGenerated, DeviceName, InitiatingProcessFileName,
          InitiatingProcessCommandLine, FileName, ProcessCommandLine
| order by TimeGenerated desc
```

---

## Response Checklist

| Step | Action |
|---|---|
| 1 | Confirm template engine via math probe response |
| 2 | Identify affected endpoint and parameter |
| 3 | Check for process spawn — if confirmed: isolate and initiate IR |
| 4 | Fix: never pass user input as template source; use variables only |
| 5 | Jinja2: switch to `SandboxedEnvironment`; Freemarker: restrict class resolver |

---

## Hardening Reference

- **Never render user input as template source** — pass as variable, not as the template itself
- **Jinja2**: use `jinja2.sandbox.SandboxedEnvironment`
- **Freemarker**: set `Configuration.setNewBuiltinClassResolver(TemplateClassResolver.SAFER_RESOLVER)`
- **Input validation**: reject `{{`, `${`, `<#`, `#set`, `<%=` at application boundary

---

## MITRE ATT&CK

| Technique | ID | Coverage |
|---|---|---|
| Exploit Public-Facing Application | T1190 | SSTI entry point |
| Command and Scripting Interpreter | T1059 | Template expression to OS exec |
