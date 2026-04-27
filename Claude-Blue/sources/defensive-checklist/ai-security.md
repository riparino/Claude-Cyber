# AI Security — Defensive

## Overview
Detection and defense for AI/LLM-specific attacks: prompt injection, jailbreaks, model inversion, training data extraction, adversarial inputs. KQL for Azure OpenAI logs. Sigma for anomalous LLM API usage patterns.

## Shortcut

- Prompt injection: user input that overrides system prompt; detect system prompt keywords in user turn.
- Jailbreak: instructions to "ignore previous instructions" or role-play as unrestricted model.
- Training data extraction: repetitive, verbatim output generation attempts.
- Azure OpenAI: content filtering enabled by default; audit `AzureDiagnostics` for filtered requests.
- Data exfiltration via LLM: indirect prompt injection via retrieved external content.

---

## AI Attack Vectors

| Attack | Description | Detection Signal |
|---|---|---|
| Prompt injection | User input overrides system prompt | System prompt keywords in user turn |
| Jailbreak | Role-play, DAN, unrestricted persona | "ignore previous instructions", "DAN" |
| Training data extraction | Repeat prompts to extract memorized data | High-rate identical prefix queries |
| Indirect prompt injection | External content (web/doc) injects instructions | Fetched content contains instruction-like text |
| Model inversion | Probe model to reconstruct training data | Statistical repeated probing |
| Adversarial input | Perturbed input to misclassify | Unusual character sequences in input |

---

## Azure OpenAI Content Filter Reference

| Category | Severity Levels | Default Action |
|---|---|---|
| Hate | Low/Medium/High | Block at Medium+ |
| Sexual | Low/Medium/High | Block at High |
| Violence | Low/Medium/High | Block at Medium+ |
| Self-harm | Low/Medium/High | Block at Medium+ |
| Prompt injection | Binary | Block |

---

## Sigma Rules

```yaml
title: Prompt Injection - Instruction Override Pattern
id: a7b8c901-2345-ab01-2345-8901234567cd
status: experimental
description: Detects common prompt injection patterns in user input
logsource:
  category: application
  product: llm_api
detection:
  selection:
    user_message|contains:
      - "ignore previous instructions"
      - "forget your instructions"
      - "you are now DAN"
      - "act as an unrestricted"
      - "disregard the above"
      - "system: "
  condition: selection
falsepositives:
  - Security research and red team testing
level: high
tags:
  - attack.t1059
```

```yaml
title: LLM API High-Rate Probing
id: b8c9d012-3456-bc12-3456-9012345678de
status: experimental
description: Detects high-rate API calls to LLM endpoint (model extraction or fuzzing)
logsource:
  category: application
  product: llm_api
detection:
  selection:
    endpoint|contains: "/chat/completions"
  timeframe: 1m
  condition: selection | count() by user_id > 60
falsepositives:
  - Legitimate batch processing applications
level: medium
tags:
  - attack.t1530
```

---

## KQL — Azure OpenAI / Defender for Cloud Apps

### Azure OpenAI Content Filtered Requests

```kusto
AzureDiagnostics
| where ResourceType == "OPENAI"
| where OperationName == "ChatCompletions_Create"
| where todynamic(properties_s).finish_reason == "content_filter"
| project TimeGenerated, OperationName,
          Reason=todynamic(properties_s).content_filter_results,
          CallerIP=callerIpAddress
| order by TimeGenerated desc
```

### High-Rate LLM API Calls (Extraction Probing)

```kusto
AzureDiagnostics
| where ResourceType == "OPENAI"
| where OperationName == "ChatCompletions_Create"
| summarize RequestCount=count() by callerIpAddress, bin(TimeGenerated, 1m)
| where RequestCount > 60
| order by RequestCount desc
```

---

## Hardening Checklist

| Control | Implementation |
|---|---|
| Content filtering | Enable all categories at Medium+ |
| System prompt hardening | Do not include secrets; assume prompt is revealed |
| Output validation | Validate LLM output before using in code/queries |
| Rate limiting | Per-user/API-key rate limit on LLM endpoint |
| Indirect injection | Sanitize fetched external content before including in prompt |
| Monitoring | Alert on content filter blocks; review weekly |

---

## MITRE ATT&CK (ATLAS)

| Technique | ID | Notes |
|---|---|---|
| LLM Prompt Injection | AML.T0051 | User-controlled prompt override |
| Jailbreak | AML.T0054 | Model restriction bypass |
| Training Data Extraction | AML.T0024 | Verbatim memorization |
