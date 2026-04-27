---
name: defensive-ai-security
description: "AI/LLM security detection and defense: prompt injection, jailbreak patterns, training data extraction, indirect prompt injection, adversarial inputs. Sigma for LLM prompt injection patterns. KQL for Azure OpenAI content filter blocks and high-rate probing. Use for AI application security monitoring."
---

# SKILL: AI Security

## Metadata
- **Skill Name**: defensive-ai-security
- **Folder**: Skills/defensive-ai-security
- **Source**: sources/defensive-checklist/ai-security.md
- **Mirrors**: offensive-ai-security

## Trigger Phrases
Use this skill when the conversation involves any of:
`prompt injection detection, LLM jailbreak detection, AI security monitoring, Azure OpenAI content filter, training data extraction, indirect prompt injection, LLM anomaly detection, AI attack detection`

## Instructions for Claude

When this skill is active:
1. Azure OpenAI content filter blocked = review what triggered it; potential prompt injection
2. High-rate LLM API calls = possible model extraction or automated jailbreak probing
3. System prompt: never include secrets; assume it will be revealed via extraction
4. Indirect injection via fetched external content = sanitize all external content before including in prompt
5. ATLAS techniques: use MITRE ATLAS alongside ATT&CK for AI-specific attack mapping

---

## Full Methodology

# AI Security Detection

## Shortcut

- `"ignore previous instructions"` = prompt injection; block and alert.
- >60 API requests/minute from same key = extraction probing; rate limit.
- Content filter `finish_reason == "content_filter"` = filter triggered; investigate.
- Indirect injection: attacker embeds instructions in external content (web page, doc) that gets included in prompt.

---

## Attack Vectors

| Attack | Signal | Severity |
|---|---|---|
| Prompt injection | Override keywords in user turn | High |
| Jailbreak | "DAN", "unrestricted", role-play | High |
| Training data extraction | High-rate identical prefix queries | Medium |
| Indirect prompt injection | Instruction-like text in fetched content | High |
| Rate abuse | >60 req/min per API key | Medium |

---

## KQL — Azure OpenAI

### Content Filter Blocks

```kusto
AzureDiagnostics
| where ResourceType == "OPENAI"
| where OperationName == "ChatCompletions_Create"
| where todynamic(properties_s).finish_reason == "content_filter"
| project TimeGenerated, Reason=todynamic(properties_s).content_filter_results,
          CallerIP=callerIpAddress
| order by TimeGenerated desc
```

### High-Rate API Probing

```kusto
AzureDiagnostics
| where ResourceType == "OPENAI"
| where OperationName == "ChatCompletions_Create"
| summarize RequestCount=count() by callerIpAddress, bin(TimeGenerated, 1m)
| where RequestCount > 60
| order by RequestCount desc
```

---

## Response Checklist

| Step | Action |
|---|---|
| 1 | Prompt injection confirmed: log, block IP, review what data was accessed |
| 2 | High-rate probing: rate limit API key; investigate extraction attempt |
| 3 | Indirect injection: add sanitization layer for all fetched external content |
| 4 | System prompt exposed: rotate secrets mentioned in prompt; harden prompt |
| 5 | Review Azure content filter configuration; enable all categories |

---

## MITRE ATLAS

| Technique | ID | Notes |
|---|---|---|
| LLM Prompt Injection | AML.T0051 | Override system prompt |
| Jailbreak | AML.T0054 | Remove safety restrictions |
| Training Data Extraction | AML.T0024 | Verbatim memorization |
