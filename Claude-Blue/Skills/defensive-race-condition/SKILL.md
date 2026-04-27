---
name: defensive-race-condition
description: "Race condition detection: TOCTOU symlink attacks, double-spend web race conditions, parallel transaction requests. Sigma for symlink creation in world-writable directories and high-frequency parallel HTTP requests. KQL for Azure Application Gateway parallel transaction detection. Use for SOC triage and secure development guidance."
---

# SKILL: Race Condition Detection

## Metadata
- **Skill Name**: defensive-race-condition
- **Folder**: Skills/defensive-race-condition
- **Source**: sources/defensive-checklist/race-condition.md
- **Mirrors**: offensive-race-condition

## Trigger Phrases
Use this skill when the conversation involves any of:
`race condition detection, TOCTOU detection, double-spend detection, symlink attack detection, parallel request detection, time-of-check time-of-use, web race condition, concurrent request anomaly`

## Instructions for Claude

When this skill is active:
1. Double-spend web race: identify if race succeeded; roll back fraudulent transactions
2. Symlink attack: identify what privileged file was accessed; assess privilege gained
3. KQL for Azure Application Gateway: parallel requests to transaction endpoints within 1s
4. Fix: database-level locks (SELECT FOR UPDATE) or atomic compare-and-swap
5. Web fix: idempotency keys to deduplicate identical requests

---

## Full Methodology

# Race Condition Detection

## Shortcut

- >3 identical POST requests to `/redeem`, `/transfer`, `/checkout` from same IP in 1s = double-spend attempt.
- Symlink in `/tmp` pointing to `/etc/shadow` = TOCTOU setup; alert immediately.
- Predictable temp file name = race condition setup; alert on process creating symlinks before privileged operation.

---

## Detection Signals

| Type | Indicator | Severity |
|---|---|---|
| Web double-spend | >3 identical requests to transaction endpoint in 1s | High |
| Symlink to privileged file | Symlink in `/tmp` → `/etc/passwd`, `/etc/shadow` | High |
| Temp file race | Predictable filename creation before privileged operation | Medium |

---

## KQL — Azure Application Gateway

### Parallel Transaction Requests (Double-Spend)

```kusto
AzureDiagnostics
| where ResourceType == "APPLICATIONGATEWAYS"
| where OperationName == "ApplicationGatewayAccess"
| where requestUri_s contains "/redeem" or requestUri_s contains "/transfer"
    or requestUri_s contains "/checkout" or requestUri_s contains "/apply-coupon"
| summarize RequestCount=count() by clientIP_s, requestUri_s, bin(TimeGenerated, 1s)
| where RequestCount > 3
| order by RequestCount desc
```

---

## Response Checklist

| Step | Action |
|---|---|
| 1 | Web double-spend: identify if race succeeded; roll back fraudulent transactions |
| 2 | Symlink attack: identify what was accessed; assess privilege gained |
| 3 | Web fix: idempotency keys; database SELECT FOR UPDATE on transaction |
| 4 | File fix: `open(O_CREAT|O_EXCL)` — fail if file exists |
| 5 | Rate limit: restrict parallel requests per session to transaction endpoints |

---

## Hardening

- **SELECT FOR UPDATE / atomic transactions**: prevent concurrent modification
- **Idempotency keys**: server-side deduplication of requests
- **`O_CREAT|O_EXCL`**: atomic file creation — fail if exists
- **Avoid world-writable directories** for privileged file operations

---

## MITRE ATT&CK

| Technique | ID | Coverage |
|---|---|---|
| Hijack Execution Flow | T1574 | Symlink/TOCTOU race |
| Endpoint Abuse | T1499 | Resource exhaustion via race |
