# Race Condition Detection

## Shortcut

- TOCTOU (Time-of-Check to Time-of-Use): detect file path changes between access check and use.
- Detect symlink attacks: unprivileged user creating symlink to privileged file in world-writable directory.
- Monitor for high-frequency file operations on the same path from multiple processes (race condition setup).
- Alert on privileged processes following symlinks to unexpected targets.
- Most race conditions in web apps manifest as double-submit: multiple identical HTTP requests in parallel.

---

## Detection Scope

| Type | What to Detect |
|---|---|
| TOCTOU file race | Symlink placed between `access()` and `open()` calls |
| Symlink attack | Symlink to privileged file in world-writable dir |
| Double-spend race | Multiple identical API calls in parallel (web) |
| Temporary file race | Predictable temp file name created via symlink |
| Lock bypass | File lock not held during multi-step operation |

---

## Sigma Rules

### Symlink Creation in World-Writable Directory

```yaml
title: Symlink Created in World-Writable Directory Pointing to Privileged Path
id: e4f5a6b7-c8d9-0123-efab-456789012062
status: experimental
description: >
  Detects symbolic links created in /tmp or other world-writable directories
  pointing to sensitive system files — TOCTOU exploit setup.
author: claude-blue
date: 2026-04-27
logsource:
  product: linux
  category: file_event
detection:
  selection_symlink:
    EventType: 'symlink'
    TargetFilename|startswith:
      - '/tmp/'
      - '/var/tmp/'
      - '/dev/shm/'
  selection_target:
    SymlinkTarget|startswith:
      - '/etc/passwd'
      - '/etc/shadow'
      - '/etc/sudoers'
      - '/root/'
  condition: selection_symlink and selection_target
falsepositives:
  - Development tooling (document)
level: high
tags:
  - attack.t1574
  - attack.privilege_escalation
```

### High-Frequency Parallel Requests to Same Endpoint (Double-Spend)

```yaml
title: Parallel HTTP Requests to Transaction Endpoint (Race Condition)
id: f5a6b7c8-d9e0-1234-fabc-567890123063
status: experimental
description: >
  Detects multiple identical HTTP requests to a transaction/payment/redeem endpoint
  within a very short window from same client — race condition double-spend attempt.
author: claude-blue
date: 2026-04-27
logsource:
  category: webserver
detection:
  selection:
    cs-uri-stem|contains:
      - '/redeem'
      - '/transfer'
      - '/checkout'
      - '/apply-coupon'
      - '/use-voucher'
  timeframe: 1s
  condition: selection | count() by c-ip > 3
falsepositives:
  - Retry logic in clients (add exponential backoff check)
level: high
tags:
  - attack.t1499
  - attack.impact
```

---

## KQL — Web Race Conditions

### Application Gateway: Parallel Requests to Transaction Endpoint

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
| 2 | Symlink attack: identify what file was accessed via symlink; assess privilege gained |
| 3 | Fix web race: add database-level locks or atomic operations (compare-and-swap) |
| 4 | Fix TOCTOU: use file descriptors instead of paths after initial open |
| 5 | Rate limit: restrict parallel requests to transaction endpoints per session |

---

## Hardening Reference

- **Database transactions with SELECT FOR UPDATE**: prevent concurrent modification
- **Idempotency keys**: deduplicate identical requests server-side
- **Atomic file operations**: `open(O_CREAT|O_EXCL)` — fail if file exists
- **Avoid world-writable directories** for privileged operations
- **Use file descriptors, not paths** for TOCTOU-sensitive code

---

## MITRE ATT&CK

| Technique | ID | Coverage |
|---|---|---|
| Hijack Execution Flow | T1574 | Symlink/TOCTOU race |
| Endpoint Denial / Abuse | T1499 | Resource exhaustion via race |
