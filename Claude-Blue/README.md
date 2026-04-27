# claude-blue

> 43 defensive security skills for Claude — structured SKILL.md files for threat detection, incident response, log analysis, hardening, and SOC workflows.

Built by **[riparino](https://github.com/riparino)** — companion to [claude-red](../Claude-Red/).

---

## What is this?

`claude-blue` is a curated library of defensive security skills designed for the [Claude skills system](https://docs.claude.com). Each skill is a structured `SKILL.md` file that primes Claude with expert-level detection methodology for a specific threat surface — from XSS detection to shellcode hunting, EDR telemetry to cloud hardening.

Drop any skill into your Claude environment and it behaves like a specialist: it knows the detection logic, the relevant log sources, the MITRE ATT&CK coverage, and the response steps.

---

## Detection Rule Formats

Each skill uses the most appropriate format for the detection:

| Format | Used For |
|---|---|
| **Sigma** | Generic SIEM detection — portable, convertible to KQL via `sigma-cli --target microsoft365defender` or `--target sentinel` |
| **KQL / Kusto** | Azure-native tables with no clean Sigma equivalent: `SigninLogs`, `DeviceProcessEvents`, `EmailEvents`, `AzureActivity`, `OfficeActivity`, `CloudAppEvents` |
| **YARA** | File and memory artifact detection — shellcode signatures, webshells, exploit tool patterns, malware families |

---

## Structure

```
claude-blue/
├── Skills/
│   ├── defensive-xss/
│   │   └── SKILL.md
│   ├── defensive-sqli/
│   │   └── SKILL.md
│   └── ... (43 total)
└── sources/
    └── defensive-checklist/
        ├── xss.md
        ├── sqli.md
        └── ... (43 raw source files)
```

Each `Skills/` directory is a self-contained skill. Point Claude at the relevant `SKILL.md` before your session begins.

---

## Skill Index

### Web Application Detection

| Skill | Description |
|---|---|
| `defensive-xss` | XSS Detection — WAF log analysis, CSP monitoring, blind XSS callbacks, DOM sink hunting |
| `defensive-sqli` | SQL Injection Detection — WAF alerts, error pattern analysis, automated tool fingerprinting |
| `defensive-ssrf` | SSRF Detection — internal metadata requests, cloud IMDS access attempts, outbound anomalies |
| `defensive-ssti` | SSTI Detection — template injection patterns in request params and WAF logs |
| `defensive-xxe` | XXE Detection — DOCTYPE/ENTITY in XML, OOB callback monitoring, WAF signatures |
| `defensive-file-upload` | File Upload Abuse Detection — MIME mismatch, double extensions, webshell YARA |
| `defensive-deserialization` | Deserialization Attack Detection — magic byte patterns, gadget chain indicators, YARA |
| `defensive-rce` | RCE Detection — web process spawning shells, command injection chains, webshell activity |

### Auth & Identity Detection

| Skill | Description |
|---|---|
| `defensive-jwt` | JWT Attack Detection — alg:none attempts, key confusion anomalies, Entra ID token abuse |
| `defensive-oauth` | OAuth Attack Detection — consent phishing, token theft, redirect abuse, AiTM indicators |
| `defensive-idor` | IDOR Detection — access pattern anomalies, horizontal privilege escalation, audit log review |
| `defensive-open-redirect` | Open Redirect Detection — parameter-based redirects, phishing chain indicators |
| `defensive-parameter-pollution` | HTTP Parameter Pollution Detection — duplicate param anomalies, WAF bypass indicators |

### Infrastructure & Endpoint Detection

| Skill | Description |
|---|---|
| `defensive-initial-access` | Initial Access Detection — phishing, credential stuffing, supply chain, AiTM; email + endpoint |
| `defensive-edr-evasion` | EDR Evasion Detection — unhooking telemetry, syscall anomalies, PPID spoofing, AMSI bypass |
| `defensive-shellcode` | Shellcode Detection — YARA (primary), memory injection indicators, process hollowing |
| `defensive-windows-mitigations` | Windows Mitigation Verification — ACG/CET/CFG status, exploit guard policy, Intune compliance |
| `defensive-windows-hardening` | Windows Security Boundary Hardening — sandbox config, privilege control, AppLocker, WDAC |
| `defensive-exploit-detection` | Exploit Attempt Detection — crash telemetry, WER analysis, memory corruption indicators |
| `defensive-basic-exploitation` | Basic Exploitation Detection — buffer overflow indicators, shellcode memory patterns |
| `defensive-mitigations` | Mitigation Coverage Verification — ASLR/DEP/CFG/CET audit, gap identification |
| `defensive-keylogger-detection` | Keylogger Detection — YARA (primary), API hook patterns, raw input access, process anomalies |
| `defensive-race-condition` | Race Condition Hardening — TOCTOU prevention, atomic operation patterns, concurrency controls |

### Web Technique Detection

| Skill | Description |
|---|---|
| `defensive-graphql` | GraphQL Attack Detection — introspection abuse, batching attacks, query depth anomalies |
| `defensive-request-smuggling` | HTTP Request Smuggling Detection — desync indicators, WAF/proxy inconsistency alerts |
| `defensive-waf-hardening` | WAF Hardening & Tuning — rule lifecycle, bypass gap coverage, alert quality improvement |
| `defensive-vuln-classes` | Vulnerability Class Detection Reference — detection pattern catalog per vulnerability class |
| `defensive-vulnerability-management` | Vulnerability Management — scanning, triage, CVSS prioritization, patch verification |
| `defensive-crash-analysis` | Crash Triage for Defenders — exploitability assessment, WER event correlation |

### Recon & Exposure Management

| Skill | Description |
|---|---|
| `defensive-opsec` | Organizational OpSec — digital footprint reduction, exposure minimization checklist |
| `defensive-exposure-management` | Attack Surface Management — ASM workflow, scan detection, external exposure inventory |
| `defensive-threat-hunting` | Threat Hunting — hypothesis-driven hunt playbooks, KQL hunt queries, TTP-based pivots |

### Course / Methodology

| Skill | Description |
|---|---|
| `defensive-fast-triage` | Rapid SOC Triage — alert prioritization, quick win checklist, shift-start workflow |
| `defensive-secure-dev-course` | Secure Development Course — SAST/DAST integration, secure code review, threat modeling |
| `defensive-fuzzing` | Defensive Fuzzing — fuzzing your own assets, CI/CD integration, crash triage |
| `defensive-ai-security` | AI/LLM Security Detection — prompt injection monitoring, LLM output abuse, model security |

### Standalone Blue Team Skills

| Skill | Description |
|---|---|
| `defensive-incident-response` | Incident Response — triage → containment → eradication → recovery playbooks, KQL queries |
| `defensive-threat-intelligence` | Threat Intelligence — IOC enrichment, STIX/TAXII, TI indicator KQL, feed management |
| `defensive-detection-engineering` | Detection Engineering — Sigma rule lifecycle, MITRE coverage mapping, FP tuning, alert fatigue |
| `defensive-cloud-hardening` | Cloud Hardening — Azure/Entra ID/Intune/Defender for Endpoint; Conditional Access; KQL-heavy |
| `defensive-soc-workflows` | SOC Workflows — alert triage SOP, escalation paths, case management, shift handoff |
| `defensive-log-analysis` | Log Analysis — log source onboarding, normalization, Sentinel table reference, KQL patterns |

---

## Usage

### Claude Code (CLI)
```bash
claude --system-file Skills/defensive-xss/SKILL.md
```

### Claude Skills System
Place the `Skills/` directory in your configured Claude skills path. Skills auto-activate on trigger phrases.

### Claude.ai Projects
Paste the contents of any `SKILL.md` into your Project's system prompt.

### Sigma → KQL Conversion
```bash
# Install sigma-cli
pip install sigma-cli
sigma plugin install microsoft365defender
sigma plugin install sentinel

# Convert a Sigma rule to KQL
sigma convert -t sentinel rules/detect_xss.yml
sigma convert -t microsoft365defender rules/detect_sqli.yml
```

---

## MITRE ATT&CK Coverage

Skills map to MITRE ATT&CK techniques throughout. Key tactic coverage:

| Tactic | Examples Covered |
|---|---|
| Initial Access (TA0001) | `defensive-initial-access`, `defensive-oauth` |
| Execution (TA0002) | `defensive-rce`, `defensive-shellcode`, `defensive-deserialization` |
| Defense Evasion (TA0005) | `defensive-edr-evasion`, `defensive-shellcode` |
| Credential Access (TA0006) | `defensive-jwt`, `defensive-oauth` |
| Discovery (TA0007) | `defensive-exposure-management` |
| Collection (TA0009) | `defensive-keylogger-detection` |
| Exfiltration (TA0010) | `defensive-ssrf`, `defensive-xxe` |
| Impact (TA0040) | `defensive-rce`, `defensive-sqli` |

---

## Credits

- Offensive counterpart: [claude-red](../Claude-Red/) by [SnailSploit](https://snailsploit.com)
- Detection content informed by: [Sigma Rules](https://github.com/SigmaHQ/sigma), [MITRE ATT&CK](https://attack.mitre.org), Microsoft Sentinel analytics community

## License

MIT
