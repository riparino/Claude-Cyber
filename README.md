# claude-cyber

> A dual-purpose AI security skill library for Claude — offensive red team capabilities and defensive blue team guidance in a single repository.

Built by **riparino**.

---

## Components

### [Claude-Red](./Claude-Red/)

Offensive security skills — 38 structured `SKILL.md` files that prime Claude with expert-level red team methodology. Covers web application attacks, binary exploitation, EDR evasion, OSINT, fuzzing, and more.

```
Claude-Red/
├── Skills/
│   ├── offensive-sqli/
│   ├── offensive-xss/
│   └── ... (38 total)
└── sources/
    └── offensive-checklist/   ← local copies of upstream checklists
```

→ See [Claude-Red/README.md](./Claude-Red/README.md) for the full skill index.

---

### [Claude-Blue](./Claude-Blue/)

Defensive security skills — 42 structured `SKILL.md` files covering threat detection, incident response, log analysis, cloud hardening, and SOC workflows. Detection rules in Sigma (generic SIEM), KQL (Azure Sentinel/MDE), and YARA.

```
Claude-Blue/
├── Skills/
│   ├── defensive-xss/
│   ├── defensive-sqli/
│   ├── defensive-rce/
│   ├── defensive-ssrf/
│   ├── defensive-file-upload/
│   ├── defensive-deserialization/
│   ├── defensive-ssti/
│   ├── defensive-xxe/
│   ├── defensive-jwt/
│   ├── defensive-oauth/
│   ├── defensive-idor/
│   ├── defensive-open-redirect/
│   ├── defensive-parameter-pollution/
│   ├── defensive-initial-access/
│   ├── defensive-edr-evasion/
│   ├── defensive-shellcode/
│   ├── defensive-windows-mitigations/
│   ├── defensive-windows-hardening/
│   ├── defensive-exploit-detection/
│   ├── defensive-basic-exploitation/
│   ├── defensive-mitigations/
│   ├── defensive-keylogger-detection/
│   ├── defensive-race-condition/
│   ├── defensive-graphql/
│   ├── defensive-request-smuggling/
│   ├── defensive-waf-hardening/
│   ├── defensive-vuln-classes/
│   ├── defensive-vulnerability-management/
│   ├── defensive-crash-analysis/
│   ├── defensive-opsec/
│   ├── defensive-exposure-management/
│   ├── defensive-threat-hunting/
│   ├── defensive-fast-triage/
│   ├── defensive-secure-dev-course/
│   ├── defensive-fuzzing/
│   ├── defensive-ai-security/
│   ├── defensive-incident-response/
│   ├── defensive-threat-intelligence/
│   ├── defensive-detection-engineering/
│   ├── defensive-cloud-hardening/
│   ├── defensive-soc-workflows/
│   └── defensive-log-analysis/
└── sources/
    └── defensive-checklist/   ← raw detection methodology sources
```

→ See [Claude-Blue/README.md](./Claude-Blue/README.md) for the full skill index.

---

## Structure

```
claude-cyber/
├── README.md              ← you are here
├── Claude-Red/            ← offensive skills (38 skills)
└── Claude-Blue/           ← defensive skills (42 skills)
```

---

## Usage

Each skill is a self-contained `SKILL.md` file. Drop it into your Claude environment as a system prompt or skill file before starting a session.

```bash
# Example — load an offensive SQLi skill
cat Claude-Red/Skills/offensive-sqli/SKILL.md
```
