![claude-red banner](/assets/banner.png)

# claude-red

> 38 offensive security skills for Claude — drop-in SKILL.md files that turn Claude into a context-aware red team operator.

Built by **[SnailSploit](https://snailsploit.com)** — GenAI Security Research.

---

## What is this?

`claude-red` is a curated library of offensive security skills designed for the [Claude skills system](https://docs.claude.com). Each skill is a structured `SKILL.md` file that primes Claude with expert-level methodology for a specific attack surface — from SQLi to shellcode, EDR evasion to exploit development.

Drop any skill into your Claude environment and it behaves like a specialist: it knows the techniques, the tooling, the edge cases, and the escalation paths.

---

## Structure

```
claude-red/
└── skills-output/
    ├── offensive-sqli/
    │   └── SKILL.md
    ├── offensive-xss/
    │   └── SKILL.md
    └── ... (38 total)
```

Each directory is a self-contained skill. Point Claude at the relevant `SKILL.md` before your engagement begins.

---

## Skill Index

### Web Application

| Skill | Description |
|---|---|
| `offensive-sqli` | SQL Injection — union-based, blind, OOB, bypass chains |
| `offensive-xss` | Cross-Site Scripting — stored, reflected, DOM, mutation |
| `offensive-ssrf` | Server-Side Request Forgery — cloud metadata, filter bypass |
| `offensive-ssti` | Server-Side Template Injection — engine identification, RCE paths |
| `offensive-xxe` | XML External Entity Injection — OOB exfil, blind exploitation |
| `offensive-idor` | Insecure Direct Object References — enumeration, business logic |
| `offensive-file-upload` | File Upload Vulnerabilities — extension bypass, polyglots, webshells |
| `offensive-rce` | Remote Code Execution — chaining, command injection, deserialization |
| `offensive-deserialization` | Insecure Deserialization — Java, PHP, .NET gadget chains |
| `offensive-race-condition` | Race Conditions — TOCTOU, limit bypass, concurrent request attacks |
| `offensive-request-smuggling` | HTTP Request Smuggling — CL.TE, TE.CL, pipeline desync |
| `offensive-open-redirect` | Open Redirect — OAuth abuse, phishing chains, SSRF pivots |
| `offensive-parameter-pollution` | HTTP Parameter Pollution — WAF bypass, logic confusion |
| `offensive-graphql` | GraphQL Vulnerabilities — introspection, batching, IDOR via aliases |
| `offensive-waf-bypass` | WAF Bypass Techniques — encoding, chunking, case mutation |

### Auth & Identity

| Skill | Description |
|---|---|
| `offensive-jwt` | JWT Security — alg:none, key confusion, secret cracking |
| `offensive-oauth` | OAuth Security Testing — open redirect abuse, token leakage, PKCE bypass |

### Infrastructure & Binary

| Skill | Description |
|---|---|
| `offensive-shellcode` | Shellcode — writing, encoding, injection techniques |
| `offensive-edr-evasion` | EDR Evasion — unhooking, indirect syscalls, PPID spoofing |
| `offensive-exploit-development` | Exploit Development — stack/heap, ROP chains, mitigations |
| `offensive-exploit-dev-course` | Exploit Development (Course) — structured curriculum format |
| `offensive-basic-exploitation` | Basic Exploitation — Linux, mitigations disabled, beginner-to-mid |
| `offensive-crash-analysis` | Crash Analysis & Exploitability Assessment — triage, root cause |
| `offensive-mitigations` | Modern Kernel Exploit Mitigations — ASLR, CFG, CET, PAC |
| `offensive-windows-mitigations` | Windows Mitigations — ACG, Arbitrary Code Guard, exploit guard |
| `offensive-windows-boundaries` | Defeating Windows Security Boundaries — sandbox escape, privilege |
| `offensive-keylogger-arch` | Keylogger Architecture — novel research, input capture techniques |
| `offensive-patch-diffing` | Patch Diffing — binary diff, silent CVE discovery, variant hunting |
| `offensive-initial-access` | Modern Initial Access — phishing, drive-by, supply chain |
| `offensive-advanced-redteam` | Advanced Red Team Ops — full kill chain, C2, OpSec |

### Reconnaissance & OSINT

| Skill | Description |
|---|---|
| `offensive-osint` | OSINT Tools — recon-ng, theHarvester, Maltego, automated pipelines |
| `offensive-osint-methodology` | OSINT Methodology — structured intelligence collection framework |

### Fuzzing & Vulnerability Research

| Skill | Description |
|---|---|
| `offensive-fuzzing` | Fuzzing — libFuzzer, AFL++, coverage-guided, mutation strategies |
| `offensive-fuzzing-course` | Fuzzing (Course) — structured curriculum, finding vulns via fuzzing |
| `offensive-bug-identification` | Bug Identification — code review patterns, static analysis triggers |
| `offensive-vuln-classes` | Vulnerability Classes — real-world examples, root cause taxonomy |

### AI Security

| Skill | Description |
|---|---|
| `offensive-ai-security` | AI Pentest — prompt injection, jailbreaking, RAG poisoning, LLM abuse |

### Utility

| Skill | Description |
|---|---|
| `offensive-fast-checking` | Fast Testing Checklist — rapid triage, quick win identification |

---

## Usage

### With Claude Code
```bash
# Point Claude at a skill before starting your session
cat skills-output/offensive-sqli/SKILL.md | claude --system-file -
```

### With the Claude Skills System
Place any skill folder under your configured skills path (e.g., `/mnt/skills/user/`) and Claude will auto-load it based on trigger keywords.

### Manual (Claude.ai)
Paste the contents of any `SKILL.md` into a Project's system prompt or prepend it to your conversation.

---

## About

These skills were developed through real-world red team engagements, bug bounty hunting, and security research. They encode the decision trees, tool selection logic, and escalation patterns that an experienced operator uses — not just a list of commands.

**Author:** Kai Aizen (SnailSploit) — [snailsploit.com](https://snailsploit.com)  
**Original Checklists:** [Sahar Shlichov](https://github.com/sahar042/offensive-checklist) — the offensive checklist collection this skill library is based on.  
**License:** MIT — use freely, attribution appreciated.

---

> *"Give Claude the right skill and it stops being a chatbot. It becomes an operator."*
