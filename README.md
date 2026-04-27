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

### Claude-Blue *(coming soon)*

Defensive security skills — structured `SKILL.md` files for threat detection, incident response, log analysis, hardening, and SOC workflows.

```
Claude-Blue/
└── Skills/
    ├── defensive-threat-hunting/
    ├── defensive-log-analysis/
    └── ...
```

---

## Structure

```
claude-cyber/
├── README.md              ← you are here
├── Claude-Red/            ← offensive skills
└── Claude-Blue/           ← defensive skills (coming soon)
```

---

## Usage

Each skill is a self-contained `SKILL.md` file. Drop it into your Claude environment as a system prompt or skill file before starting a session.

```bash
# Example — load an offensive SQLi skill
cat Claude-Red/Skills/offensive-sqli/SKILL.md
```
