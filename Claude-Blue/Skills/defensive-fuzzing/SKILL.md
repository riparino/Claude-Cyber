---
name: defensive-fuzzing
description: "Defensive fuzzing of own assets: AFL++, libFuzzer, OSS-Fuzz, jazzer for JVM, ffuf for web endpoints. Crash triage with AddressSanitizer. CI/CD integration for continuous fuzzing. Use to find vulnerabilities before attackers do. Merges offensive-fuzzing and offensive-fuzzing-course from the defensive perspective."
---

# SKILL: Defensive Fuzzing

## Metadata
- **Skill Name**: defensive-fuzzing
- **Folder**: Skills/defensive-fuzzing
- **Source**: sources/defensive-checklist/fuzzing.md
- **Mirrors**: offensive-fuzzing / offensive-fuzzing-course

## Trigger Phrases
Use this skill when the conversation involves any of:
`defensive fuzzing, AFL++, libFuzzer, OSS-Fuzz, jazzer, fuzzing CI/CD, fuzzing harness, crash triage AddressSanitizer, coverage fuzzing, fuzzing setup, ffuf, web fuzzing`

## Instructions for Claude

When this skill is active:
1. Provide AFL++ or libFuzzer command line immediately when asked
2. libFuzzer: always compile with `-fsanitize=fuzzer,address,undefined` for maximum coverage
3. Crash found: minimize with `afl-tmin`; triage exploitability with ASAN output
4. CI/CD: add `timeout 600 afl-fuzz ...` step; fail build on crash file
5. Web fuzzing: ffuf for directory/parameter discovery; Burp Enterprise for continuous

---

## Full Methodology

# Defensive Fuzzing

## Shortcut

- AFL++: `afl-clang-fast -o target target.c && afl-fuzz -i corpus -o findings -- ./target @@`
- libFuzzer: `clang -fsanitize=fuzzer,address,undefined -o fuzz harness.c target.c`
- Crash: `findings/crashes/` → minimize → ASAN stacktrace → classify exploitability
- heap-use-after-free > stack-overflow > OOB-read for exploitability

---

## Tools Reference

| Tool | Target | Command |
|---|---|---|
| AFL++ | Native C/C++ | `afl-fuzz -i corpus -o out -- ./target @@` |
| libFuzzer | LLVM C/C++ | `-fsanitize=fuzzer,address,undefined` |
| jazzer | Java/JVM | Bazel integration; libFuzzer backend |
| ffuf | Web | `ffuf -w wordlist.txt -u https://target/FUZZ` |
| Radamsa | Any (mutation) | `echo input \| radamsa \| ./target` |

---

## libFuzzer Harness Template

```c
#include <stdint.h>
#include <stddef.h>

extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    parse_input(Data, Size);  // Call target with fuzz input
    return 0;
}
```

Compile: `clang -fsanitize=fuzzer,address,undefined -o fuzz harness.c target.c`

---

## CI/CD Integration

```yaml
- name: Fuzz target for 10 minutes
  run: |
    timeout 600 afl-fuzz -i corpus -o findings -- ./target @@ || true
    [ -d findings/crashes ] && exit 1 || exit 0
```

---

## MITRE ATT&CK

| Technique | ID | Notes |
|---|---|---|
| Exploitation of Remote Services | T1210 | Pre-emptive fuzzing finds vulnerabilities |
| Exploit for Client Execution | T1203 | Native binary fuzzing |
