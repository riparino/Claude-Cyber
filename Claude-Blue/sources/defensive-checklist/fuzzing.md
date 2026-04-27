# Defensive Fuzzing — Own Asset Testing

## Overview
Fuzzing your own applications to find vulnerabilities before attackers do. AFL++, libFuzzer, OSS-Fuzz integration. CI/CD crash triage. Coverage-guided fuzzing for native code; web fuzzing with ffuf/Burp Intruder.

## Shortcut

- AFL++: fastest for native C/C++ binaries; persistent mode for speed.
- libFuzzer: integrated with ASAN/UBSAN for sanitizer-guided fuzzing.
- OSS-Fuzz: continuous fuzzing for open-source dependencies.
- Web fuzzing: ffuf for directory/parameter discovery; Burp Intruder for targeted fuzzing.
- Crash triage: `!exploitable` WinDbg plugin; AddressSanitizer stacktrace.

---

## Fuzzing Tools Reference

| Tool | Target | Setup |
|---|---|---|
| AFL++ | Native C/C++ | `afl-cc -o target target.c; afl-fuzz -i corpus -o findings -- ./target @@` |
| libFuzzer | C/C++ with LLVM | Compile with `-fsanitize=fuzzer,address,undefined` |
| OSS-Fuzz | Open source projects | Submit to oss-fuzz.com; Google runs continuously |
| jazzer | Java / JVM | JVM fuzzing via libFuzzer; Bazel integration |
| ffuf | Web endpoints | `ffuf -w wordlist.txt -u https://target/FUZZ` |
| Radamsa | Mutation-based | `echo "input" | radamsa` — quick mutation without instrumentation |

---

## AFL++ Quick Start

```bash
# Compile with AFL instrumentation
afl-clang-fast -o target target.c

# Create initial corpus
mkdir corpus && echo "valid_input" > corpus/seed

# Run fuzzer
afl-fuzz -i corpus -o findings -- ./target @@

# Parallel fuzzing
afl-fuzz -M master -i corpus -o findings -- ./target @@
afl-fuzz -S worker01 -i corpus -o findings -- ./target @@
```

## libFuzzer Harness Template

```c
#include <stdint.h>
#include <stddef.h>

extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    // Call target function with fuzz input
    parse_input(Data, Size);
    return 0;
}
```

Compile: `clang -fsanitize=fuzzer,address,undefined -o fuzz_target harness.c target.c`

---

## Crash Triage Workflow

1. AFL++ finds crash: `findings/crashes/id:000000,sig:11,...`
2. Minimize: `afl-tmin -i crash -o minimal -- ./target @@`
3. Reproduce: run with minimal input; capture output
4. Classify: AddressSanitizer/UBSAN output shows heap/stack/UB type
5. Exploitability: heap-use-after-free > stack-overflow > OOB-read

### AddressSanitizer Output Example
```
ERROR: AddressSanitizer: heap-buffer-overflow on address 0x602000000010
READ of size 1 at 0x602000000010
    #0 in parse_input()
```

---

## CI/CD Integration

```yaml
# GitHub Actions fuzzing example
- name: Run AFL++ for 10 minutes
  run: |
    timeout 600 afl-fuzz -i corpus -o findings -- ./target @@ || true
    if [ -d findings/crashes ]; then
      echo "CRASH FOUND" && cat findings/crashes/id:* | xxd | head -20
      exit 1
    fi
```

---

## MITRE ATT&CK

| Technique | ID | Notes |
|---|---|---|
| Exploitation of Remote Services | T1210 | Fuzzing finds pre-exploitation |
| Exploit for Client Execution | T1203 | Native binary fuzzing |
