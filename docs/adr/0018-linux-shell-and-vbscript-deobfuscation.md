# ADR-0018: Linux Shell (`bash`/`sh`) and VBScript/JScript Deobfuscation Layer

- **Status:** Accepted
- **Date:** 2026-11-13
- **Deciders:** Dion (SOC Engineering)
- **Target Version:** `cmd-unmask` v1.0.0

## Context
Modern SOC alerts span both Windows endpoints (PowerShell, `cmd.exe`, HTA/`wscript.exe`/`cscript.exe` VBScript droppers) and Linux/cloud workloads (`bash`, `sh`, container entrypoints, cron/SSH telemetry). Attackers on Linux routinely evade naive string matching using `$IFS` / `${IFS}` field-separator injection (`curl$IFS-s$IFShttp://...`), ANSI-C quoting (`$'\x63\x75\x72\x6c'`, octal `$'\143\165\162\154'`), Base64-to-shell pipes (`echo <b64> | base64 -d | bash`), and hex-to-shell reconstruction (`xxd -r -p` / `printf '\x...' | sh`). Meanwhile, phishing and HTA/script-host campaigns frequently use VBScript `Chr(N)` / `ChrW(N)` concatenation (`Chr(119)&Chr(115)...`) wrapped in `Execute`, `ExecuteGlobal`, or `Eval`.

`cmd-unmask` already handles basic `$'...'` ANSI-C escapes and `echo ... | base64 -d` in `resolver.py`, but lacks comprehensive `$IFS` normalization, `xxd -r -p` / `printf '\x...'` hex-to-shell decoding, Linux shell MITRE/LOLBin rules (`T1059.004`, `T1105`), and VBScript `Chr()`/`ChrW()` + execution-wrapper unpacking.

## Decision
Extend the static Unpacking DAG (`normalizer.py`, `resolver.py`, `unpacker.py`) and Behavioral Classifier (`rules.py`) using **100% Python standard library** with zero `eval`/`exec`/subprocess execution:

1. **Linux Shell (`bash`/`sh`) Deobfuscation:**
   - Normalize `$IFS` and `${IFS}` separator obfuscation outside single-quoted `'...'` literals into a single ASCII space (` `).
   - Support ANSI-C quoting (`$'\xNN'` hex and `$'\NNN'` octal) inside `resolver.py`, plus `echo <hex> | xxd -r -p` and `printf '\xNN...'` hex-to-shell reconstruction with strict printable-ratio and byte-ceiling (`256 KB`) checks.
   - Support `echo <b64> | base64 -d | sh/bash` (and `base64 --decode`) pipelines, feeding decoded payloads back into the bounded DAG for IOC and behavioral classification.
   - Add/align Linux shell behavioral rules (`T1059.004` Unix Shell Execution, `T1105` Ingress Tool Transfer via `curl`/`wget` piped to `sh`/`bash`).

2. **VBScript/JScript (`Chr()`/`ChrW()`) Deobfuscation:**
   - Implement a deterministic stdlib evaluator for `Chr(N)` and `ChrW(N)` chains joined with `&` or `+` (handling decimal and VBScript hex `&HNN` literals, bounded to `0 <= N <= 0x10FFFF` and `MAX_CHAR_ARRAY_LEN = 16_384`).
   - Unwrap `Execute(...)`, `ExecuteGlobal(...)`, and `Eval(...)` script-host wrappers when their argument resolves to a concrete string literal, emitting a child DAG node for downstream IOC/classifier inspection.

3. **Strict Anti-False-Positive Boundaries:**
   - **Linux Paths & Flags:** Never modify `$IFS` when used inside standard shell configuration assignments (`IFS= read -r ...` or `local IFS=$'\n'`) without obfuscated command tokens, and never flag standard Linux admin commands (`apt-get update`, `systemctl status`, `docker ps`, `sudo id`, `tar -xzf`, `grep -rn`) as `OBF_COMMAND` or malicious.
   - **Benign VBScript/Admin Calls:** Standard WSH/admin snippets (`WScript.Echo`, `CreateObject("Scripting.FileSystemObject")`, single `Chr(13)`/`Chr(10)` newline formatting in benign scripts) must not trigger false-positive malicious verdicts (`FPR = 0.0000` on Regression Corpus).

## Consequences
- **Positive:** Unifies Windows (`cmd.exe`, PowerShell, VBScript/HTA) and Linux (`bash`/`sh`) static command-line triage in a single zero-dependency v1.0.0 tracer script.
- **Negative / Trade-offs:** Runtime-only shell variable expansion depending on live environment state or external files remains out of scope by design ([ADR-0001](0001-static-stdlib-only-analysis.md)).
