# cmd-unmask

Static command-line de-obfuscation and behavioral triage domain for SOC alert analysis.

## Language

**Tracer Script**:
An on-demand, single-run automation utility that collects, peels, or enriches Indicators of Compromise (IOCs) and command artifacts without running as a persistent background daemon.
_Avoid_: Agent, daemon, background service, scanner

**Ingestion Pipeline**:
The initial stage that filters, parses, validates, and normalizes raw command-line artifacts from SIEM/EDR alerts prior to recursive unpacking.
_Avoid_: Input loader, pre-processor, file reader

**Detection Rigidity**:
The resilience of extraction heuristics, regex patterns, and behavioral signatures against triggering False Positives on benign administrative commands in production.
_Avoid_: Sensitivity, accuracy rate, rule strictness

**Obfuscation Layer**:
A single distinct transformation applied to a command line (such as caret escaping, Base64 encoding, Gzip compression, or string formatting) that hides its underlying payload.
_Avoid_: Stage, wrapper, step

**Provenance Chain**:
The ordered sequence of parent-to-child transformations recording exactly which de-obfuscation technique and parameters produced each decoded payload node.
_Avoid_: Decode log, history list, trace stack

**Triage Verdict**:
The final structured assessment combining the fully unmasked payload, its Provenance Chain, defanged IOCs, and MITRE ATT&CK behavioral classification for SOC ticketing.
_Avoid_: Scan result, output report, summary

**Shell Normalizer**:
The context-aware pre-processing component that strips shell-specific character escaping and resolves environment variable slices without corrupting quoted literals.
_Avoid_: Pre-cleaner, quote stripper, sanitizer

**Unpacking DAG**:
The bounded directed acyclic graph of decoded payload states explored from a root command, deduplicated by content hash to prevent cyclic loops.
_Avoid_: Decode tree, recursion stack, state graph

**Payload Node**:
A distinct command or decoded artifact state within the Unpacking DAG, carrying its text, entropy metrics, and parent provenance link.
_Avoid_: Chunk, blob, vertex

**Reconstructed Command**:
A synthetic Payload Node produced when an embedded encoded span is decoded and spliced back into its surrounding parent command syntax.
_Avoid_: Patched string, inline replacement

**Expression Resolver**:
The static reduction component that folds obfuscated shell string expressions, character casts, and string replacements into literal text without executing code.
_Avoid_: Interpreter, emulator, AST evaluator

**Defanged IOC**:
An extracted Indicator of Compromise neutralized with bracketed notation (`hxxp`, `[.]`, `[:]`) so analysts can paste it into tickets without triggering accidental network requests.
_Avoid_: Sanitized URL, masked indicator, escaped IOC

