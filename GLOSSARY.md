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

**Primary Unmasked Payload**:
The highest-signal terminal leaf node selected from the Unpacking DAG as the headline decoded command in the Triage Verdict.
_Avoid_: Best guess, final string, winner node

**Sigma Rule Synthesizer**:
The dependency-free generator that translates unmasked commands, extracted IOCs, and MITRE ATT&CK classifications into portable, vendor-neutral Sigma YAML detection rules.
_Avoid_: Rule exporter, Sigma writer, signature maker

**Regression Corpus**:
The versioned, sanitized dataset of malicious stagers and benign administrative command lines with expected triage outcomes used to validate de-obfuscation and classification accuracy over time.
_Avoid_: Test dump, sample list, training set

**Corpus Fixture**:
A single labeled entry inside a Regression Corpus pairing a raw command artifact with its expected severity bounds, MITRE ATT&CK techniques, IOCs, and negative-match assertions.
_Avoid_: Test row, mock alert, data point

**Detection Rigidity Gate**:
The automated pass/fail threshold check executed during benchmarking that blocks regressions in False Positive rate, detection recall, or per-command latency.
_Avoid_: Quality check, lint gate, pass threshold

**Benchmark Report**:
The structured summary emitted by the benchmark runner detailing corpus pass/fail counts, precision, recall, False Positive rate, and p50/p95 latency metrics.
_Avoid_: Test log, perf dump, stats output

**Process Lineage Context**:
The optional execution metadata (`parent_image`, `parent_command`, `image`) from Event ID 4688, Sysmon Event ID 1, or CLI `--parent` capturing who spawned the target process.
_Avoid_: Process tree dump, parent metadata, fork info

**Staging Path Anomaly**:
Execution of a binary or script from a non-standard, user-writable, or temporary directory (such as `\Users\Public\`, `\AppData\Local\Temp\`, `\ProgramData\`, `/tmp/`, or `/dev/shm/`) rather than canonical OS directories.
_Avoid_: Temp folder, weird path, bad directory

**Spawn Matrix**:
The deterministic mapping of suspicious parent-child process relationships (e.g., Office macros or web servers spawning shell interpreters) to MITRE ATT&CK techniques and risk weights.
_Avoid_: Parent blacklist, process ruleset, spawn list

**UTF-16LE Null-Byte Padding**:
Interleaved `\x00` bytes produced when Windows PowerShell `-EncodedCommand` UTF-16LE Base64 strings are decoded as raw ASCII/UTF-8 or pasted standalone without the `-enc` flag.
_Avoid_: Null garbage, wide-char noise, zero bytes

**Authorized Audit Baseline**:
Known read-only enterprise vulnerability assessment (VA) and configuration-audit signatures (such as Nessus `NetGetJoinInformation` checks) explicitly distinguished from offensive Win32 injection APIs to prevent False Positives.
_Avoid_: Scanner whitelist, safe list, bypass rule

**Behavioral Capability Summary**:
The structured list of non-IOC operational behaviors extracted statically from an unmasked payload—such as file write targets, Win32/.NET P/Invoke API imports, and registry key operations—giving SOC analysts immediate intent visibility.
_Avoid_: Behavior dump, API log, capability tags

**Verdict Rationale**:
The explicit, human-readable explanation recorded on a Triage Verdict detailing why a command scored `BENIGN` (such as Authorized Audit Baseline suppression) or why specific behavioral rules escalated its severity.
_Avoid_: Reason string, debug note, justification text



