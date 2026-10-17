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
