# Tactical HUD Terminal Layout

As `cmd-unmask` evolved through v0.5–v0.7, `render_pretty()` accumulated additional diagnostic blocks (`[BEHAVIORAL CAPABILITIES]`, `[VERDICT RATIONALE]`, `[ANALYST EXECUTIVE BRIEF]`, `[RECOMMENDED L1/L2 NEXT STEPS]`, and `[4] READY-TO-PASTE SOC TICKET NOTE`) alongside `[1]`–`[3]` and `[5] AUTO-SYNTHESIZED SIGMA RULE`. On live SOC triage runs, this caused three terminal UX problems:

1. **Broken visual hierarchy:** Critical context (`Process Chain` and `Analyst Executive Brief`) appeared either outside the top summary box or buried near the bottom after raw timeline dumps, while numbered sections (`[1]`–`[4]`) mixed with unnumbered headers.
2. **Benign clutter:** Empty `BENIGN` sections (`[2] EXTRACTED IOCs -> None`, `[3] WHY THIS WAS FLAGGED -> None`) consumed vertical terminal space without adding analyst signal.
3. **Duplicate ticket dump:** `[4] READY-TO-PASTE SOC TICKET NOTE` repeated the entire verdict summary on stdout even though interactive runs already auto-copy the borderless ticket note to the OS clipboard ([ADR-0014](0014-smart-zero-flag-cli-and-auto-siem-clipboard.md)).

To deliver a scannable, top-down **Tactical Triage HUD** using 100% Python standard library (`renderer.py` and `cli.py`, zero external dependencies):

1. **Top-Down Summary HUD Box:** `render_pretty()` renders a structured top summary box containing **Verdict / Severity + Risk Score**, **Source ID**, **Process Chain** (when present), and **Executive Brief** (synthesized narrative) so L1 analysts see the full triage picture in the first 5–8 lines.
2. **Strict ASCII Fallback (`--no-color`):** When `color=False` (`--no-color`), `render_pretty()` switches from Unicode box-drawing characters (`╔═╗`, `║`, `╚═╝`, `├─►`, `└─►`, `│`) to pure 7-bit ASCII borders and tree connectors (`+---+`, `|`, `|--`, `+--`), guaranteeing clean rendering in non-UTF-8 consoles and plain-text logs.
3. **Unified Sequential Section Numbering & Empty-Section Collapsing:** All body sections following the HUD box use clean sequential `[1]`..`[N]` numbering:
   - `[1] UNMASKING TIMELINE` (always shown)
   - `[2] BEHAVIORAL EVIDENCE & CAPABILITIES` (MITRE ATT&CK matches + capabilities + verdict rationale; on `BENIGN` runs with no matches/capabilities, collapsed into a single concise rationale line)
   - `[3] EXTRACTED IOCs` (omitted/collapsed on `BENIGN` runs with zero IOCs; always rendered when IOCs exist)
   - `[4] RECOMMENDED L1/L2 NEXT STEPS` (rendered when playbook steps exist)
   - `[!] DIAGNOSTIC WARNINGS` (rendered only when warnings exist)
   - Auto-synthesized Sigma YAML continues as the final numbered section when emitted on interactive runs.
4. **Compact Clipboard Banner & `--show-note` Opt-In:** By default, `render_pretty()` no longer dumps the full duplicate `[SOC TRIAGE NOTE]` block to the terminal. Instead, when clipboard copy succeeds (or is active), `cli.py` emits a crisp 1-line status banner (`[+] SOC Ticket Note copied to clipboard (use --show-note to print)`), while preserving the exact full `build_soc_ticket_note()` payload in the OS clipboard. Analysts who want the ticket note printed on stdout pass `--show-note`.
5. **Machine-Readable Stability:** `--format json` and `--format jsonl` remain strictly unchanged and pure on stdout.
