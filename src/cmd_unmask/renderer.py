"""Output renderers for TriageVerdict (Pretty ANSI Terminal UI, SOC Ticket Markdown, JSON, and JSONL)."""

from __future__ import annotations

import json
import re
from cmd_unmask.models import BenchmarkReport, Severity, TriageVerdict

_TECHNIQUE_LABELS: dict[str, str] = {
    "root": "Raw Input",
    "shell_normalizer": "Shell Normalizer",
    "expression_resolver": "Static Expression Resolver",
    "base64_utf16le": "Base64 UTF-16LE Decoded",
    "base64_utf8": "Base64 UTF-8 Decoded",
    "base64_gzip_decode": "Base64 + Gzip Decompressed",
    "base64_deflate_decode": "Base64 + Deflate Decompressed",
    "hex_decode": "Hex Decoded",
    "url_decode": "URL Percent-Decoded",
    "charcode_decode": "CharCode Sequence Decoded",
    "xor_explicit": "XOR Decoded",
    "xor_bruteforce": "XOR Brute-Force Decoded",
}

_NODE_ARROW_RE = re.compile(r"^node_\d+\s*->\s*node_\d+\s*via\s*")


def format_technique_label(technique: str, parameters: dict | None = None) -> str:
    """Convert an internal decoder technique slug into a human-readable step name."""
    base = _TECHNIQUE_LABELS.get(technique, technique.replace("_", " ").title())
    params = parameters or {}
    if technique in ("xor_explicit", "xor_bruteforce") and params.get("key"):
        return f"{base} (key {params['key']})"
    return base


def build_unmasking_timeline(verdict: TriageVerdict) -> tuple[list[tuple[int, str, str]], dict[str, str]]:
    """Build an ordered, deduplicated list of (step_index, step_label, payload_text) and node_id -> step_label map."""
    timeline: list[tuple[int, str, str]] = [
        (0, "Raw Input", verdict.original_command),
    ]
    node_labels: dict[str, str] = {verdict.dag.root_id: "Step 0 [Raw Input]"}

    step_idx = 1
    prev_normalized = verdict.original_command.strip()
    for edge in verdict.provenance_chain:
        child = verdict.dag.nodes.get(edge.child_id)
        if child is None:
            continue
        child_normalized = child.text.strip()
        if child_normalized == prev_normalized:
            prev_step_num, prev_label, _ = timeline[-1]
            node_labels[edge.child_id] = f"Step {prev_step_num} [{prev_label}]"
            continue
        label = format_technique_label(edge.technique, edge.parameters)
        timeline.append((step_idx, label, child.text))
        node_labels[edge.child_id] = f"Step {step_idx} [{label}]"
        prev_normalized = child_normalized
        step_idx += 1

    for nid, node in verdict.dag.nodes.items():
        if nid not in node_labels:
            lbl = format_technique_label(node.technique, node.parameters)
            node_labels[nid] = f"Step {node.depth} [{lbl}]"

    return timeline, node_labels


def _truncate_lines(text: str, head: int = 8, tail: int = 4, full: bool = False) -> str:
    """Truncate long multi-line payloads using head/tail windows unless full=True."""
    if full or not text:
        return text
    lines = text.splitlines()
    if len(lines) <= head + tail:
        return text
    omitted = len(lines) - (head + tail)
    marker = f"... [{omitted} lines omitted; pass --full to view complete payload] ..."
    return "\n".join(lines[:head] + [marker] + lines[-tail:])


def _humanize_evidence(evidence: str, node_labels: dict[str, str]) -> str:
    """Replace internal 'node_X -> node_Y via tech' evidence strings with human-friendly descriptions."""
    if _NODE_ARROW_RE.search(evidence):
        tech = _NODE_ARROW_RE.sub("", evidence).strip()
        return f"Applied {format_technique_label(tech)}"
    return evidence


def _format_process_chain(verdict: TriageVerdict) -> str | None:
    """Format parent -> child process chain when parent_image is present."""
    if not verdict.parent_image:
        return None
    child = verdict.image or "<command>"
    return f"{verdict.parent_image} -> {child}"


def build_soc_ticket_note(verdict: TriageVerdict, defang: bool = True, full: bool = False) -> str:
    """Generate a compact, ready-to-paste SOC ticket note block for QRadar/MSA offense notes."""
    timeline, _ = build_unmasking_timeline(verdict)
    applied_steps = [lbl for idx, lbl, _ in timeline if idx > 0]
    unmask_summary = " -> ".join(applied_steps) if applied_steps else "None (Unobfuscated)"

    raw_cmd = verdict.original_command
    if len(raw_cmd) > 90:
        raw_display = f"{raw_cmd[:87]}... ({len(raw_cmd)} chars total)"
    else:
        raw_display = raw_cmd

    unmasked_display = _truncate_lines(verdict.primary_unmasked_payload, full=full)

    lines: list[str] = [
        f"[SOC TRIAGE NOTE - {verdict.source_id}]",
        f"Verdict       : {verdict.severity.value} (Risk Score: {verdict.risk_score}/100)",
        f"Obfuscation   : {unmask_summary}",
    ]
    if verdict.verdict_rationale:
        lines.append(f"Rationale     : {verdict.verdict_rationale}")
    process_chain = _format_process_chain(verdict)
    if process_chain:
        lines.append(f"Process Chain : {process_chain}")
    lines.extend(
        [
            f"Raw Command   : {raw_display}",
            "Unmasked Cmd  :",
        ]
    )
    for uline in unmasked_display.splitlines() or [""]:
        lines.append(f"  {uline}")

    if verdict.capabilities:
        lines.append("Capabilities  :")
        for cap in verdict.capabilities:
            lines.append(f"  - {cap}")

    if verdict.iocs:
        lines.append("Extracted IOCs:")
        for i in verdict.iocs:
            val = i.defanged_value if defang else i.raw_value
            lines.append(f"  - [{i.ioc_type.upper()}] {val}")
    else:
        lines.append("Extracted IOCs: None")

    if verdict.behavioral_matches:
        lines.append("MITRE ATT&CK  :")
        for m in verdict.behavioral_matches:
            lines.append(f"  - {m.mitre_id} : {m.name} ({m.tactic})")
    else:
        lines.append("MITRE ATT&CK  : None")

    if verdict.warnings:
        lines.append(f"Warnings      : {'; '.join(verdict.warnings)}")

    return "\n".join(lines)


def render_pretty(
    verdicts: list[TriageVerdict],
    defang: bool = True,
    color: bool = True,
    full: bool = False,
) -> str:
    """Render verdicts using a rich ANSI terminal UI with box-drawing characters and 4 clear sections."""
    c_reset = "\x1b[0m" if color else ""
    c_bold = "\x1b[1m" if color else ""
    c_cyan = "\x1b[36m" if color else ""
    c_dim = "\x1b[2m" if color else ""
    c_green = "\x1b[32m" if color else ""
    c_yellow = "\x1b[33m" if color else ""
    c_red = "\x1b[31m" if color else ""
    c_magenta = "\x1b[35m" if color else ""

    def _sev_color(sev: Severity) -> str:
        if not color:
            return ""
        if sev in (Severity.HIGH, Severity.CRITICAL):
            return c_red + c_bold
        if sev == Severity.MEDIUM:
            return c_yellow + c_bold
        if sev == Severity.LOW:
            return c_magenta + c_bold
        if sev == Severity.UNKNOWN:
            return c_yellow + c_bold
        return c_green + c_bold

    blocks: list[str] = []
    for verdict in verdicts:
        timeline, node_labels = build_unmasking_timeline(verdict)
        sc = _sev_color(verdict.severity)
        header_title = (
            f" Triage Verdict [{verdict.source_id}] | "
            f"Severity: {verdict.severity.value} ({verdict.risk_score}/100) "
        )
        box_width = max(68, len(header_title) + 4)
        top_bar = "╔" + ("═" * box_width) + "╗"
        bot_bar = "╚" + ("═" * box_width) + "╝"

        lines: list[str] = [
            f"{c_cyan}{top_bar}{c_reset}",
            f"{c_cyan}║{c_reset}{sc}{header_title.ljust(box_width)}{c_reset}{c_cyan}║{c_reset}",
            f"{c_cyan}{bot_bar}{c_reset}",
        ]
        process_chain = _format_process_chain(verdict)
        if process_chain:
            lines.append(f"{c_bold}Process Chain:{c_reset} {process_chain}")
        lines.extend(
            [
                "",
                f"{c_bold}{c_cyan}[1] UNMASKING TIMELINE (LAYER-BY-LAYER){c_reset}",
            ]
        )

        for idx, (step_num, label, text_val) in enumerate(timeline):
            is_last = idx == len(timeline) - 1
            connector = "└─►" if is_last else "├─►"
            tag = " [FINAL UNMASKED PAYLOAD]" if (is_last and len(timeline) > 1) else ""
            lines.append(
                f"  {c_cyan}{connector}{c_reset} {c_bold}Step {step_num} [{label}]{tag}{c_reset}"
            )
            pipe_prefix = "      " if is_last else f"  {c_cyan}│{c_reset}   "
            display_text = _truncate_lines(text_val, full=full)
            for tline in display_text.splitlines() or [""]:
                lines.append(f"{pipe_prefix}{tline}")

        ioc_header_mode = "DEFANGED" if defang else "RAW"
        lines.append("")
        lines.append(f"{c_bold}{c_cyan}[2] EXTRACTED IOCs ({ioc_header_mode}){c_reset}")
        if verdict.iocs:
            for i, ioc in enumerate(verdict.iocs):
                conn = "└─►" if i == len(verdict.iocs) - 1 else "├─►"
                val = ioc.defanged_value if defang else ioc.raw_value
                origin_label = node_labels.get(ioc.source_node_id, "Unpacked Layer")
                lines.append(
                    f"  {c_cyan}{conn}{c_reset} [{c_yellow}{ioc.ioc_type}{c_reset}] {c_bold}{val}{c_reset} {c_dim}(from {origin_label}){c_reset}"
                )
        else:
            lines.append(f"  {c_dim}└─► None{c_reset}")

        lines.append("")
        lines.append(f"{c_bold}{c_cyan}[3] WHY THIS WAS FLAGGED (MITRE ATT&CK & EVIDENCE){c_reset}")
        if verdict.behavioral_matches:
            for i, match in enumerate(verdict.behavioral_matches):
                conn = "└─►" if i == len(verdict.behavioral_matches) - 1 else "├─►"
                clean_ev = _humanize_evidence(match.evidence, node_labels)
                origin_label = node_labels.get(match.source_node_id, "Unpacked Layer")
                lines.append(
                    f"  {c_cyan}{conn}{c_reset} {c_bold}{match.mitre_id}{c_reset} ({match.tactic}) - {match.name}: {clean_ev} {c_dim}({origin_label}){c_reset}"
                )
        else:
            lines.append(f"  {c_dim}└─► None (No malicious behavioral indicators matched){c_reset}")

        if verdict.capabilities:
            lines.append("")
            lines.append(f"{c_bold}{c_cyan}[BEHAVIORAL CAPABILITIES]{c_reset}")
            for i, cap in enumerate(verdict.capabilities):
                conn = "└─►" if i == len(verdict.capabilities) - 1 else "├─►"
                lines.append(f"  {c_cyan}{conn}{c_reset} {cap}")

        if verdict.verdict_rationale:
            lines.append("")
            lines.append(f"{c_bold}{c_cyan}[VERDICT RATIONALE]{c_reset}")
            lines.append(f"  {c_cyan}└─►{c_reset} {verdict.verdict_rationale}")

        if verdict.warnings:
            lines.append("")
            lines.append(f"{c_bold}{c_yellow}[!] DIAGNOSTIC WARNINGS{c_reset}")
            for i, w in enumerate(verdict.warnings):
                conn = "└─►" if i == len(verdict.warnings) - 1 else "├─►"
                lines.append(f"  {conn} {w}")

        lines.append("")
        lines.append(f"{c_bold}{c_cyan}[4] READY-TO-PASTE SOC TICKET NOTE{c_reset}")
        divider = "─" * 68
        lines.append(f"{c_dim}{divider}{c_reset}")
        for note_line in build_soc_ticket_note(verdict, defang=defang, full=full).splitlines():
            lines.append(note_line)
        lines.append(f"{c_dim}{divider}{c_reset}")

        blocks.append("\n".join(lines))

    return "\n\n".join(blocks) + "\n"


def render_markdown(verdicts: list[TriageVerdict], defang: bool = True) -> str:
    """Render one or more TriageVerdict objects into SOC Ticket Markdown."""
    blocks: list[str] = []
    for verdict in verdicts:
        timeline, node_labels = build_unmasking_timeline(verdict)
        lines: list[str] = [
            f"## Triage Verdict [{verdict.source_id}]",
            f"- **Severity**: `{verdict.severity.value}` (Risk Score: `{verdict.risk_score}/100`)",
        ]
        process_chain = _format_process_chain(verdict)
        if process_chain:
            lines.append(f"- **Process Chain**: `{process_chain}`")
        lines.extend(
            [
                f"- **Original Command**: `{verdict.original_command}`",
                f"- **Primary Unmasked Payload**: `{verdict.primary_unmasked_payload}`",
                "- **Unmasking Timeline**:",
            ]
        )
        for step_num, label, text_val in timeline:
            lines.append(f"  - **Step {step_num} [{label}]**: `{text_val}`")

        if verdict.iocs:
            lines.append("- **Extracted IOCs**:")
            for ioc in verdict.iocs:
                val = ioc.defanged_value if defang else ioc.raw_value
                origin_label = node_labels.get(ioc.source_node_id, "Unpacked Layer")
                lines.append(f"  - [{ioc.ioc_type}] `{val}` (from {origin_label})")
        else:
            lines.append("- **Extracted IOCs**: None")

        if verdict.behavioral_matches:
            lines.append("- **MITRE ATT&CK Behavioral Matches**:")
            for match in verdict.behavioral_matches:
                clean_ev = _humanize_evidence(match.evidence, node_labels)
                origin_label = node_labels.get(match.source_node_id, "Unpacked Layer")
                lines.append(
                    f"  - `{match.mitre_id}` ({match.tactic}) - **{match.name}**: `{clean_ev}` (from {origin_label})"
                )
        else:
            lines.append("- **MITRE ATT&CK Behavioral Matches**: None")

        if verdict.capabilities:
            lines.append("- **Behavioral Capabilities**:")
            for cap in verdict.capabilities:
                lines.append(f"  - `{cap}`")

        if verdict.verdict_rationale:
            lines.append(f"- **Verdict Rationale**: {verdict.verdict_rationale}")

        if verdict.warnings:
            lines.append("- **Diagnostic Warnings**:")
            for warn in verdict.warnings:
                lines.append(f"  - {warn}")

        blocks.append("\n".join(lines))
    return "\n\n---\n\n".join(blocks) + "\n"


def render_json(verdicts: list[TriageVerdict], defang: bool = True) -> str:
    """Render verdicts as pretty-printed JSON (single object if 1 verdict, list if multiple)."""
    if len(verdicts) == 1:
        payload = verdicts[0].to_dict(defang=defang)
    else:
        payload = [v.to_dict(defang=defang) for v in verdicts]
    return json.dumps(payload, indent=2) + "\n"


def render_jsonl(verdicts: list[TriageVerdict], defang: bool = True) -> str:
    """Render verdicts as line-delimited JSONL."""
    return "\n".join(json.dumps(v.to_dict(defang=defang)) for v in verdicts) + "\n"


def render_benchmark_summary(
    report: BenchmarkReport,
    color: bool = False,
    max_fpr: float = 0.0,
    verbose: bool = False,
) -> str:
    """Render a structured summary table for a Regression Corpus BenchmarkReport."""
    green = "\033[92m" if color else ""
    red = "\033[91m" if color else ""
    yellow = "\033[93m" if color else ""
    cyan = "\033[96m" if color else ""
    dim = "\033[2m" if color else ""
    bold = "\033[1m" if color else ""
    reset = "\033[0m" if color else ""

    gate_ok = report.failed == 0 and report.fpr <= max_fpr
    gate_status = f"{green}PASS{reset}" if gate_ok else f"{red}FAIL{reset}"

    lines = [
        f"{bold}{cyan}[cmd-unmask Regression Corpus Benchmark]{reset} Gate: {gate_status}",
        f"  Fixtures : {report.total} total | {green}{report.passed} passed{reset} | "
        f"{(red if report.failed else dim)}{report.failed} failed{reset}",
        f"  Matrix   : TP={report.true_positives} FP={report.false_positives} "
        f"FN={report.false_negatives} TN={report.true_negatives}",
        f"  Metrics  : Precision={report.precision:.4f} | Recall={report.recall:.4f} "
        f"| F1={report.f1_score:.4f} | FPR={report.fpr:.4f} (max={max_fpr:.4f})",
        f"  Latency  : p50={report.p50_ms:.2f}ms | p95={report.p95_ms:.2f}ms",
    ]

    if report.category_stats:
        lines.append("")
        lines.append(f"{bold}Category Breakdown:{reset}")
        lines.append(
            f"  {'Category':<24} {'Total':>5} {'Pass':>5} {'Fail':>5} {'Acc':>8} {'p50(ms)':>8} {'Avg(ms)':>8}"
        )
        lines.append(f"  {'-' * 67}")
        for cat, stats in report.category_stats.items():
            acc_pct = f"{stats['accuracy'] * 100.0:.1f}%"
            cat_color = green if stats["failed"] == 0 else red
            lines.append(
                f"  {cat:<24} {stats['total']:>5} {cat_color}{stats['passed']:>5}{reset} "
                f"{stats['failed']:>5} {acc_pct:>8} {stats['p50_ms']:>8.2f} {stats['avg_ms']:>8.2f}"
            )

    if verbose and report.results:
        lines.append("")
        lines.append(f"{bold}Fixture Results:{reset}")
        lines.append(
            f"  {'Status':<6} {'ID':<12} {'Category':<22} {'Label':<10} {'Actual':<9} {'Score':>5} {'ms':>7}"
        )
        lines.append(f"  {'-' * 77}")
        for item in report.results:
            status_txt = f"{green}PASS{reset}" if item.passed else f"{red}FAIL{reset}"
            sev_color = yellow if item.actual_severity.rank >= Severity.MEDIUM.rank else dim
            lines.append(
                f"  {status_txt:<6} {item.fixture_id:<12} {item.category:<22} "
                f"{item.label:<10} {sev_color}{item.actual_severity.value:<9}{reset} "
                f"{item.actual_risk_score:>5} {item.latency_ms:>7.2f}"
            )

    failed_items = [r for r in report.results if not r.passed]
    if failed_items:
        lines.append("")
        lines.append(f"{red}  Failures:{reset}")
        for item in failed_items:
            lines.append(
                f"    - {item.fixture_id} ({item.label}, {item.actual_severity.value}): "
                + "; ".join(item.failures)
            )
    return "\n".join(lines) + "\n"


def render_benchmark_json(report: BenchmarkReport) -> str:
    """Render a BenchmarkReport as pretty-printed JSON."""
    return json.dumps(report.to_dict(), indent=2) + "\n"
