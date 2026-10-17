"""Output renderers for TriageVerdict (SOC Ticket Markdown, JSON, and JSONL)."""

from __future__ import annotations

import json
from cmd_unmask.models import TriageVerdict


def render_markdown(verdicts: list[TriageVerdict], defang: bool = True) -> str:
    """Render one or more TriageVerdict objects into SOC Ticket Markdown."""
    blocks: list[str] = []
    for verdict in verdicts:
        lines: list[str] = [
            f"## Triage Verdict [{verdict.source_id}]",
            f"- **Severity**: `{verdict.severity.value}` (Risk Score: `{verdict.risk_score}/100`)",
            f"- **Original Command**: `{verdict.original_command}`",
            f"- **Primary Unmasked Payload**: `{verdict.primary_unmasked_payload}`",
        ]
        if verdict.provenance_chain:
            lines.append("- **Provenance Chain**:")
            for idx, step in enumerate(verdict.provenance_chain, start=1):
                lines.append(f"  {idx}. `{step.parent_id} -> {step.child_id}` via `{step.technique}`")
        else:
            lines.append("- **Provenance Chain**: `root` (0 obfuscation layers unpacked)")

        if verdict.iocs:
            lines.append("- **Extracted IOCs**:")
            for ioc in verdict.iocs:
                val = ioc.defanged_value if defang else ioc.raw_value
                lines.append(f"  - [{ioc.ioc_type}] `{val}` (from `{ioc.source_node_id}`)")
        else:
            lines.append("- **Extracted IOCs**: None")

        if verdict.behavioral_matches:
            lines.append("- **MITRE ATT&CK Behavioral Matches**:")
            for match in verdict.behavioral_matches:
                lines.append(
                    f"  - `{match.mitre_id}` ({match.tactic}) - **{match.name}**: `{match.evidence}` (from `{match.source_node_id}`)"
                )
        else:
            lines.append("- **MITRE ATT&CK Behavioral Matches**: None")

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
