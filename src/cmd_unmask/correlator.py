"""Deterministic Attack-Chain Correlation and L1/L2 Investigation Playbook Engine."""

from __future__ import annotations

import re

from cmd_unmask.knowledge import (
    classify_network_target,
    explain_execution_flags,
    lookup_binary_profile,
)
from cmd_unmask.models import BehavioralMatch, ExtractedIOC, Severity, UnpackingDAG


def _short_name(path: str | None) -> str:
    if not path:
        return ""
    return path.strip().strip("\"'").replace("\\", "/").rsplit("/", 1)[-1]


def correlate_triage(
    *,
    original_command: str,
    primary_unmasked_payload: str,
    dag: UnpackingDAG,
    iocs: list[ExtractedIOC],
    behavioral_matches: list[BehavioralMatch],
    capabilities: list[str],
    verdict_rationale: str,
    severity: Severity,
    risk_score: int,
    image: str | None = None,
    parent_image: str | None = None,
    defang: bool = True,
) -> tuple[str, list[str]]:
    """Synthesize a concise executive brief and artifact-grounded L1/L2 playbook steps."""
    if severity == Severity.UNKNOWN:
        return (
            "Input command was empty or unparseable; static correlation could not evaluate execution intent.",
            [
                "Retrieve the complete CommandLine and ParentImage fields from the source SIEM/EDR event.",
                "Re-run cmd-unmask with the full raw event JSON or command string.",
            ],
        )

    if severity == Severity.BENIGN:
        if "Authorized VA Audit Baseline" in verdict_rationale:
            return (
                "Authorized VA Audit Baseline activity detected: read-only Netapi32.dll domain-join audit "
                "with zero offensive memory-injection APIs or remote download cradles.",
                [
                    "Verify the source host/account matches an active Nessus or scheduled VA scan window.",
                    "Close alert as Authorized VA Audit Baseline if scan ticket is confirmed.",
                ],
            )
        target_bin = image or (primary_unmasked_payload.split()[0] if primary_unmasked_payload.split() else "")
        prof = lookup_binary_profile(target_bin)
        role_note = f" ({prof.legitimate_purpose})" if prof else ""
        return (
            f"Benign administrative or standard CLI activity{role_note}; no obfuscation layers, "
            "masquerading paths, or malicious behavioral indicators were observed.",
            [
                "No containment required; confirm standard operator/automation context if alert volume spikes.",
            ],
        )

    rule_ids = {m.rule_id for m in behavioral_matches}
    mitre_ids = {m.mitre_id for m in behavioral_matches}
    chain_layers = len(dag.get_provenance_chain(dag.primary_leaf_id))

    target_token = image or (primary_unmasked_payload.split()[0] if primary_unmasked_payload.split() else "")
    profile = lookup_binary_profile(target_token)
    flag_notes = explain_execution_flags(primary_unmasked_payload) or explain_execution_flags(original_command)

    net_iocs = [i for i in iocs if i.ioc_type in ("url", "domain", "ipv4", "ipv6")]
    file_iocs = [i for i in iocs if i.ioc_type in ("file_path", "path")]
    classified_net = [(i, classify_network_target(i.raw_value, i.ioc_type)) for i in net_iocs]

    # Build concise, natural analyst prose Executive Brief (<= ~160 chars)
    parent_disp = _short_name(parent_image) if parent_image else ""
    child_disp = _short_name(image) or _short_name(target_token) or "process"

    if "BINARY_MASQUERADING" in rule_ids:
        lead = f"Masquerading {image} from non-canonical path"
    elif parent_disp:
        adj = "obfuscated " if chain_layers > 0 else ""
        lead = f"{parent_disp} spawned {adj}{child_disp}"
    elif chain_layers > 0:
        lead = f"Obfuscated {child_disp}"
    elif profile:
        lead = f"{profile.name} execution"
    else:
        lead = f"Suspicious {child_disp} activity ({severity.value} {risk_score}/100)"

    if any(mid.startswith("T1003") for mid in mitre_ids):
        action = "performing LSASS/credential dumping"
    elif "T1055" in mitre_ids:
        action = "using Win32 process-injection APIs"
    else:
        action = ""

    target = ""
    if classified_net:
        ext_vals = [i.raw_value for i, cls in classified_net if cls == "public_external"]
        meta_vals = [i.raw_value for i, cls in classified_net if cls == "cloud_metadata"]
        priv_vals = [i.raw_value for i, cls in classified_net if cls == "private_rfc1918"]
        if ext_vals:
            target = f"targeting {ext_vals[0]}"
        elif meta_vals:
            target = f"querying cloud metadata {meta_vals[0]}"
        elif priv_vals:
            target = f"targeting internal {priv_vals[0]}"

    brief_parts = [part for part in (lead, action, target) if part]
    brief = " ".join(brief_parts) + "."
    if len(brief) > 160 and action and target:
        brief = f"{lead} {target}."
    if flag_notes and len(brief) <= 125:
        flag_tag = flag_notes[0].split(":", 1)[0]
        candidate = f"{brief} Key flag: {flag_tag}."
        if len(candidate) <= 160:
            brief = candidate

    # Build artifact-grounded L1/L2 Investigation Playbook
    steps: list[str] = []

    if any(mid.startswith("T1003") for mid in mitre_ids) or "T1055" in mitre_ids:
        steps.append(
            "Isolate host immediately in EDR and initiate credential rotation for active/privileged sessions."
        )

    if "BINARY_MASQUERADING" in rule_ids and image:
        steps.append(
            f"Quarantine non-canonical binary '{image}' and verify file SHA256/Authenticode signature."
        )

    if parent_image:
        steps.append(
            f"Inspect parent process '{parent_image}' (document/web-server worker/service) for initial-access vector."
        )

    ext_or_meta = [i for i, cls in classified_net if cls in ("public_external", "cloud_metadata")]
    if ext_or_meta:
        targets = ", ".join(
            (i.defanged_value if defang else i.raw_value) for i in ext_or_meta[:3]
        )
        steps.append(
            f"Hunt and block network target(s) ({targets}) across firewall, proxy, and DNS logs."
        )

    # Collect concrete file/staging paths from IOCs or capabilities
    concrete_paths: list[str] = []
    for fi in file_iocs:
        if fi.raw_value not in concrete_paths:
            concrete_paths.append(fi.raw_value)
    for cap in capabilities:
        if cap.startswith("File Write: "):
            p = cap.split("File Write: ", 1)[1]
            if p not in concrete_paths:
                concrete_paths.append(p)
    for m_path in re.findall(
        r"""([A-Za-z]:\\(?:Users|Temp|ProgramData|Windows\\Temp)\\[^\s"';|&)]+|/(?:tmp|dev/shm)/[^\s"';|&)]+)""",
        primary_unmasked_payload,
        re.IGNORECASE,
    ):
        if m_path not in concrete_paths:
            concrete_paths.append(m_path)
    if concrete_paths:
        steps.append(
            f"Acquire and hash on-disk artifact(s): {', '.join(concrete_paths[:3])}."
        )

    if not steps:
        steps.append(
            f"Review full unmasked command and host telemetry around '{_short_name(target_token) or 'process'}' for unauthorized activity."
        )

    return brief, steps[:5]
