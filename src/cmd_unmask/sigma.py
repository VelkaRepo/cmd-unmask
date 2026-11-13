"""Zero-dependency Sigma Rule Synthesizer for cmd-unmask."""

from __future__ import annotations

import re
import uuid
from datetime import date
from typing import Any

from cmd_unmask.models import Severity, SigmaRule, TriageVerdict

_SEVERITY_TO_SIGMA_LEVEL: dict[Severity, str] = {
    Severity.CRITICAL: "critical",
    Severity.HIGH: "high",
    Severity.MEDIUM: "medium",
    Severity.LOW: "low",
}

_WINDOWS_PROCESS_MARKERS: tuple[tuple[str, str], ...] = (
    ("powershell.exe", r"\powershell.exe"),
    ("pwsh.exe", r"\pwsh.exe"),
    ("powershell", r"\powershell.exe"),
    ("cmd.exe", r"\cmd.exe"),
    ("certutil.exe", r"\certutil.exe"),
    ("certutil", r"\certutil.exe"),
    ("mshta.exe", r"\mshta.exe"),
    ("mshta", r"\mshta.exe"),
    ("rundll32.exe", r"\rundll32.exe"),
    ("rundll32", r"\rundll32.exe"),
    ("regsvr32.exe", r"\regsvr32.exe"),
    ("regsvr32", r"\regsvr32.exe"),
    ("wmic.exe", r"\wmic.exe"),
    ("wmic", r"\wmic.exe"),
    ("bitsadmin.exe", r"\bitsadmin.exe"),
    ("bitsadmin", r"\bitsadmin.exe"),
    ("cscript.exe", r"\cscript.exe"),
    ("wscript.exe", r"\wscript.exe"),
    ("schtasks.exe", r"\schtasks.exe"),
)

_LINUX_PROCESS_MARKERS: tuple[tuple[str, str], ...] = (
    ("/bin/bash", "/bash"),
    ("/bin/sh", "/sh"),
    ("bash", "/bash"),
    ("curl", "/curl"),
    ("wget", "/wget"),
)

_HIGH_SIGNAL_KEYWORDS: tuple[str, ...] = (
    "DownloadString",
    "DownloadFile",
    "Invoke-Expression",
    "IEX",
    "Invoke-WebRequest",
    "FromBase64String",
    "Net.WebClient",
    "AmsiUtils",
    "amsiInitFailed",
    "-bxor",
    "-enc",
    "-EncodedCommand",
    "urlcache",
    "split",
    "vbscript:",
    "javascript:",
)

_SAFE_UNQUOTED_RE = re.compile(r"^[A-Za-z0-9_.\-/]+$")


def _infer_platform_and_image(verdict: TriageVerdict) -> tuple[str, str | None]:
    """Infer target Sigma product ('windows' or 'linux') and process Image suffix."""
    combined = f"{verdict.original_command}\n{verdict.primary_unmasked_payload}".lower()
    for marker, image_suffix in _WINDOWS_PROCESS_MARKERS:
        if marker in combined:
            return "windows", image_suffix

    for marker, image_suffix in _LINUX_PROCESS_MARKERS:
        if marker in combined:
            return "linux", image_suffix

    return "windows", None


def _build_mitre_tags(verdict: TriageVerdict) -> list[str]:
    """Convert BehavioralMatch tactics and MITRE IDs into lowercase Sigma attack.* tags."""
    tags: list[str] = []
    seen: set[str] = set()
    for match in verdict.behavioral_matches:
        if match.tactic:
            tactic_slug = (
                match.tactic.strip().lower().replace(" ", "_").replace("-", "_")
            )
            tactic_tag = f"attack.{tactic_slug}"
            if tactic_tag not in seen:
                seen.add(tactic_tag)
                tags.append(tactic_tag)
        if match.mitre_id:
            tech_tag = f"attack.{match.mitre_id.strip().lower()}"
            if tech_tag not in seen:
                seen.add(tech_tag)
                tags.append(tech_tag)
    return tags


def _extract_selection_keywords(verdict: TriageVerdict, max_keywords: int = 8) -> list[str]:
    """Extract high-signal keywords and IOCs for CommandLine|contains|all."""
    keywords: list[str] = []
    seen_lower: set[str] = set()

    def _add(candidate: str) -> None:
        cleaned = candidate.strip()
        if not cleaned or len(cleaned) < 3:
            return
        lowered = cleaned.lower()
        if any(lowered == existing or lowered in existing for existing in seen_lower):
            return
        seen_lower.add(lowered)
        keywords.append(cleaned)

    for match in verdict.behavioral_matches:
        if len(keywords) >= max_keywords:
            break
        if match.evidence:
            _add(match.evidence)

    payload = verdict.primary_unmasked_payload
    for token in _HIGH_SIGNAL_KEYWORDS:
        if len(keywords) >= max_keywords:
            break
        if token.lower() in payload.lower():
            _add(token)

    for ioc in verdict.iocs:
        if len(keywords) >= max_keywords:
            break
        if ioc.ioc_type in ("url", "domain", "ip", "hash"):
            _add(ioc.raw_value)

    if not keywords and payload.strip():
        snippet = payload.strip().splitlines()[0][:80].strip()
        if snippet:
            keywords.append(snippet)

    return keywords[:max_keywords]


def _format_parent_image_endswith(parent_image: str | None) -> str | None:
    """Normalize parent_image into a portable Sigma ParentImage|endswith pattern."""
    if not parent_image or not isinstance(parent_image, str):
        return None
    cleaned = parent_image.strip().strip("\"'")
    if not cleaned:
        return None
    base = re.split(r"[\\/]", cleaned)[-1].lower()
    if not base:
        return None
    if "/" in cleaned and "\\" not in cleaned:
        return f"*/{base}"
    return f"*\\{base}"


def generate_sigma_rule(
    verdict: TriageVerdict,
    author: str = "cmd-unmask",
) -> SigmaRule | None:
    """Synthesize a portable SigmaRule from a non-benign TriageVerdict.

    Returns None when the verdict is BENIGN, UNKNOWN, or lacks an unmasked payload.
    """
    if verdict.severity in (Severity.BENIGN, Severity.UNKNOWN):
        return None
    if not verdict.primary_unmasked_payload.strip():
        return None

    rule_uuid = str(uuid.uuid5(uuid.NAMESPACE_DNS, verdict.primary_unmasked_payload))
    product, image_suffix = _infer_platform_and_image(verdict)
    tags = _build_mitre_tags(verdict)
    keywords = _extract_selection_keywords(verdict)
    sigma_level = _SEVERITY_TO_SIGMA_LEVEL.get(verdict.severity, "medium")

    if verdict.behavioral_matches:
        primary_behavior = verdict.behavioral_matches[0].name
        title = f"Suspicious {product.capitalize()} Activity - {primary_behavior}"
    else:
        title = f"Suspicious {product.capitalize()} Command Execution ({verdict.severity.value})"

    description = (
        f"Auto-generated Sigma rule by cmd-unmask for alert '{verdict.source_id}'. "
        f"Detects unmasked command-line indicators (Risk Score: {verdict.risk_score}/100)."
    )

    selection: dict[str, Any] = {}
    parent_suffix = _format_parent_image_endswith(verdict.parent_image)
    if parent_suffix:
        selection["ParentImage|endswith"] = parent_suffix
    if image_suffix:
        selection["Image|endswith"] = image_suffix
    if keywords:
        selection["CommandLine|contains|all"] = keywords

    detection: dict[str, Any] = {
        "selection": selection,
        "condition": "selection",
    }

    return SigmaRule(
        title=title,
        id=rule_uuid,
        status="experimental",
        description=description,
        references=["https://github.com/VelkaRepo/cmd-unmask"],
        author=author,
        date=date.today().strftime("%Y/%m/%d"),
        tags=tags,
        logsource={
            "category": "process_creation",
            "product": product,
        },
        detection=detection,
        falsepositives=[
            "Legitimate administrative scripts",
            "Authorized software deployment or automation tooling",
        ],
        level=sigma_level,
    )


def _format_yaml_scalar(value: str, force_quote: bool = False) -> str:
    """Format a scalar string safely for YAML without external libraries."""
    if not force_quote and _SAFE_UNQUOTED_RE.match(value):
        return value
    escaped = value.replace("'", "''")
    return f"'{escaped}'"


def render_sigma_yaml(rule: SigmaRule) -> str:
    """Serialize a SigmaRule dataclass into standard-compliant Sigma YAML."""
    lines: list[str] = [
        f"title: {_format_yaml_scalar(rule.title, force_quote=True)}",
        f"id: {rule.id}",
        f"status: {rule.status}",
        f"description: {_format_yaml_scalar(rule.description, force_quote=True)}",
    ]

    if rule.references:
        lines.append("references:")
        for ref in rule.references:
            lines.append(f"    - {_format_yaml_scalar(ref, force_quote=True)}")

    lines.append(f"author: {_format_yaml_scalar(rule.author, force_quote=True)}")
    if rule.date:
        lines.append(f"date: {rule.date}")

    if rule.tags:
        lines.append("tags:")
        for tag in rule.tags:
            lines.append(f"    - {tag}")

    lines.append("logsource:")
    for key, val in rule.logsource.items():
        lines.append(f"    {key}: {_format_yaml_scalar(str(val))}")

    lines.append("detection:")
    for det_key, det_val in rule.detection.items():
        if isinstance(det_val, dict):
            lines.append(f"    {det_key}:")
            for sub_key, sub_val in det_val.items():
                if isinstance(sub_val, list):
                    lines.append(f"        {sub_key}:")
                    for item in sub_val:
                        lines.append(
                            f"            - {_format_yaml_scalar(str(item), force_quote=True)}"
                        )
                else:
                    lines.append(
                        f"        {sub_key}: {_format_yaml_scalar(str(sub_val), force_quote=True)}"
                    )
        else:
            lines.append(f"    {det_key}: {_format_yaml_scalar(str(det_val))}")

    if rule.falsepositives:
        lines.append("falsepositives:")
        for fp in rule.falsepositives:
            lines.append(f"    - {_format_yaml_scalar(fp, force_quote=True)}")

    lines.append(f"level: {rule.level}")
    return "\n".join(lines) + "\n"


def render_sigma_yaml_bundle(rules: list[SigmaRule]) -> str:
    """Render one or more SigmaRule objects as a YAML document stream."""
    if not rules:
        return ""
    if len(rules) == 1:
        return render_sigma_yaml(rules[0])
    return "---\n".join(render_sigma_yaml(rule) for rule in rules)
