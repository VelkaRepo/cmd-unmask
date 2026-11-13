"""Ingestion Pipeline for cmd-unmask."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from cmd_unmask.models import IngestionRecord

DEFAULT_SIEM_FIELDS: tuple[str, ...] = (
    "CommandLine",
    "command_line",
    "cmd",
    "process.command_line",
    "data.win.eventdata.commandLine",
    "payload",
)

DEFAULT_IMAGE_FIELDS: tuple[str, ...] = (
    "Image",
    "NewProcessName",
    "image",
    "process.executable",
    "data.win.eventdata.image",
)

DEFAULT_PARENT_IMAGE_FIELDS: tuple[str, ...] = (
    "ParentImage",
    "ParentProcessName",
    "parent_image",
    "parentImage",
    "process.parent.executable",
    "data.win.eventdata.parentImage",
)

DEFAULT_PARENT_COMMAND_FIELDS: tuple[str, ...] = (
    "ParentCommandLine",
    "parent_command",
    "parent_command_line",
    "parentCommandLine",
    "parentCommand",
    "process.parent.command_line",
    "data.win.eventdata.parentCommandLine",
)


_BS = chr(92)
_ESC_QUOTE = _BS + '"'
_ESC_BS = _BS + _BS
_DOUBLED_QUOTES_RE = re.compile(r'(?:(?<=^)|(?<=[\s(=,;]))""([^"\s][^"]*?)""(?=$|[\s);,])')


def unwrap_doubled_quotes(text: str) -> str:
    """Unwrap token-delimiting SIEM/QRadar doubled quotes without altering mid-word empty quotes."""
    if '""' in text:
        return _DOUBLED_QUOTES_RE.sub(r'"\1"', text)
    return text


def unescape_outer_siem_wrapper(raw_cmd: str) -> str:
    """Unescape outer SIEM JSON string wrapper or QRadar doubled quotes when present."""
    text = raw_cmd.strip().lstrip("\ufeff")
    if len(text) >= 2 and text.startswith('"') and text.endswith('"'):
        try:
            loaded = json.loads(text)
            if isinstance(loaded, str):
                text = loaded
        except Exception:
            inner = text[1:-1]
            text = inner.replace(_ESC_QUOTE, '"').replace(_ESC_BS, _BS)
    elif _ESC_QUOTE in text and text.count(_ESC_QUOTE) >= 2:
        text = text.replace(_ESC_QUOTE, '"').replace(_ESC_BS, _BS)

    return unwrap_doubled_quotes(text)


unescape_siem_wrapper = unescape_outer_siem_wrapper


def _normalize_optional_str(value: Any) -> str | None:
    """Normalize optional string metadata to stripped non-empty text or None."""
    if not isinstance(value, str):
        return None
    stripped = value.strip()
    return stripped if stripped else None


def _extract_field_from_mapping(
    obj: dict[str, Any],
    field_path: str,
    case_insensitive: bool = False,
) -> str | None:
    """Resolve flat or dotted field path inside a JSON mapping."""
    if field_path in obj and isinstance(obj[field_path], str):
        return obj[field_path]
    curr: Any = obj
    for part in field_path.split("."):
        if not isinstance(curr, dict):
            return None
        if part in curr:
            curr = curr[part]
        elif case_insensitive:
            target_lower = part.lower()
            matched = next(
                (v for k, v in curr.items() if isinstance(k, str) and k.lower() == target_lower),
                None,
            )
            if matched is None:
                return None
            curr = matched
        else:
            return None
    return curr if isinstance(curr, str) else None


def _extract_first_optional(obj: dict[str, Any], candidate_fields: tuple[str, ...]) -> str | None:
    """Extract and normalize the first matching optional string field from a SIEM mapping."""
    for key in candidate_fields:
        val = _extract_field_from_mapping(obj, key, case_insensitive=True)
        norm = _normalize_optional_str(val)
        if norm is not None:
            return norm
    return None


def _extract_lineage(obj: dict[str, Any]) -> tuple[str | None, str | None, str | None]:
    """Extract (image, parent_image, parent_command) from a SIEM/EDR JSON record."""
    return (
        _extract_first_optional(obj, DEFAULT_IMAGE_FIELDS),
        _extract_first_optional(obj, DEFAULT_PARENT_IMAGE_FIELDS),
        _extract_first_optional(obj, DEFAULT_PARENT_COMMAND_FIELDS),
    )


def _record_from_json_obj(
    obj: Any,
    source_id: str,
    raw_input: str,
    candidate_fields: tuple[str, ...],
) -> IngestionRecord:
    """Convert a parsed JSON record into an IngestionRecord."""
    clean_raw_input = raw_input.lstrip("\ufeff")
    if isinstance(obj, str):
        cleaned = unescape_outer_siem_wrapper(obj)
        warnings = [] if cleaned.strip() else ["Empty command string in JSON record."]
        return IngestionRecord(
            source_id=source_id,
            raw_input=clean_raw_input,
            command_text=cleaned,
            warnings=warnings,
        )
    if not isinstance(obj, dict):
        return IngestionRecord(
            source_id=source_id,
            raw_input=clean_raw_input,
            command_text="",
            warnings=[f"Unsupported JSON record type: {type(obj).__name__}."],
        )
    image, parent_image, parent_command = _extract_lineage(obj)
    for key in candidate_fields:
        val = _extract_field_from_mapping(obj, key)
        if val is not None:
            cleaned = unescape_outer_siem_wrapper(val)
            warnings = [] if cleaned.strip() else [f"Field '{key}' is empty."]
            return IngestionRecord(
                source_id=source_id,
                raw_input=clean_raw_input,
                command_text=cleaned,
                warnings=warnings,
                image=image,
                parent_image=parent_image,
                parent_command=parent_command,
            )
    return IngestionRecord(
        source_id=source_id,
        raw_input=clean_raw_input,
        command_text="",
        warnings=[
            f"Command field not found in JSON record (checked: {', '.join(candidate_fields)})."
        ],
        image=image,
        parent_image=parent_image,
        parent_command=parent_command,
    )


def ingest_single_command(
    raw_cmd: str,
    source_id: str = "cli",
    image: str | None = None,
    parent_image: str | None = None,
    parent_command: str | None = None,
) -> IngestionRecord:
    """Ingest a single command string from CLI or stdin."""
    warnings: list[str] = []
    raw_str = raw_cmd if isinstance(raw_cmd, str) else ""
    if raw_str.startswith("\ufeff"):
        raw_str = raw_str.lstrip("\ufeff")
    text = unescape_outer_siem_wrapper(raw_str)
    if not text.strip():
        warnings.append("Empty or whitespace-only command input.")
    return IngestionRecord(
        source_id=source_id,
        raw_input=raw_str,
        command_text=text,
        warnings=warnings,
        image=_normalize_optional_str(image),
        parent_image=_normalize_optional_str(parent_image),
        parent_command=_normalize_optional_str(parent_command),
    )


def ingest_file(file_path: str, custom_field: str | None = None) -> list[IngestionRecord]:
    """Ingest batch artifacts from a line-delimited text, JSON, or JSONL file."""
    path = Path(file_path)
    label = path.name
    try:
        content = path.read_text(encoding="utf-8-sig", errors="replace")
    except Exception as exc:
        return [
            IngestionRecord(
                source_id=label,
                raw_input="",
                command_text="",
                warnings=[f"Failed to read file '{file_path}': {exc}"],
            )
        ]

    candidate_fields: tuple[str, ...] = (
        (custom_field,) if custom_field else DEFAULT_SIEM_FIELDS
    )
    content = content.lstrip("\ufeff")
    stripped = content.strip()
    if not stripped:
        return [
            IngestionRecord(
                source_id=label,
                raw_input="",
                command_text="",
                warnings=["Input file is empty."],
            )
        ]

    suffix = path.suffix.lower()
    if suffix == ".json" or stripped.startswith("["):
        try:
            parsed = json.loads(stripped)
            if isinstance(parsed, list):
                return [
                    _record_from_json_obj(
                        item,
                        source_id=f"{label}:{idx}",
                        raw_input=json.dumps(item),
                        candidate_fields=candidate_fields,
                    )
                    for idx, item in enumerate(parsed, start=1)
                ]
            if isinstance(parsed, dict):
                return [
                    _record_from_json_obj(
                        parsed,
                        source_id=f"{label}:1",
                        raw_input=stripped,
                        candidate_fields=candidate_fields,
                    )
                ]
        except Exception:
            pass

    lines = content.splitlines()
    is_jsonl_mode = suffix in (".jsonl", ".json") or any(
        ln.lstrip().startswith("{") for ln in lines if ln.strip()
    )

    records: list[IngestionRecord] = []
    for line_num, raw_line in enumerate(lines, start=1):
        clean_raw_line = raw_line.lstrip("\ufeff")
        line = clean_raw_line.strip()
        if not line:
            continue
        src_id = f"{label}:{line_num}"
        if is_jsonl_mode:
            try:
                parsed_line = json.loads(line)
                records.append(
                    _record_from_json_obj(
                        parsed_line,
                        source_id=src_id,
                        raw_input=clean_raw_line,
                        candidate_fields=candidate_fields,
                    )
                )
            except Exception as exc:
                cleaned = unescape_outer_siem_wrapper(line)
                records.append(
                    IngestionRecord(
                        source_id=src_id,
                        raw_input=clean_raw_line,
                        command_text=cleaned,
                        warnings=[f"Corrupt JSON line at {src_id}: {exc}; falling back to raw command"],
                    )
                )
        else:
            cleaned = unescape_outer_siem_wrapper(line)
            records.append(
                IngestionRecord(
                    source_id=src_id,
                    raw_input=clean_raw_line,
                    command_text=cleaned,
                    warnings=[],
                )
            )
    if not records:
        return [
            IngestionRecord(
                source_id=label,
                raw_input="",
                command_text="",
                warnings=["Input contains zero analyzable records."],
            )
        ]
    return records


def ingest_source(
    file_path: str | None = None,
    custom_field: str | None = None,
    *,
    cmd: str | None = None,
    stdin_text: str | None = None,
) -> list[IngestionRecord]:
    """Unified Ingestion Pipeline entrypoint for CLI and programmatic callers."""
    if file_path is not None:
        return ingest_file(file_path, custom_field=custom_field)
    if cmd is not None:
        return [ingest_single_command(cmd, source_id="cli")]
    if stdin_text is not None:
        return [ingest_single_command(stdin_text, source_id="stdin")]
    return []
