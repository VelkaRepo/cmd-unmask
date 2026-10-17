"""Ingestion Pipeline for cmd-unmask."""

from __future__ import annotations

import json
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


_BS = chr(92)
_ESC_QUOTE = _BS + '"'
_ESC_BS = _BS + _BS


def unescape_outer_siem_wrapper(raw_cmd: str) -> str:
    """Unescape outer SIEM JSON string wrapper when present."""
    text = raw_cmd.strip()
    if len(text) >= 2 and text.startswith('"') and text.endswith('"'):
        try:
            loaded = json.loads(text)
            if isinstance(loaded, str):
                return loaded
        except Exception:
            inner = text[1:-1]
            return inner.replace(_ESC_QUOTE, '"').replace(_ESC_BS, _BS)
    if _ESC_QUOTE in text and text.count(_ESC_QUOTE) >= 2:
        return text.replace(_ESC_QUOTE, '"').replace(_ESC_BS, _BS)
    return text


unescape_siem_wrapper = unescape_outer_siem_wrapper


def _extract_field_from_mapping(obj: dict[str, Any], field_path: str) -> str | None:
    """Resolve flat or dotted field path inside a JSON mapping."""
    if field_path in obj and isinstance(obj[field_path], str):
        return obj[field_path]
    curr: Any = obj
    for part in field_path.split("."):
        if isinstance(curr, dict) and part in curr:
            curr = curr[part]
        else:
            return None
    return curr if isinstance(curr, str) else None


def _record_from_json_obj(
    obj: Any,
    source_id: str,
    raw_input: str,
    candidate_fields: tuple[str, ...],
) -> IngestionRecord:
    """Convert a parsed JSON record into an IngestionRecord."""
    if isinstance(obj, str):
        cleaned = unescape_outer_siem_wrapper(obj)
        warnings = [] if cleaned.strip() else ["Empty command string in JSON record."]
        return IngestionRecord(
            source_id=source_id,
            raw_input=raw_input,
            command_text=cleaned,
            warnings=warnings,
        )
    if not isinstance(obj, dict):
        return IngestionRecord(
            source_id=source_id,
            raw_input=raw_input,
            command_text="",
            warnings=[f"Unsupported JSON record type: {type(obj).__name__}."],
        )
    for key in candidate_fields:
        val = _extract_field_from_mapping(obj, key)
        if val is not None:
            cleaned = unescape_outer_siem_wrapper(val)
            warnings = [] if cleaned.strip() else [f"Field '{key}' is empty."]
            return IngestionRecord(
                source_id=source_id,
                raw_input=raw_input,
                command_text=cleaned,
                warnings=warnings,
            )
    return IngestionRecord(
        source_id=source_id,
        raw_input=raw_input,
        command_text="",
        warnings=[
            f"Command field not found in JSON record (checked: {', '.join(candidate_fields)})."
        ],
    )


def ingest_single_command(raw_cmd: str, source_id: str = "cli") -> IngestionRecord:
    """Ingest a single command string from CLI or stdin."""
    warnings: list[str] = []
    raw_str = raw_cmd if isinstance(raw_cmd, str) else ""
    text = unescape_outer_siem_wrapper(raw_str)
    if not text.strip():
        warnings.append("Empty or whitespace-only command input.")
    return IngestionRecord(
        source_id=source_id,
        raw_input=raw_str,
        command_text=text,
        warnings=warnings,
    )


def ingest_file(file_path: str, custom_field: str | None = None) -> list[IngestionRecord]:
    """Ingest batch artifacts from a line-delimited text, JSON, or JSONL file."""
    path = Path(file_path)
    label = path.name
    try:
        content = path.read_text(encoding="utf-8", errors="replace")
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
        line = raw_line.strip()
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
                        raw_input=raw_line,
                        candidate_fields=candidate_fields,
                    )
                )
            except Exception as exc:
                records.append(
                    IngestionRecord(
                        source_id=src_id,
                        raw_input=raw_line,
                        command_text="",
                        warnings=[f"Corrupt JSON line at {src_id}: {exc}"],
                    )
                )
        else:
            cleaned = unescape_outer_siem_wrapper(line)
            records.append(
                IngestionRecord(
                    source_id=src_id,
                    raw_input=raw_line,
                    command_text=cleaned,
                    warnings=[],
                )
            )
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
