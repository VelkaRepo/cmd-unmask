"""Ingestion Pipeline for cmd-unmask."""

from __future__ import annotations

from cmd_unmask.models import IngestionRecord


def ingest_single_command(raw_cmd: str, source_id: str = "cli") -> IngestionRecord:
    """Ingest a single command string from CLI or stdin."""
    warnings: list[str] = []
    text = raw_cmd.strip("\r\n") if isinstance(raw_cmd, str) else ""
    if not text.strip():
        warnings.append("Empty or whitespace-only command input.")
    return IngestionRecord(
        source_id=source_id,
        raw_input=raw_cmd if isinstance(raw_cmd, str) else "",
        command_text=text,
        warnings=warnings,
    )
