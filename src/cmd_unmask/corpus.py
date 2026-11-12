"""Regression Corpus schema validation and seed dataset loader."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from cmd_unmask.models import CorpusFixture, Severity

_VALID_LABELS = frozenset({"malicious", "benign"})


def _parse_optional_severity(raw_value: Any, field_name: str) -> Severity | None:
    if raw_value is None:
        return None
    if not isinstance(raw_value, str):
        raise ValueError(f"Field '{field_name}' must be a string or null")
    try:
        return Severity(raw_value.strip().upper())
    except ValueError as exc:
        raise ValueError(f"Invalid severity '{raw_value}' in '{field_name}'") from exc


def _parse_str_list(raw_value: Any, field_name: str) -> list[str]:
    if raw_value is None:
        return []
    if not isinstance(raw_value, list) or not all(isinstance(item, str) for item in raw_value):
        raise ValueError(f"Field '{field_name}' must be a list of strings")
    return list(raw_value)


def parse_corpus_record(record: dict[str, Any]) -> CorpusFixture:
    """Validate and convert a raw JSON mapping into a CorpusFixture."""
    if not isinstance(record, dict):
        raise ValueError("Corpus record must be a JSON object")

    fixture_id = record.get("fixture_id")
    if not isinstance(fixture_id, str) or not fixture_id.strip():
        raise ValueError("Field 'fixture_id' must be a non-empty string")

    label = record.get("label")
    if not isinstance(label, str) or label.strip().lower() not in _VALID_LABELS:
        raise ValueError("Field 'label' must be 'malicious' or 'benign'")

    command = record.get("command")
    if not isinstance(command, str) or not command.strip():
        raise ValueError("Field 'command' must be a non-empty string")

    description = record.get("description", "")
    if not isinstance(description, str):
        raise ValueError("Field 'description' must be a string")

    category = record.get("category", "uncategorized")
    if not isinstance(category, str) or not category.strip():
        raise ValueError("Field 'category' must be a non-empty string")

    return CorpusFixture(
        fixture_id=fixture_id.strip(),
        label=label.strip().lower(),
        command=command,
        expected_severity=_parse_optional_severity(record.get("expected_severity"), "expected_severity"),
        min_severity=_parse_optional_severity(record.get("min_severity"), "min_severity"),
        max_severity=_parse_optional_severity(record.get("max_severity"), "max_severity"),
        expected_techniques=_parse_str_list(record.get("expected_techniques"), "expected_techniques"),
        expected_iocs=_parse_str_list(record.get("expected_iocs"), "expected_iocs"),
        must_not_match=_parse_str_list(record.get("must_not_match"), "must_not_match"),
        description=description,
        category=category.strip(),
    )


def load_corpus_file(path: str | Path) -> list[CorpusFixture]:
    """Load and validate CorpusFixture records from a JSON or JSONL file."""
    target = Path(path)
    if not target.is_file():
        raise ValueError(f"Corpus file not found: {target}")

    try:
        raw_text = target.read_text(encoding="utf-8-sig")
    except OSError as exc:
        raise ValueError(f"Failed to read corpus file '{target}': {exc}") from exc

    stripped = raw_text.strip()
    if not stripped:
        raise ValueError(f"Corpus file is empty: {target}")

    records: list[dict[str, Any]] = []
    if stripped.startswith("["):
        try:
            parsed = json.loads(stripped)
        except json.JSONDecodeError as exc:
            raise ValueError(f"Invalid JSON array in '{target}': {exc}") from exc
        if not isinstance(parsed, list):
            raise ValueError(f"Expected JSON array in '{target}'")
        records = parsed
    else:
        for line_no, line in enumerate(raw_text.splitlines(), start=1):
            clean_line = line.strip()
            if not clean_line or clean_line.startswith("#"):
                continue
            try:
                parsed_line = json.loads(clean_line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"Invalid JSONL at {target}:{line_no}: {exc}") from exc
            records.append(parsed_line)

    fixtures: list[CorpusFixture] = []
    for idx, rec in enumerate(records, start=1):
        try:
            fixtures.append(parse_corpus_record(rec))
        except ValueError as exc:
            raise ValueError(f"Invalid fixture #{idx} in '{target}': {exc}") from exc
    return fixtures


def default_corpus_dir() -> Path:
    """Resolve the repository's built-in corpus/ directory."""
    return Path(__file__).resolve().parent.parent.parent / "corpus"


def load_seed_corpus(corpus_dir: str | Path | None = None) -> list[CorpusFixture]:
    """Load both benign.jsonl and malicious.jsonl from the seed corpus directory."""
    base = Path(corpus_dir) if corpus_dir is not None else default_corpus_dir()
    if not base.is_dir():
        raise ValueError(f"Seed corpus directory not found: {base}")

    fixtures: list[CorpusFixture] = []
    for filename in ("benign.jsonl", "malicious.jsonl"):
        candidate = base / filename
        if candidate.is_file():
            fixtures.extend(load_corpus_file(candidate))
    if not fixtures:
        raise ValueError(f"No corpus files found in '{base}'")
    return fixtures
