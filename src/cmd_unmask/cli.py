"""CLI entrypoint for cmd-unmask Tracer Script."""

from __future__ import annotations

import argparse
import sys
from typing import Sequence

from cmd_unmask.ingestion import ingest_single_command
from cmd_unmask.models import Severity, TriageConfig, TriageVerdict
from cmd_unmask.renderer import render_json, render_jsonl, render_markdown
from cmd_unmask.unpacker import unmask_command


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cmd-unmask",
        description="Static command-line de-obfuscation and behavioral triage Tracer Script.",
    )
    parser.add_argument("-c", "--cmd", help="Single obfuscated command string to unmask.")
    parser.add_argument("-f", "--file", help="Path to raw text, JSON, or JSONL input file.")
    parser.add_argument("--field", help="Custom JSON field name containing the command line.")
    parser.add_argument(
        "--format",
        choices=["markdown", "json", "jsonl"],
        default="markdown",
        help="Output format (default: markdown).",
    )
    parser.add_argument(
        "--no-defang",
        action="store_true",
        help="Emit raw IOCs instead of defanged IOCs.",
    )
    parser.add_argument(
        "--max-depth",
        type=int,
        default=10,
        help="Maximum Unpacking DAG depth (default: 10).",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=3.0,
        help="Per-command unpacking timeout in seconds (default: 3.0).",
    )
    parser.add_argument(
        "--fail-on",
        choices=["LOW", "MEDIUM", "HIGH", "CRITICAL"],
        help="Exit with status code 2 if any verdict meets or exceeds this severity.",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Execute cmd-unmask CLI and return process exit code."""
    parser = build_parser()
    args = parser.parse_args(argv)

    config = TriageConfig(
        max_depth=args.max_depth,
        timeout_seconds=args.timeout,
        defang_iocs=not args.no_defang,
        custom_field=args.field,
    )

    records = []
    if args.cmd is not None:
        records.append(ingest_single_command(args.cmd, source_id="cli"))
    elif not sys.stdin.isatty():
        stdin_text = sys.stdin.read()
        records.append(ingest_single_command(stdin_text, source_id="stdin"))
    else:
        parser.print_help(sys.stderr)
        return 1

    verdicts: list[TriageVerdict] = []
    for rec in records:
        verdict = unmask_command(
            rec.command_text,
            config=config,
            source_id=rec.source_id,
            initial_warnings=rec.warnings,
        )
        verdicts.append(verdict)

    defang = not args.no_defang
    if args.format == "json":
        sys.stdout.write(render_json(verdicts, defang=defang))
    elif args.format == "jsonl":
        sys.stdout.write(render_jsonl(verdicts, defang=defang))
    else:
        sys.stdout.write(render_markdown(verdicts, defang=defang))

    if args.fail_on:
        threshold = Severity(args.fail_on)
        if any(v.severity.rank >= threshold.rank for v in verdicts):
            return 2

    return 0
