"""CLI entrypoint for cmd-unmask Tracer Script."""

from __future__ import annotations

import argparse
import ctypes
import os
import subprocess
import sys
from typing import Sequence

from cmd_unmask.ingestion import ingest_single_command, ingest_source
from cmd_unmask.models import Severity, TriageConfig, TriageVerdict
from cmd_unmask.renderer import (
    build_soc_ticket_note,
    render_json,
    render_jsonl,
    render_markdown,
    render_pretty,
)
from cmd_unmask.unpacker import unmask_command

_CF_UNICODETEXT = 13
_GMEM_MOVEABLE = 0x0002


def get_clipboard_text() -> str:
    """Read raw text from the OS clipboard using stdlib ctypes (Win32) or OS CLI fallbacks."""
    if sys.platform == "win32":
        try:
            user32 = ctypes.windll.user32
            kernel32 = ctypes.windll.kernel32
            user32.OpenClipboard.argtypes = [ctypes.c_void_p]
            user32.OpenClipboard.restype = ctypes.c_int
            user32.GetClipboardData.argtypes = [ctypes.c_uint]
            user32.GetClipboardData.restype = ctypes.c_void_p
            user32.CloseClipboard.argtypes = []
            user32.CloseClipboard.restype = ctypes.c_int
            kernel32.GlobalLock.argtypes = [ctypes.c_void_p]
            kernel32.GlobalLock.restype = ctypes.c_void_p
            kernel32.GlobalUnlock.argtypes = [ctypes.c_void_p]
            kernel32.GlobalUnlock.restype = ctypes.c_int

            if user32.OpenClipboard(None):
                try:
                    handle = user32.GetClipboardData(_CF_UNICODETEXT)
                    if handle:
                        ptr = kernel32.GlobalLock(handle)
                        if ptr:
                            try:
                                return ctypes.wstring_at(ptr)
                            finally:
                                kernel32.GlobalUnlock(handle)
                finally:
                    user32.CloseClipboard()
        except Exception:
            pass

        try:
            res = subprocess.run(
                ["powershell", "-NoProfile", "-Command", "Get-Clipboard"],
                capture_output=True,
                text=True,
                timeout=3,
                check=False,
            )
            if res.returncode == 0:
                return res.stdout.strip()
        except Exception:
            pass
        return ""

    for cmd in (["pbpaste"], ["wl-paste"], ["xclip", "-selection", "clipboard", "-o"]):
        try:
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=3, check=False)
            if res.returncode == 0:
                return res.stdout.strip()
        except Exception:
            continue
    return ""


def set_clipboard_text(text: str) -> bool:
    """Write text to the OS clipboard using stdlib ctypes (Win32) or OS CLI fallbacks."""
    if sys.platform == "win32":
        try:
            user32 = ctypes.windll.user32
            kernel32 = ctypes.windll.kernel32
            user32.OpenClipboard.argtypes = [ctypes.c_void_p]
            user32.OpenClipboard.restype = ctypes.c_int
            user32.EmptyClipboard.argtypes = []
            user32.EmptyClipboard.restype = ctypes.c_int
            user32.SetClipboardData.argtypes = [ctypes.c_uint, ctypes.c_void_p]
            user32.SetClipboardData.restype = ctypes.c_void_p
            user32.CloseClipboard.argtypes = []
            user32.CloseClipboard.restype = ctypes.c_int
            kernel32.GlobalAlloc.argtypes = [ctypes.c_uint, ctypes.c_size_t]
            kernel32.GlobalAlloc.restype = ctypes.c_void_p
            kernel32.GlobalLock.argtypes = [ctypes.c_void_p]
            kernel32.GlobalLock.restype = ctypes.c_void_p
            kernel32.GlobalUnlock.argtypes = [ctypes.c_void_p]
            kernel32.GlobalUnlock.restype = ctypes.c_int

            encoded = text.encode("utf-16le") + b"\x00\x00"
            if user32.OpenClipboard(None):
                try:
                    user32.EmptyClipboard()
                    h_mem = kernel32.GlobalAlloc(_GMEM_MOVEABLE, len(encoded))
                    if h_mem:
                        ptr = kernel32.GlobalLock(h_mem)
                        if ptr:
                            ctypes.memmove(ptr, encoded, len(encoded))
                            kernel32.GlobalUnlock(h_mem)
                            if user32.SetClipboardData(_CF_UNICODETEXT, h_mem):
                                return True
                finally:
                    user32.CloseClipboard()
        except Exception:
            pass

        try:
            res = subprocess.run(
                ["clip"],
                input=text,
                text=True,
                timeout=3,
                check=False,
            )
            return res.returncode == 0
        except Exception:
            return False

    for cmd in (["pbcopy"], ["wl-copy"], ["xclip", "-selection", "clipboard"]):
        try:
            res = subprocess.run(cmd, input=text, text=True, timeout=3, check=False)
            if res.returncode == 0:
                return True
        except Exception:
            continue
    return False


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cmd-unmask",
        description="Static command-line de-obfuscation and behavioral triage Tracer Script.",
    )
    parser.add_argument("-c", "--cmd", help="Single obfuscated command string to unmask.")
    parser.add_argument("-f", "--file", help="Path to raw text, JSON, or JSONL input file.")
    parser.add_argument(
        "-p",
        "--paste",
        action="store_true",
        help="Read the obfuscated command directly from the OS clipboard (bypasses EDR CLI blocks).",
    )
    parser.add_argument("--field", help="Custom JSON field name containing the command line.")
    parser.add_argument(
        "--format",
        choices=["pretty", "markdown", "json", "jsonl"],
        default="pretty",
        help="Output format (default: pretty).",
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable ANSI colors in pretty terminal output.",
    )
    parser.add_argument(
        "--copy-note",
        action="store_true",
        help="Copy the generated Ready-to-Paste SOC Ticket Note to the OS clipboard.",
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
    elif args.paste:
        clip_text = get_clipboard_text()
        records.append(ingest_single_command(clip_text, source_id="clipboard"))
    elif args.file is not None:
        records.extend(ingest_source(args.file, custom_field=args.field))
    elif not sys.stdin.isatty():
        stdin_text = sys.stdin.read()
        records.append(ingest_single_command(stdin_text, source_id="stdin"))
    else:
        try:
            sys.stderr.write("Paste obfuscated command (or press Enter to read from clipboard): ")
            sys.stderr.flush()
            typed = input().strip()
        except EOFError:
            typed = ""
        if typed:
            records.append(ingest_single_command(typed, source_id="interactive"))
        else:
            clip_text = get_clipboard_text()
            if clip_text and clip_text.strip():
                records.append(ingest_single_command(clip_text, source_id="clipboard"))
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
    use_color = (
        not args.no_color
        and "NO_COLOR" not in os.environ
        and hasattr(sys.stdout, "isatty")
        and sys.stdout.isatty()
    )

    if args.format == "json":
        sys.stdout.write(render_json(verdicts, defang=defang))
    elif args.format == "jsonl":
        sys.stdout.write(render_jsonl(verdicts, defang=defang))
    elif args.format == "markdown":
        sys.stdout.write(render_markdown(verdicts, defang=defang))
    else:
        sys.stdout.write(render_pretty(verdicts, defang=defang, color=use_color))

    if args.copy_note and verdicts:
        combined_notes = "\n\n".join(build_soc_ticket_note(v, defang=defang) for v in verdicts)
        set_clipboard_text(combined_notes)

    if args.fail_on:
        threshold = Severity(args.fail_on)
        if any(v.severity.rank >= threshold.rank for v in verdicts):
            return 2

    return 0
