"""Tests for Zero-Flag Input Routing and Auto-SIEM Clipboard Ingestion."""

from __future__ import annotations

import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch

from cmd_unmask.cli import main as cli_main


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


if __name__ == "__main__":
    unittest.main()
