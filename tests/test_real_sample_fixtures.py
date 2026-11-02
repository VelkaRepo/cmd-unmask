"""Real-sample sanitized fixtures test suite (backlog item g)."""

import base64
import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from cmd_unmask import Severity, unmask_command
from cmd_unmask.cli import main
from cmd_unmask.ingestion import ingest_single_command


class TestRealSampleFixtures(unittest.TestCase):
    """Real-sample sanitized fixtures verifying edge-case unwrapping and decoding."""

    def test_qradar_export_doubled_quotes_unwrapped_and_decoded(self) -> None:
        payload = "Write-Output 'sample_run'"
        b64_payload = base64.b64encode(payload.encode("utf-16le")).decode("ascii")
        line = (
            '""C:\\Windows\\sysnative\\WindowsPowerShell\\v1.0\\powershell.exe"" '
            f"-encodedCommand {b64_payload}"
        )

        # Ingestion pipeline unwraps SIEM / QRadar doubled quotes
        record = ingest_single_command(line)
        self.assertNotIn('""', record.command_text)

        verdict = unmask_command(record.command_text)
        self.assertNotIn('""', verdict.original_command)
        self.assertIn("Write-Output 'sample_run'", verdict.primary_unmasked_payload)
        self.assertTrue(
            any("Write-Output 'sample_run'" in node.text for node in verdict.dag.nodes.values())
        )

        # Also verify end-to-end via CLI
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = main(["-c", line, "--format", "json"])
        self.assertEqual(code, 0)
        res = json.loads(buf.getvalue())
        self.assertNotIn('""', res["original_command"])
        self.assertIn("Write-Output 'sample_run'", res["primary_unmasked_payload"])

    def test_cron_style_shell_group_via_cmd_and_file(self) -> None:
        inner = (
            "/usr/bin/pkill -0 sensors.d 2>/dev/null || "
            '/usr/bin/bash -c "exec -a \'[ipv6_addrconf]\' \'/opt/app/.cache/tmp/sensors.d\'" '
            "2>/dev/null"
        )
        b64_inner = base64.b64encode(inner.encode("utf-8")).decode("ascii")
        cron_cmd = (
            f"{{ echo {b64_inner}|base64 -d|bash;}} 2>/dev/null "
            "#1b5b324a50524e47 >/dev/random # seed prng sensors.d-kernel"
        )

        # 1. Via CLI `-c` flag
        buf_c = io.StringIO()
        with redirect_stdout(buf_c):
            code_c = main(["-c", cron_cmd, "--format", "json"])
        self.assertEqual(code_c, 0)
        res_c = json.loads(buf_c.getvalue())
        self.assertNotIn(res_c["severity"], [Severity.BENIGN.name, "UNKNOWN"])
        self.assertTrue(
            any("exec -a" in node["text"] for node in res_c["dag"]["nodes"].values()),
            "Expected decoded base64 layer with 'exec -a' in DAG nodes for -c",
        )

        # 2. Via CLI `-f` flag
        with tempfile.TemporaryDirectory() as tmpdir:
            fixture_file = Path(tmpdir) / "cron_sample.txt"
            fixture_file.write_text(cron_cmd + "\n", encoding="utf-8")

            buf_f = io.StringIO()
            with redirect_stdout(buf_f):
                code_f = main(["-f", str(fixture_file), "--format", "json"])
            self.assertEqual(code_f, 0)
            res_f = json.loads(buf_f.getvalue())
            self.assertNotIn(res_f["severity"], [Severity.BENIGN.name, "UNKNOWN"])
            self.assertTrue(
                any("exec -a" in node["text"] for node in res_f["dag"]["nodes"].values()),
                "Expected decoded base64 layer with 'exec -a' in DAG nodes for -f",
            )

    def test_truncated_utf16le_encoded_command_blob(self) -> None:
        # EncodedCommand payload whose length is not a multiple of 4 (ends mid-token)
        full_payload = "Write-Output 'alert_test_notification'"
        b64_full = base64.b64encode(full_payload.encode("utf-16le")).decode("ascii")
        # Length 22 is not a multiple of 4 (22 % 4 != 0)
        trunc_b64 = b64_full[:22]
        self.assertNotEqual(len(trunc_b64) % 4, 0)

        cmd = f"powershell.exe -EncodedCommand {trunc_b64}"
        verdict = unmask_command(cmd)

        self.assertTrue(
            any("truncated" in w.lower() and "base64" in w.lower() for w in verdict.warnings),
            f"Expected truncation warning, got: {verdict.warnings}",
        )
        # Partial decode should still unmask initial substring
        self.assertIn("Write-Ou", verdict.primary_unmasked_payload)

    def test_wrapped_token_nessus_cmd_start_and_stop(self) -> None:
        inner_command = "whoami /all"
        b64_token = base64.b64encode(inner_command.encode("utf-8")).decode("ascii")

        for wrapper in (f"nessus_cmd_{b64_token}_start", f"nessus_cmd_{b64_token}_stop"):
            with self.subTest(wrapper=wrapper):
                verdict = unmask_command(f"echo {wrapper}")
                self.assertTrue(
                    any(inner_command in node.text for node in verdict.dag.nodes.values()),
                    f"Expected inner token '{inner_command}' to be decoded in DAG nodes for {wrapper}",
                )


if __name__ == "__main__":
    unittest.main()
