import hashlib
import io
import json
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch

from cmd_unmask import Severity, TriageConfig, unmask_command
from cmd_unmask.cli import main


class TestTracerBulletPipeline(unittest.TestCase):
    def test_unmask_command_returns_verdict_with_root_node_metrics(self) -> None:
        raw = "powershell.exe -NoProfile -Command Write-Host hello"
        verdict = unmask_command(raw, TriageConfig())

        self.assertEqual(verdict.primary_unmasked_payload, raw)
        self.assertEqual(verdict.severity, Severity.BENIGN)
        self.assertEqual(verdict.risk_score, 0)
        self.assertEqual(len(verdict.dag.nodes), 1)

        root = verdict.dag.nodes[verdict.dag.root_id]
        expected_hash = hashlib.sha256(raw.encode("utf-8")).hexdigest()
        self.assertEqual(root.sha256, expected_hash)
        self.assertEqual(root.depth, 0)
        self.assertIsNone(root.parent_id)
        self.assertAlmostEqual(root.printable_ratio, 1.0)
        self.assertGreater(root.shannon_entropy, 3.0)
        self.assertLess(root.shannon_entropy, 5.0)

    def test_cli_markdown_output_from_cmd_flag(self) -> None:
        buf = io.StringIO()
        with redirect_stdout(buf):
            exit_code = main(["-c", "whoami /all"])
        output = buf.getvalue()
        self.assertEqual(exit_code, 0)
        self.assertIn("Triage Verdict", output)
        self.assertIn("BENIGN", output)
        self.assertIn("whoami /all", output)

    def test_cli_json_and_jsonl_output_and_stdin(self) -> None:
        buf = io.StringIO()
        with patch("sys.stdin", io.StringIO("ipconfig /flushdns\n")), redirect_stdout(buf):
            exit_code = main(["--format", "json"])
        self.assertEqual(exit_code, 0)
        data = json.loads(buf.getvalue())
        self.assertEqual(data["primary_unmasked_payload"], "ipconfig /flushdns")
        self.assertEqual(data["severity"], "BENIGN")

        buf_jsonl = io.StringIO()
        with redirect_stdout(buf_jsonl):
            exit_code_jsonl = main(["-c", "hostname", "--format", "jsonl"])
        self.assertEqual(exit_code_jsonl, 0)
        line_obj = json.loads(buf_jsonl.getvalue().strip())
        self.assertEqual(line_obj["primary_unmasked_payload"], "hostname")

    def test_defensive_handling_on_empty_command(self) -> None:
        verdict = unmask_command("   ")
        self.assertEqual(verdict.severity, Severity.BENIGN)
        self.assertTrue(any("Empty" in w for w in verdict.warnings))


if __name__ == "__main__":
    unittest.main()
