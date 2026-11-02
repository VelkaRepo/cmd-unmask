import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from cmd_unmask.cli import main
from cmd_unmask.ingestion import ingest_file, ingest_single_command
from cmd_unmask.models import Severity


class TestBatchSiemIngestionAndUnescaping(unittest.TestCase):
    def test_unescape_outer_siem_json_wrapped_command(self) -> None:
        raw = '"powershell.exe -w hidden -c \"IEX (New-Object Net.WebClient)\""'
        rec = ingest_single_command(raw, source_id="cli")
        self.assertEqual(
            rec.command_text,
            'powershell.exe -w hidden -c "IEX (New-Object Net.WebClient)"',
        )

    def test_ingest_line_delimited_raw_text_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            file_path = Path(tmpdir) / "commands.txt"
            file_path.write_text(
                "whoami /all\n\npowershell -enc ZQBjAGgAbwA=\n",
                encoding="utf-8",
            )
            records = ingest_file(str(file_path))
            self.assertEqual(len(records), 2)
            self.assertEqual(records[0].source_id, f"{file_path.name}:1")
            self.assertEqual(records[0].command_text, "whoami /all")
            self.assertEqual(records[1].source_id, f"{file_path.name}:3")
            self.assertEqual(records[1].command_text, "powershell -enc ZQBjAGgAbwA=")

    def test_ingest_json_and_jsonl_standard_and_nested_siem_keys(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            jsonl_path = Path(tmpdir) / "alerts.jsonl"
            lines = [
                json.dumps({"CommandLine": "cmd.exe /c dir"}),
                json.dumps({"process": {"command_line": "powershell.exe -nop"}}),
                json.dumps({"data": {"win": {"eventdata": {"commandLine": "certutil -urlcache"}}}}),
            ]
            jsonl_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
            records = ingest_file(str(jsonl_path))
            self.assertEqual(len(records), 3)
            self.assertEqual(records[0].command_text, "cmd.exe /c dir")
            self.assertEqual(records[1].command_text, "powershell.exe -nop")
            self.assertEqual(records[2].command_text, "certutil -urlcache")

    def test_ingest_custom_field_override_and_fault_isolation(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            jsonl_path = Path(tmpdir) / "custom.jsonl"
            content = (
                '{"custom": {"exec": "rundll32.exe javascript:.."}}\n'
                '{"broken_json": \n'
                '{"unrelated_key": "val"}\n'
            )
            jsonl_path.write_text(content, encoding="utf-8")
            records = ingest_file(str(jsonl_path), custom_field="custom.exec")
            self.assertEqual(len(records), 3)
            self.assertEqual(records[0].command_text, "rundll32.exe javascript:..")
            self.assertEqual(records[0].warnings, [])
            self.assertTrue(any("Corrupt" in w or "Failed" in w or "missing" in w.lower() for w in records[1].warnings))
            self.assertTrue(any("missing" in w.lower() or "not found" in w.lower() for w in records[2].warnings))

    def test_cli_batch_file_jsonl_execution(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            json_path = Path(tmpdir) / "qradar.json"
            json_path.write_text(
                json.dumps([
                    {"command_line": "ipconfig /all"},
                    {"payload": '"cmd.exe /c \"echo ok\""'},
                ]),
                encoding="utf-8",
            )
            buf = io.StringIO()
            with redirect_stdout(buf):
                code = main(["-f", str(json_path), "--format", "jsonl"])
            self.assertEqual(code, 0)
            out_lines = [json.loads(line) for line in buf.getvalue().strip().splitlines()]
            self.assertEqual(len(out_lines), 2)
            self.assertEqual(out_lines[0]["primary_unmasked_payload"], "ipconfig /all")
            self.assertEqual(out_lines[1]["primary_unmasked_payload"], 'cmd.exe /c "echo ok"')

    def test_cron_brace_command_fallback_via_file_flag(self) -> None:
        import base64
        inner_payload = (
            "/usr/bin/pkill -0 -U1001 sensors.d 2>/dev/null || "
            "/usr/bin/bash -c \"exec -a '[ipv6_addrconf]' '/opt/app/.cache/tmp/sensors.d'\" 2>/dev/null"
        )
        b64 = base64.b64encode(inner_payload.encode("utf-8")).decode("ascii")
        line = f"{{ echo {b64}|base64 -d|bash;}} 2>/dev/null #1b5b324a50524e47 >/dev/random # seed prng sensors.d-kernel"

        with tempfile.TemporaryDirectory() as tmpdir:
            file_path = Path(tmpdir) / "cron_task.txt"
            file_path.write_text(line + "\n", encoding="utf-8")
            buf = io.StringIO()
            with redirect_stdout(buf):
                code = main(["-f", str(file_path), "--format", "json"])
            self.assertEqual(code, 0)
            data = json.loads(buf.getvalue())
            self.assertNotEqual(data["severity"], Severity.BENIGN.value)
            self.assertNotEqual(data["severity"], Severity.UNKNOWN.value)
            self.assertIn("sensors.d", data["primary_unmasked_payload"])
            self.assertTrue(any("Corrupt JSON" in w or "falling back to raw command" in w for w in data["warnings"]))

    def test_valid_json_line_regression(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            file_path = Path(tmpdir) / "valid.jsonl"
            file_path.write_text(json.dumps({"command_line": "whoami /all"}) + "\n", encoding="utf-8")
            buf = io.StringIO()
            with redirect_stdout(buf):
                code = main(["-f", str(file_path), "--format", "json"])
            self.assertEqual(code, 0)
            data = json.loads(buf.getvalue())
            self.assertEqual(data["severity"], Severity.BENIGN.value)
            self.assertEqual(data["primary_unmasked_payload"], "whoami /all")
            self.assertEqual(data["warnings"], [])

    def test_empty_record_produces_unknown_verdict_not_benign(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            file_path = Path(tmpdir) / "empty.txt"
            file_path.write_text("   \n\n", encoding="utf-8")
            buf = io.StringIO()
            with redirect_stdout(buf):
                code = main(["-f", str(file_path), "--format", "json"])
            self.assertEqual(code, 0)
            data = json.loads(buf.getvalue())
            self.assertEqual(data["severity"], Severity.UNKNOWN.value)
            self.assertEqual(data["risk_score"], 0)
            self.assertTrue(any("Empty" in w or "zero" in w.lower() or "empty" in w.lower() for w in data["warnings"]))

    def test_batch_with_corrupt_and_good_lines_continues_processing(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            file_path = Path(tmpdir) / "batch.jsonl"
            file_path.write_text(
                '{"broken_json": \n'
                '{"command_line": "whoami"}\n',
                encoding="utf-8",
            )
            buf = io.StringIO()
            with redirect_stdout(buf):
                code = main(["-f", str(file_path), "--format", "jsonl"])
            self.assertEqual(code, 0)
            lines = [json.loads(line) for line in buf.getvalue().strip().splitlines()]
            self.assertEqual(len(lines), 2)
            self.assertTrue(any("Corrupt" in w or "falling back" in w for w in lines[0]["warnings"]))
            self.assertEqual(lines[1]["primary_unmasked_payload"], "whoami")
            self.assertEqual(lines[1]["severity"], Severity.BENIGN.value)

    def test_fail_on_gate_triggers_on_unknown_verdict(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            file_path = Path(tmpdir) / "empty.txt"
            file_path.write_text("", encoding="utf-8")
            buf = io.StringIO()
            with redirect_stdout(buf):
                code = main(["-f", str(file_path), "--fail-on", "HIGH"])
            self.assertEqual(code, 2)


if __name__ == "__main__":
    unittest.main()
