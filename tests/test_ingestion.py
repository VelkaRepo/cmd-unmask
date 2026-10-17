import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from cmd_unmask.cli import main
from cmd_unmask.ingestion import ingest_file, ingest_single_command


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


if __name__ == "__main__":
    unittest.main()
