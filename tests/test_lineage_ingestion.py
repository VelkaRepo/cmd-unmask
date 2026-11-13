import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from cmd_unmask.cli import main as cli_main
from cmd_unmask.corpus import parse_corpus_record
from cmd_unmask.ingestion import ingest_file, ingest_single_command
from cmd_unmask.models import (
    CorpusFixture,
    IngestionRecord,
    PayloadNode,
    Severity,
    TriageVerdict,
    UnpackingDAG,
)
from cmd_unmask.unpacker import unmask_command


class TestProcessLineageModels(unittest.TestCase):
    def test_lineage_defaults_are_none(self):
        rec = IngestionRecord(
            source_id="cli",
            raw_input="whoami",
            command_text="whoami",
        )
        self.assertIsNone(rec.image)
        self.assertIsNone(rec.parent_image)
        self.assertIsNone(rec.parent_command)

        dag = UnpackingDAG(
            root_id="node_0",
            nodes={"node_0": PayloadNode(node_id="node_0", text="whoami", depth=0)},
            primary_leaf_id="node_0",
        )
        verdict = TriageVerdict(
            source_id="cli",
            original_command="whoami",
            primary_unmasked_payload="whoami",
            dag=dag,
            severity=Severity.BENIGN,
        )
        self.assertIsNone(verdict.image)
        self.assertIsNone(verdict.parent_image)
        self.assertIsNone(verdict.parent_command)
        payload = verdict.to_dict()
        self.assertIn("image", payload)
        self.assertIn("parent_image", payload)
        self.assertIn("parent_command", payload)
        self.assertIsNone(payload["image"])
        self.assertIsNone(payload["parent_image"])
        self.assertIsNone(payload["parent_command"])

        fixture = CorpusFixture(
            fixture_id="fix-1",
            label="benign",
            command="whoami",
        )
        self.assertIsNone(fixture.image)
        self.assertIsNone(fixture.parent_image)
        self.assertIsNone(fixture.parent_command)

    def test_lineage_explicit_population_and_serialization(self):
        rec = IngestionRecord(
            source_id="siem:1",
            raw_input="{}",
            command_text="cmd.exe /c whoami",
            image="C:\\Windows\\System32\\cmd.exe",
            parent_image="C:\\Program Files\\App\\worker.exe",
            parent_command="worker.exe --run",
        )
        self.assertEqual(rec.image, "C:\\Windows\\System32\\cmd.exe")
        self.assertEqual(rec.parent_image, "C:\\Program Files\\App\\worker.exe")
        self.assertEqual(rec.parent_command, "worker.exe --run")

        dag = UnpackingDAG(
            root_id="node_0",
            nodes={"node_0": PayloadNode(node_id="node_0", text="cmd.exe /c whoami", depth=0)},
            primary_leaf_id="node_0",
        )
        verdict = TriageVerdict(
            source_id="siem:1",
            original_command="cmd.exe /c whoami",
            primary_unmasked_payload="cmd.exe /c whoami",
            dag=dag,
            severity=Severity.BENIGN,
            image="C:\\Windows\\System32\\cmd.exe",
            parent_image="C:\\Program Files\\App\\worker.exe",
            parent_command="worker.exe --run",
        )
        payload = verdict.to_dict()
        self.assertEqual(payload["image"], "C:\\Windows\\System32\\cmd.exe")
        self.assertEqual(payload["parent_image"], "C:\\Program Files\\App\\worker.exe")
        self.assertEqual(payload["parent_command"], "worker.exe --run")

        fixture = CorpusFixture(
            fixture_id="fix-2",
            label="benign",
            command="cmd.exe /c whoami",
            image="C:\\Windows\\System32\\cmd.exe",
            parent_image="C:\\Windows\\explorer.exe",
            parent_command="explorer.exe",
        )
        fdict = fixture.to_dict()
        self.assertEqual(fdict["image"], "C:\\Windows\\System32\\cmd.exe")
        self.assertEqual(fdict["parent_image"], "C:\\Windows\\explorer.exe")
        self.assertEqual(fdict["parent_command"], "explorer.exe")


class TestProcessLineageIngestionAndCli(unittest.TestCase):
    def test_ingest_sysmon_and_4688_json_records(self):
        records_data = [
            {
                "Image": "  C:\\Windows\\System32\\cmd.exe  ",
                "ParentImage": "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
                "ParentCommandLine": "  winword.exe /n doc.docx  ",
                "CommandLine": "cmd.exe /c whoami",
            },
            {
                "NewProcessName": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                "ParentProcessName": "C:\\Windows\\System32\\inetsrv\\w3wp.exe",
                "CommandLine": "powershell.exe -NoP -Command Get-Date",
            },
        ]
        with tempfile.TemporaryDirectory() as tmpdir:
            p = Path(tmpdir) / "eid.jsonl"
            p.write_text("\n".join(json.dumps(r) for r in records_data) + "\n", encoding="utf-8")
            recs = ingest_file(str(p))

        self.assertEqual(len(recs), 2)
        self.assertEqual(recs[0].image, "C:\\Windows\\System32\\cmd.exe")
        self.assertEqual(
            recs[0].parent_image,
            "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
        )
        self.assertEqual(recs[0].parent_command, "winword.exe /n doc.docx")

        self.assertEqual(
            recs[1].image,
            "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        )
        self.assertEqual(recs[1].parent_image, "C:\\Windows\\System32\\inetsrv\\w3wp.exe")
        self.assertIsNone(recs[1].parent_command)

    def test_ingest_ecs_wazuh_and_case_insensitive_variants(self):
        ecs_record = {
            "process": {
                "executable": "/bin/sh",
                "command_line": "sh -c id",
                "parent": {
                    "executable": "/usr/sbin/nginx",
                    "command_line": "nginx: worker process",
                },
            }
        }
        wazuh_record = {
            "data": {
                "win": {
                    "eventdata": {
                        "image": "C:\\Windows\\System32\\cmd.exe",
                        "parentImage": "C:\\Windows\\System32\\wbem\\WmiPrvSE.exe",
                        "parentCommandLine": "C:\\Windows\\System32\\wbem\\WmiPrvSE.exe -secured",
                        "commandLine": "cmd.exe /c hostname",
                    }
                }
            }
        }
        camel_record = {
            "command_line": "whoami",
            "IMAGE": "C:\\Windows\\System32\\whoami.exe",
            "parentimage": "C:\\Windows\\explorer.exe",
            "parentCommand": "explorer.exe",
        }
        with tempfile.TemporaryDirectory() as tmpdir:
            p = Path(tmpdir) / "multi.json"
            p.write_text(json.dumps([ecs_record, wazuh_record, camel_record]), encoding="utf-8")
            recs = ingest_file(str(p))

        self.assertEqual(recs[0].image, "/bin/sh")
        self.assertEqual(recs[0].parent_image, "/usr/sbin/nginx")
        self.assertEqual(recs[0].parent_command, "nginx: worker process")

        self.assertEqual(recs[1].image, "C:\\Windows\\System32\\cmd.exe")
        self.assertEqual(recs[1].parent_image, "C:\\Windows\\System32\\wbem\\WmiPrvSE.exe")
        self.assertEqual(
            recs[1].parent_command,
            "C:\\Windows\\System32\\wbem\\WmiPrvSE.exe -secured",
        )

        self.assertEqual(recs[2].image, "C:\\Windows\\System32\\whoami.exe")
        self.assertEqual(recs[2].parent_image, "C:\\Windows\\explorer.exe")
        self.assertEqual(recs[2].parent_command, "explorer.exe")

    def test_malformed_null_empty_lineage_normalizes_to_none(self):
        malformed = {
            "CommandLine": "dir C:\\",
            "Image": None,
            "ParentImage": "   ",
            "ParentCommandLine": ["not", "a", "string"],
        }
        with tempfile.TemporaryDirectory() as tmpdir:
            p = Path(tmpdir) / "bad_lineage.jsonl"
            p.write_text(json.dumps(malformed) + "\n", encoding="utf-8")
            recs = ingest_file(str(p))

        self.assertEqual(len(recs), 1)
        self.assertEqual(recs[0].command_text, "dir C:\\")
        self.assertIsNone(recs[0].image)
        self.assertIsNone(recs[0].parent_image)
        self.assertIsNone(recs[0].parent_command)

    def test_ingest_single_unmask_corpus_and_cli_parent_flags(self):
        rec = ingest_single_command(
            "whoami",
            image="  C:\\Windows\\System32\\whoami.exe ",
            parent_image="  C:\\Windows\\System32\\cmd.exe ",
            parent_command="   ",
        )
        self.assertEqual(rec.image, "C:\\Windows\\System32\\whoami.exe")
        self.assertEqual(rec.parent_image, "C:\\Windows\\System32\\cmd.exe")
        self.assertIsNone(rec.parent_command)

        verdict = unmask_command(
            "whoami",
            image=rec.image,
            parent_image=rec.parent_image,
            parent_command=rec.parent_command,
        )
        self.assertEqual(verdict.image, "C:\\Windows\\System32\\whoami.exe")
        self.assertEqual(verdict.parent_image, "C:\\Windows\\System32\\cmd.exe")
        self.assertIsNone(verdict.parent_command)

        fixture = parse_corpus_record(
            {
                "fixture_id": "lin-1",
                "label": "benign",
                "command": "whoami",
                "parent_image": "explorer.exe",
                "image": "",
            }
        )
        self.assertEqual(fixture.parent_image, "explorer.exe")
        self.assertIsNone(fixture.image)
        self.assertIsNone(fixture.parent_command)

        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = cli_main(
                [
                    "-c",
                    "cmd.exe /c whoami",
                    "--parent",
                    "winword.exe",
                    "--parent-cmd",
                    "winword.exe report.docx",
                    "--image",
                    "C:\\Windows\\System32\\cmd.exe",
                    "--format",
                    "json",
                ]
            )
        self.assertEqual(rc, 0)
        out = json.loads(buf.getvalue())
        self.assertEqual(out["parent_image"], "winword.exe")
        self.assertEqual(out["parent_command"], "winword.exe report.docx")
        self.assertEqual(out["image"], "C:\\Windows\\System32\\cmd.exe")


if __name__ == "__main__":
    unittest.main()
