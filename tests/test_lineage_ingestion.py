import unittest

from cmd_unmask.models import (
    CorpusFixture,
    IngestionRecord,
    PayloadNode,
    Severity,
    TriageVerdict,
    UnpackingDAG,
)


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


if __name__ == "__main__":
    unittest.main()
