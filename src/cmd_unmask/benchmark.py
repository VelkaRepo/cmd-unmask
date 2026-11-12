"""Regression Corpus benchmark runner, metrics calculator, and pretty renderer."""

from __future__ import annotations

import math
import time
from pathlib import Path

from cmd_unmask.corpus import load_corpus_file, load_seed_corpus
from cmd_unmask.models import (
    BenchmarkReport,
    CorpusFixture,
    FixtureResult,
    Severity,
    TriageConfig,
)
from cmd_unmask.renderer import render_benchmark_summary
from cmd_unmask.unpacker import unmask_command


def load_corpus(path: str | Path | None = None) -> list[CorpusFixture]:
    """Load the built-in seed corpus or a custom JSON/JSONL corpus file."""
    if path is None:
        return load_seed_corpus()
    return load_corpus_file(path)


def compute_percentile(values: list[float], percentile: float) -> float:
    """Compute a linear-interpolated percentile over a list of numeric samples."""
    if not values:
        return 0.0
    ordered = sorted(values)
    if len(ordered) == 1:
        return float(ordered[0])
    rank = (percentile / 100.0) * (len(ordered) - 1)
    lower = math.floor(rank)
    upper = math.ceil(rank)
    if lower == upper:
        return float(ordered[lower])
    fraction = rank - lower
    return float(ordered[lower] + (ordered[upper] - ordered[lower]) * fraction)


def evaluate_fixture(
    fixture: CorpusFixture,
    config: TriageConfig | None = None,
) -> FixtureResult:
    """Execute unmask_command on a single CorpusFixture and verify all assertions."""
    cfg = config or TriageConfig()
    start = time.perf_counter()
    try:
        verdict = unmask_command(fixture.command, config=cfg, source_id=fixture.fixture_id)
    except Exception as exc:  # Defensive isolation for malformed/edge inputs
        elapsed_ms = (time.perf_counter() - start) * 1000.0
        return FixtureResult(
            fixture_id=fixture.fixture_id,
            label=fixture.label,
            passed=False,
            actual_severity=Severity.UNKNOWN,
            actual_risk_score=0,
            latency_ms=elapsed_ms,
            failures=[f"Unhandled exception during unmask_command: {exc}"],
        )
    elapsed_ms = (time.perf_counter() - start) * 1000.0

    failures: list[str] = []
    actual_sev = verdict.severity

    if fixture.expected_severity is not None and actual_sev != fixture.expected_severity:
        failures.append(
            f"expected_severity={fixture.expected_severity.value}, got={actual_sev.value}"
        )
    if fixture.min_severity is not None and actual_sev.rank < fixture.min_severity.rank:
        failures.append(
            f"min_severity={fixture.min_severity.value}, got={actual_sev.value}"
        )
    if fixture.max_severity is not None and actual_sev.rank > fixture.max_severity.rank:
        failures.append(
            f"max_severity={fixture.max_severity.value}, got={actual_sev.value}"
        )

    matched_techniques = {m.mitre_id for m in verdict.behavioral_matches}
    for tech in fixture.expected_techniques:
        if tech not in matched_techniques:
            failures.append(f"missing expected technique: {tech}")

    ioc_values = [ioc.raw_value for ioc in verdict.iocs] + [
        ioc.defanged_value for ioc in verdict.iocs
    ]
    for expected_ioc in fixture.expected_iocs:
        if not any(expected_ioc in val for val in ioc_values):
            failures.append(f"missing expected IOC: {expected_ioc}")

    matched_rule_ids = {m.rule_id for m in verdict.behavioral_matches}
    for forbidden in fixture.must_not_match:
        if forbidden in matched_rule_ids or any(forbidden in val for val in ioc_values):
            failures.append(f"must_not_match triggered: {forbidden}")

    return FixtureResult(
        fixture_id=fixture.fixture_id,
        label=fixture.label,
        passed=len(failures) == 0,
        actual_severity=actual_sev,
        actual_risk_score=verdict.risk_score,
        latency_ms=elapsed_ms,
        failures=failures,
    )


def run_benchmark(
    fixtures: list[CorpusFixture],
    config: TriageConfig | None = None,
) -> BenchmarkReport:
    """Run all fixtures through unmask_command and compute Detection Rigidity metrics."""
    cfg = config or TriageConfig()
    results: list[FixtureResult] = []
    tp = fp = fn = tn = 0

    for fixture in fixtures:
        res = evaluate_fixture(fixture, config=cfg)
        results.append(res)
        predicted_positive = res.actual_severity.rank >= Severity.LOW.rank
        if fixture.label == "malicious":
            if predicted_positive:
                tp += 1
            else:
                fn += 1
        else:
            if predicted_positive:
                fp += 1
            else:
                tn += 1

    total = len(results)
    passed = sum(1 for r in results if r.passed)
    failed = total - passed

    precision = (tp / (tp + fp)) if (tp + fp) > 0 else 0.0
    recall = (tp / (tp + fn)) if (tp + fn) > 0 else 0.0
    f1_score = (
        (2.0 * precision * recall / (precision + recall))
        if (precision + recall) > 0
        else 0.0
    )
    fpr = (fp / (fp + tn)) if (fp + tn) > 0 else 0.0

    latencies = [r.latency_ms for r in results]
    p50_ms = compute_percentile(latencies, 50.0)
    p95_ms = compute_percentile(latencies, 95.0)

    return BenchmarkReport(
        total=total,
        passed=passed,
        failed=failed,
        true_positives=tp,
        false_positives=fp,
        false_negatives=fn,
        true_negatives=tn,
        precision=precision,
        recall=recall,
        fpr=fpr,
        p50_ms=p50_ms,
        p95_ms=p95_ms,
        f1_score=f1_score,
        results=results,
    )


def render_benchmark_pretty(report: BenchmarkReport, no_color: bool = False) -> str:
    """Render a concise terminal summary of the BenchmarkReport."""
    return render_benchmark_summary(report, color=not no_color)
