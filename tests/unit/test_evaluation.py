from pathlib import Path

from aion.evaluation import (
    FixtureCase,
    FixturePrediction,
    compute_metrics,
    compute_repair_metrics,
    evaluate_repair_cases,
    load_fixture_cases,
)
from aion.models import Finding


def test_load_fixture_cases_reads_labels() -> None:
    cases = load_fixture_cases(Path("tests/fixtures"))

    assert cases
    assert cases[0].source_path.exists()
    assert cases[0].context_path.exists()


def test_compute_metrics_counts_predictions() -> None:
    vulnerable_case = FixtureCase(
        relative_path="vulnerable/demo.py",
        source_path=Path("vulnerable/demo.py"),
        context_path=Path("vulnerable/demo_context.json"),
        has_vuln=True,
        expected_context_gap="sqlalchemy",
    )
    safe_case = FixtureCase(
        relative_path="safe/demo.py",
        source_path=Path("safe/demo.py"),
        context_path=Path("safe/demo_context.json"),
        has_vuln=False,
        expected_context_gap="",
    )

    metrics = compute_metrics(
        [
            FixturePrediction(
                case=vulnerable_case,
                findings=[
                    Finding(
                        issue="demo",
                        severity="high",
                        line=1,
                        context_gap="Project uses sqlalchemy",
                        fix="Use the ORM",
                        semgrep_rule=None,
                    )
                ],
                semgrep_findings=[],
                used_semgrep=False,
            ),
            FixturePrediction(
                case=safe_case,
                findings=[],
                semgrep_findings=[],
                used_semgrep=False,
            ),
        ]
    )

    assert metrics.true_positive == 1
    assert metrics.true_negative == 1
    assert metrics.false_positive == 0
    assert metrics.false_negative == 0
    assert metrics.precision == 1.0
    assert metrics.recall == 1.0


def test_compute_repair_metrics_counts_results(monkeypatch) -> None:
    monkeypatch.setattr("aion.repair.semgrep_available", lambda: False)
    cases = load_fixture_cases(Path("tests/fixtures"))

    results = evaluate_repair_cases(cases, verify=True)
    metrics = compute_repair_metrics(results)

    assert metrics.vulnerable_total == 5
    assert metrics.safe_total == 5
    assert metrics.repair_success_count == 5
    assert metrics.verification_pass_count == 5
    assert metrics.false_fix_count == 0
    assert metrics.rollback_count == 0
    assert metrics.repair_success_rate == 1.0
    assert metrics.verification_pass_rate == 1.0
    assert metrics.false_fix_rate == 0.0
    assert metrics.rollback_rate == 0.0
