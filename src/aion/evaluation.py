from __future__ import annotations

import json
from dataclasses import asdict
from dataclasses import dataclass
from pathlib import Path

from .llm_analyzer import LLMAnalyzer, LLMAnalyzerError
from .models import ContextProfile, Finding, RepairAttemptRecord, SemgrepFinding
from .repair import RepairExecutor
from .risk_heuristics import fallback_reasons
from .semgrep_runner import SemgrepError, SemgrepRunner, semgrep_available


@dataclass(frozen=True)
class FixtureCase:
    relative_path: str
    source_path: Path
    context_path: Path
    has_vuln: bool
    expected_context_gap: str


@dataclass(frozen=True)
class FixturePrediction:
    case: FixtureCase
    findings: list[Finding]
    semgrep_findings: list[SemgrepFinding]
    used_semgrep: bool

    @property
    def predicted_vulnerable(self) -> bool:
        return bool(self.findings)


@dataclass(frozen=True)
class EvalMetrics:
    true_positive: int
    false_positive: int
    true_negative: int
    false_negative: int

    @property
    def precision(self) -> float:
        denominator = self.true_positive + self.false_positive
        return self.true_positive / denominator if denominator else 1.0

    @property
    def recall(self) -> float:
        denominator = self.true_positive + self.false_negative
        return self.true_positive / denominator if denominator else 1.0


@dataclass(frozen=True)
class RepairFixtureResult:
    case: FixtureCase
    record: RepairAttemptRecord

    @property
    def artifact_generated(self) -> bool:
        return self.record.artifact is not None

    @property
    def verification_passed(self) -> bool:
        return self.record.verification is not None and self.record.verification.verdict == "verified_fix"

    @property
    def rolled_back(self) -> bool:
        return self.record.verification is not None and self.record.verification.verdict == "unsafe_patch"


@dataclass(frozen=True)
class RepairEvalMetrics:
    vulnerable_total: int
    safe_total: int
    repair_success_count: int
    verification_pass_count: int
    false_fix_count: int
    rollback_count: int

    @property
    def repair_success_rate(self) -> float:
        return self.repair_success_count / self.vulnerable_total if self.vulnerable_total else 1.0

    @property
    def verification_pass_rate(self) -> float:
        return self.verification_pass_count / self.vulnerable_total if self.vulnerable_total else 1.0

    @property
    def false_fix_rate(self) -> float:
        return self.false_fix_count / self.safe_total if self.safe_total else 0.0

    @property
    def rollback_rate(self) -> float:
        return self.rollback_count / self.vulnerable_total if self.vulnerable_total else 0.0

    def summary_payload(self) -> dict[str, int | float]:
        payload = asdict(self)
        payload.update(
            {
                "repair_success_rate": self.repair_success_rate,
                "verification_pass_rate": self.verification_pass_rate,
                "false_fix_rate": self.false_fix_rate,
                "rollback_rate": self.rollback_rate,
            }
        )
        return payload


def load_fixture_cases(fixtures_root: Path) -> list[FixtureCase]:
    labels = json.loads((fixtures_root / "labels.json").read_text(encoding="utf-8"))
    cases: list[FixtureCase] = []
    for relative_path, metadata in sorted(labels.items()):
        source_path = fixtures_root / relative_path
        prefix = source_path.name.split("_", 1)[0]
        context_path = source_path.with_name(f"{prefix}_context.json")
        cases.append(
            FixtureCase(
                relative_path=relative_path,
                source_path=source_path,
                context_path=context_path,
                has_vuln=bool(metadata["has_vuln"]),
                expected_context_gap=str(metadata["expected_context_gap"]),
            )
        )
    return cases


def load_context_profile(context_path: Path) -> ContextProfile:
    payload = json.loads(context_path.read_text(encoding="utf-8"))
    return ContextProfile(**payload)


def evaluate_cases(
    cases: list[FixtureCase],
    api_key: str,
    model: str = "claude-3-5-sonnet-latest",
    provider: str = "anthropic",
    ignore_llm_errors: bool = True,
) -> list[FixturePrediction]:
    analyzer = LLMAnalyzer(api_key=api_key, model=model, provider=provider)
    runner = SemgrepRunner()
    use_semgrep = semgrep_available()
    predictions: list[FixturePrediction] = []

    for case in cases:
        context_profile = load_context_profile(case.context_path)
        semgrep_findings: list[SemgrepFinding] = []
        if use_semgrep:
            try:
                semgrep_findings = runner.run(case.source_path)
            except SemgrepError:
                semgrep_findings = []

        try:
            reasons = fallback_reasons(case.source_path, context_profile)
            if use_semgrep and not semgrep_findings and not reasons:
                findings = []
            else:
                findings = analyzer.analyze(
                    case.source_path,
                    context_profile,
                    semgrep_findings,
                    fallback_signals=reasons,
                )
        except LLMAnalyzerError:
            if not ignore_llm_errors:
                raise
            findings = []

        predictions.append(
            FixturePrediction(
                case=case,
                findings=findings,
                semgrep_findings=semgrep_findings,
                used_semgrep=use_semgrep,
            )
        )
    return predictions


def compute_metrics(predictions: list[FixturePrediction]) -> EvalMetrics:
    true_positive = false_positive = true_negative = false_negative = 0
    for prediction in predictions:
        actual = prediction.case.has_vuln
        predicted = prediction.predicted_vulnerable
        if actual and predicted:
            true_positive += 1
        elif actual and not predicted:
            false_negative += 1
        elif not actual and predicted:
            false_positive += 1
        else:
            true_negative += 1
    return EvalMetrics(
        true_positive=true_positive,
        false_positive=false_positive,
        true_negative=true_negative,
        false_negative=false_negative,
    )


def evaluate_repair_cases(
    cases: list[FixtureCase],
    verify: bool = True,
    records_dir: Path | None = None,
) -> list[RepairFixtureResult]:
    executor = RepairExecutor()
    results: list[RepairFixtureResult] = []

    for case in cases:
        context_profile = load_context_profile(case.context_path)
        record = executor.run(case.source_path, context_profile, verify=verify)
        if records_dir is not None:
            output_path = records_dir / f"{case.relative_path.replace('/', '__')}.json"
            executor.write_record(record, output_path)
        results.append(RepairFixtureResult(case=case, record=record))
    return results


def compute_repair_metrics(results: list[RepairFixtureResult]) -> RepairEvalMetrics:
    vulnerable_total = sum(1 for result in results if result.case.has_vuln)
    safe_total = sum(1 for result in results if not result.case.has_vuln)
    repair_success_count = sum(1 for result in results if result.case.has_vuln and result.artifact_generated)
    verification_pass_count = sum(1 for result in results if result.case.has_vuln and result.verification_passed)
    false_fix_count = sum(1 for result in results if not result.case.has_vuln and result.artifact_generated)
    rollback_count = sum(1 for result in results if result.case.has_vuln and result.rolled_back)
    return RepairEvalMetrics(
        vulnerable_total=vulnerable_total,
        safe_total=safe_total,
        repair_success_count=repair_success_count,
        verification_pass_count=verification_pass_count,
        false_fix_count=false_fix_count,
        rollback_count=rollback_count,
    )
