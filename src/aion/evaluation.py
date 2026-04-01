from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from .llm_analyzer import LLMAnalyzer, LLMAnalyzerError
from .models import ContextProfile, Finding, SemgrepFinding
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
