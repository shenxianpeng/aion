import json
import os
from pathlib import Path

import pytest

from aion.evaluation import compute_metrics, evaluate_cases, load_fixture_cases


def _resolve_eval_provider() -> tuple[str, str]:
    if os.getenv("OPENAI_API_KEY"):
        return "openai", os.environ["OPENAI_API_KEY"]
    if os.getenv("ANTHROPIC_API_KEY"):
        return "anthropic", os.environ["ANTHROPIC_API_KEY"]
    pytest.skip("OPENAI_API_KEY or ANTHROPIC_API_KEY is required for live eval tests")


def _default_model_for_provider(provider: str) -> str:
    if provider == "openai":
        return "gpt-4.1"
    return "claude-3-5-sonnet-latest"


@pytest.mark.eval
def test_fixture_labels_are_loadable() -> None:
    fixtures_root = Path("tests/fixtures")
    labels = json.loads((fixtures_root / "labels.json").read_text(encoding="utf-8"))
    assert labels


@pytest.mark.eval
def test_raw_sqlite3_demo() -> None:
    provider, api_key = _resolve_eval_provider()

    fixtures_root = Path("tests/fixtures")
    cases = [case for case in load_fixture_cases(fixtures_root) if case.relative_path == "vulnerable/01_raw_sqlite3.py"]

    predictions = evaluate_cases(
        cases,
        api_key=api_key,
        provider=provider,
        model=_default_model_for_provider(provider),
        ignore_llm_errors=False,
    )

    assert len(predictions) == 1
    assert predictions[0].findings
    assert any("sqlalchemy" in finding.context_gap.lower() for finding in predictions[0].findings)


@pytest.mark.eval
def test_quality_thresholds() -> None:
    provider, api_key = _resolve_eval_provider()

    fixtures_root = Path("tests/fixtures")
    cases = load_fixture_cases(fixtures_root)
    predictions = evaluate_cases(
        cases,
        api_key=api_key,
        provider=provider,
        model=_default_model_for_provider(provider),
        ignore_llm_errors=False,
    )
    metrics = compute_metrics(predictions)

    assert metrics.precision >= 0.70
    assert metrics.recall >= 0.60
