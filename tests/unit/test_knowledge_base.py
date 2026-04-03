from __future__ import annotations

from pathlib import Path

import pytest

from aion.knowledge_base import KnowledgeBase
from aion.models import ContextProfile, Incident, VerificationResult, PatchArtifact


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_incident(
    issue_type: str = "hardcoded_secret",
    severity: str = "critical",
    strategy: str = "env_secret",
) -> Incident:
    return Incident(
        id=f"{issue_type}-001",
        target_file="app.py",
        issue_type=issue_type,
        issue="test incident",
        severity=severity,
        line=1,
        confidence=0.95,
        remediation_strategy=strategy,
    )


def _make_verification(verdict: str = "verified_fix") -> VerificationResult:
    artifact = PatchArtifact(
        target_file="app.py",
        original_content="SECRET = 'abc'",
        patched_content='import os\nSECRET = os.getenv("SECRET", "")',
        diff="",
    )
    return VerificationResult(
        artifact=artifact,
        verdict=verdict,
        syntax_ok=True,
        semgrep_ok=True,
        assertions_ok=True,
    )


# ---------------------------------------------------------------------------
# record_success
# ---------------------------------------------------------------------------


def test_record_success_creates_pattern(tmp_path: Path) -> None:
    kb = KnowledgeBase(base_dir=tmp_path / "kb")
    incident = _make_incident()
    verification = _make_verification()

    pattern = kb.record_success(incident, verification)

    assert pattern.issue_type == "hardcoded_secret"
    assert pattern.strategy == "env_secret"
    assert pattern.success_count == 1
    assert pattern.failure_count == 0


def test_record_success_increments_existing_pattern(tmp_path: Path) -> None:
    kb = KnowledgeBase(base_dir=tmp_path / "kb")
    incident = _make_incident()
    verification = _make_verification()

    kb.record_success(incident, verification)
    pattern = kb.record_success(incident, verification)

    assert pattern.success_count == 2


def test_record_success_persists_to_disk(tmp_path: Path) -> None:
    kb_dir = tmp_path / "kb"
    kb = KnowledgeBase(base_dir=kb_dir)
    kb.record_success(_make_incident(), _make_verification())

    assert (kb_dir / "patterns.json").exists()


def test_patterns_reload_from_disk(tmp_path: Path) -> None:
    kb_dir = tmp_path / "kb"
    kb1 = KnowledgeBase(base_dir=kb_dir)
    kb1.record_success(_make_incident(), _make_verification())

    # A fresh instance should read the persisted data.
    kb2 = KnowledgeBase(base_dir=kb_dir)
    patterns = kb2.get_patterns("hardcoded_secret")

    assert len(patterns) == 1
    assert patterns[0].success_count == 1


# ---------------------------------------------------------------------------
# record_failure
# ---------------------------------------------------------------------------


def test_record_failure_increments_failure_count(tmp_path: Path) -> None:
    kb = KnowledgeBase(base_dir=tmp_path / "kb")
    incident = _make_incident()

    # Create initial pattern via success.
    kb.record_success(incident, _make_verification())
    kb.record_failure(incident)

    patterns = kb.get_patterns("hardcoded_secret")
    assert patterns[0].failure_count == 1


def test_record_failure_unknown_incident_is_noop(tmp_path: Path) -> None:
    kb = KnowledgeBase(base_dir=tmp_path / "kb")
    # Should not raise; no pattern exists for this type.
    kb.record_failure(_make_incident(issue_type="unknown_type"))
    assert kb.get_patterns("unknown_type") == []


# ---------------------------------------------------------------------------
# confidence_boost
# ---------------------------------------------------------------------------


def test_confidence_boost_zero_when_no_history(tmp_path: Path) -> None:
    kb = KnowledgeBase(base_dir=tmp_path / "kb")
    assert kb.confidence_boost(_make_incident()) == 0.0


def test_confidence_boost_positive_after_success(tmp_path: Path) -> None:
    kb = KnowledgeBase(base_dir=tmp_path / "kb")
    incident = _make_incident()
    kb.record_success(incident, _make_verification())

    boost = kb.confidence_boost(incident)
    assert boost > 0.0


def test_confidence_boost_lower_after_failure(tmp_path: Path) -> None:
    kb = KnowledgeBase(base_dir=tmp_path / "kb")
    incident = _make_incident()
    kb.record_success(incident, _make_verification())
    boost_before = kb.confidence_boost(incident)

    kb.record_failure(incident)
    boost_after = kb.confidence_boost(incident)

    assert boost_after < boost_before


# ---------------------------------------------------------------------------
# summary
# ---------------------------------------------------------------------------


def test_summary_empty(tmp_path: Path) -> None:
    kb = KnowledgeBase(base_dir=tmp_path / "kb")
    summary = kb.summary()
    assert summary["total_patterns"] == 0
    assert summary["patterns"] == []


def test_summary_reflects_recorded_patterns(tmp_path: Path) -> None:
    kb = KnowledgeBase(base_dir=tmp_path / "kb")
    for issue_type, strategy in [
        ("hardcoded_secret", "env_secret"),
        ("insecure_yaml_load", "safe_yaml_load"),
    ]:
        kb.record_success(
            _make_incident(issue_type=issue_type, strategy=strategy),
            _make_verification(),
        )

    summary = kb.summary()
    assert summary["total_patterns"] == 2


# ---------------------------------------------------------------------------
# Integration: KnowledgeBase with RepairExecutor
# ---------------------------------------------------------------------------


def test_repair_executor_records_success_in_knowledge_base(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("aion.repair.semgrep_available", lambda: False)

    from aion.repair import RepairExecutor

    kb = KnowledgeBase(base_dir=tmp_path / "kb")
    executor = RepairExecutor(knowledge_base=kb)

    target = Path("tests/fixtures/vulnerable/02_hardcoded_secret.py")
    context = ContextProfile()

    record = executor.run(target, context, verify=True)

    assert record.verification is not None
    assert record.verification.verdict == "verified_fix"
    patterns = kb.get_patterns("hardcoded_secret")
    assert len(patterns) == 1
    assert patterns[0].success_count == 1
