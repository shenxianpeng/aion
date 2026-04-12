"""End-to-end scenario tests for AION.

Each test function is a self-contained walkthrough of one realistic usage scenario.
Together they cover every major capability of the AION control plane and serve as
executable examples for users learning the project.

Run without LLM keys:
    uv run pytest tests/e2e/ -v
    # or without uv:
    python3 -m pytest tests/e2e/ -v

No external API calls are made; semgrep is disabled via monkeypatch.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from aion.config import AppConfig
from aion.defense import RuntimeDefensePlanner
from aion.drift_detector import DriftDetector
from aion.inbox import EventInbox
from aion.knowledge_base import KnowledgeBase
from aion.models import ContextProfile, Incident, OrchestrationEvent, PatchArtifact, VerificationResult
from aion.orchestrator import Orchestrator, PolicyEngine, SandboxExecutor
from aion.release_manager import ReleaseManager
from aion.repair import IncidentDetector, PatchGenerator, Verifier

# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

FIXTURES = Path("tests/fixtures")
VULN = FIXTURES / "vulnerable"
SAFE = FIXTURES / "safe"


def _ctx(name: str) -> ContextProfile:
    return ContextProfile(**json.loads((VULN / name).read_text(encoding="utf-8")))


def _safe_ctx(name: str) -> ContextProfile:
    return ContextProfile(**json.loads((SAFE / name).read_text(encoding="utf-8")))


# ---------------------------------------------------------------------------
# Scenario 1 — Single-file repair lifecycle
#
# Demonstrates the fundamental AION repair loop for a raw SQL injection:
#   1. Detect the incident from source code
#   2. Generate a deterministic patch artifact
#   3. Verify the patch (syntax + assertion checks)
#   4. Drive the full flow through the Orchestrator in one call
# ---------------------------------------------------------------------------


def test_scenario_single_file_repair_lifecycle(monkeypatch: pytest.MonkeyPatch) -> None:
    """Complete repair lifecycle for a raw SQLite injection vulnerability.

    Example usage::

        from aion.repair import IncidentDetector, PatchGenerator, Verifier
        from aion.models import ContextProfile
        from pathlib import Path

        context = ContextProfile()
        target  = Path("app.py")  # contains f-string SQL

        incidents = IncidentDetector().detect(target, context)
        artifact  = PatchGenerator().generate(target, incidents, context)
        result    = Verifier().verify(artifact)
        print(result.verdict)  # "verified_fix"
    """
    monkeypatch.setattr("aion.repair.semgrep_available", lambda: False)

    target = VULN / "01_raw_sqlite3.py"
    context = _ctx("01_context.json")

    # Step 1 – detect
    incidents = IncidentDetector().detect(target, context)
    assert len(incidents) >= 1
    assert incidents[0].issue_type == "raw_sqlite_query"
    assert incidents[0].remediation_strategy == "parameterize_sqlite_query"

    # Step 2 – generate patch
    artifact = PatchGenerator().generate(target, incidents, context)
    assert artifact is not None
    assert artifact.static_validation_passed is True

    # Step 3 – verify
    result = Verifier().verify(artifact)
    assert result.verdict == "verified_fix"
    assert result.syntax_ok is True
    assert result.assertions_ok is True

    # Step 4 – end-to-end via Orchestrator
    orch = Orchestrator()
    run_result = orch.run_incident(target, context)
    assert run_result.verification is not None
    assert run_result.verification.verdict == "verified_fix"


# ---------------------------------------------------------------------------
# Scenario 2 — All 8 vulnerability types
#
# Each vulnerability fixture is detected, patched, and verified end-to-end.
# This confirms that every built-in remediation template produces a verified fix.
# ---------------------------------------------------------------------------

_VULN_CASES = [
    ("01_raw_sqlite3.py",        "01_context.json", "parameterize_sqlite_query"),
    ("02_hardcoded_secret.py",   "02_context.json", "env_secret"),
    ("03_missing_auth_decorator.py", "03_context.json", "inject_auth_decorator"),
    ("04_insecure_yaml_load.py", "04_context.json", "safe_yaml_load"),
    ("05_command_injection.py",  "05_context.json", "shlex_quote_command"),
    ("06_eval_injection.py",     "06_context.json", "ast_literal_eval"),
    ("07_subprocess_injection.py", "07_context.json", "shlex_quote_subprocess"),
    ("08_weak_cryptography.py",  "08_context.json", "upgrade_hash_algorithm"),
]


@pytest.mark.parametrize(("source", "ctx_file", "strategy"), _VULN_CASES)
def test_scenario_all_vulnerability_types(
    monkeypatch: pytest.MonkeyPatch,
    source: str,
    ctx_file: str,
    strategy: str,
) -> None:
    """Every built-in vulnerability type produces a verified fix.

    Example usage::

        # The same three-step pattern works for all 8 issue types.
        incidents = IncidentDetector().detect(target, context)
        artifact  = PatchGenerator().generate(target, incidents, context)
        result    = Verifier().verify(artifact)
        assert result.verdict == "verified_fix"
    """
    monkeypatch.setattr("aion.repair.semgrep_available", lambda: False)

    target = VULN / source
    context = _ctx(ctx_file)

    incidents = IncidentDetector().detect(target, context)
    assert incidents, f"Expected at least one incident in {source}"
    assert incidents[0].remediation_strategy == strategy

    artifact = PatchGenerator().generate(target, incidents, context)
    assert artifact is not None

    result = Verifier().verify(artifact)
    assert result.verdict == "verified_fix", f"{source}: {result.failure_reasons}"


# ---------------------------------------------------------------------------
# Scenario 3 — Policy gating
#
# The PolicyEngine decides whether a detected incident can be auto-repaired
# inside a sandbox or must go to human review.  Three sub-cases:
#   A) high confidence + known type → auto_repair_sandbox
#   B) low confidence + known type  → needs_human_review
#   C) unknown issue type           → needs_human_review
# ---------------------------------------------------------------------------


def _make_incident(
    issue_type: str = "hardcoded_secret",
    confidence: float = 0.95,
    strategy: str = "env_secret",
) -> Incident:
    return Incident(
        id=f"{issue_type}-e2e",
        target_file="service.py",
        issue_type=issue_type,
        issue="test incident for policy gating",
        severity="critical",
        line=1,
        confidence=confidence,
        remediation_strategy=strategy,
    )


def test_scenario_policy_gating_auto_repair() -> None:
    """High-confidence known issue type → auto_repair_sandbox.

    Example usage::

        engine = PolicyEngine()
        event  = OrchestrationEvent(event_id="e1", event_type="code_scan",
                                    target_file="service.py")
        decision = engine.decide(event, [incident])
        assert decision.action == "auto_repair_sandbox"
    """
    engine = PolicyEngine(min_confidence=0.85)
    event = OrchestrationEvent(event_id="e1", event_type="code_scan", target_file="service.py")
    incident = _make_incident(confidence=0.95)

    decision = engine.decide(event, [incident])

    assert decision.action == "auto_repair_sandbox"
    assert decision.sandbox_required is True
    assert incident.id in decision.approved_incident_ids


def test_scenario_policy_gating_low_confidence() -> None:
    """Low-confidence incident stays in human review even when type is approved.

    Example usage::

        # Set a higher threshold or lower confidence to force human review.
        engine = PolicyEngine(min_confidence=0.90)
        decision = engine.decide(event, [low_confidence_incident])
        assert decision.action == "needs_human_review"
    """
    engine = PolicyEngine(min_confidence=0.90)
    event = OrchestrationEvent(event_id="e2", event_type="code_scan", target_file="service.py")
    incident = _make_incident(confidence=0.75)

    decision = engine.decide(event, [incident])

    assert decision.action == "needs_human_review"
    assert any("confidence" in r for r in decision.reasons)


def test_scenario_policy_gating_unknown_issue_type() -> None:
    """Unknown issue types are never auto-repaired regardless of confidence.

    Example usage::

        engine = PolicyEngine()
        incident = Incident(..., issue_type="custom_rule", confidence=1.0)
        decision = engine.decide(event, [incident])
        assert decision.action == "needs_human_review"
    """
    engine = PolicyEngine()
    event = OrchestrationEvent(event_id="e3", event_type="code_scan", target_file="service.py")
    incident = _make_incident(issue_type="custom_rule", confidence=1.0)

    decision = engine.decide(event, [incident])

    assert decision.action == "needs_human_review"
    assert any("not approved" in r for r in decision.reasons)


# ---------------------------------------------------------------------------
# Scenario 4 — Sandbox modes
#
# AION can stage a patch in a single-file workspace (fast) or copy the entire
# repository into a temporary directory and run verification commands against it.
#
#   A) File mode   — default, lightweight
#   B) Repository mode + passing command → approved_for_rollout
#   C) Repository mode + failing command → rollback
# ---------------------------------------------------------------------------


def test_scenario_sandbox_file_mode(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """File-mode sandbox: patch is staged and verified without copying the repo.

    Example usage::

        orchestrator = Orchestrator()  # defaults to file sandbox
        result = orchestrator.process_event(event, context)
        assert result.sandbox.mode == "file"
        assert result.sandbox.verification.verdict == "verified_fix"
    """
    monkeypatch.setattr("aion.repair.semgrep_available", lambda: False)
    target = (VULN / "02_hardcoded_secret.py").resolve()
    context = _ctx("02_context.json")

    orch = Orchestrator()
    event = orch.ingest_event({"event_type": "code_scan", "target_file": str(target)})
    result = orch.process_event(event, context)

    assert result.sandbox is not None
    assert result.sandbox.mode == "file"
    assert Path(result.sandbox.staged_target_file).exists()
    assert result.sandbox.verification is not None
    assert result.sandbox.verification.verdict == "verified_fix"

    orch.cleanup_sandbox(result)
    assert not Path(result.sandbox.workspace_root).exists()


def test_scenario_sandbox_repository_mode_approved(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Repository-mode sandbox with a passing command → approved_for_rollout.

    Example usage::

        orchestrator = Orchestrator.from_config(AppConfig(
            sandbox_mode="repository",
            sandbox_verification_commands=["python -m pytest tests/"],
            auto_approve_verified_fixes=True,
        ))
        result = orchestrator.process_event(event, context, repo_root=repo_root)
        assert result.sandbox.rollout.recommendation == "approved_for_rollout"
    """
    monkeypatch.setattr("aion.repair.semgrep_available", lambda: False)

    repo_root = tmp_path / "demo-repo"
    repo_root.mkdir()
    target = repo_root / "service.py"
    target.write_text((VULN / "02_hardcoded_secret.py").read_text(encoding="utf-8"), encoding="utf-8")
    (repo_root / "context.json").write_text(
        (VULN / "02_context.json").read_text(encoding="utf-8"), encoding="utf-8"
    )

    orch = Orchestrator.from_config(
        AppConfig(
            sandbox_mode="repository",
            sandbox_verification_commands=[f'{sys.executable} -c "print(\'sandbox-ok\')"'],
            auto_approve_verified_fixes=True,
        )
    )
    event = orch.ingest_event({
        "event_type": "runtime_alert",
        "target_file": str(target.resolve()),
        "metadata": {"repo_root": str(repo_root.resolve())},
    })
    context = ContextProfile(**json.loads((repo_root / "context.json").read_text(encoding="utf-8")))
    result = orch.process_event(event, context, repo_root=repo_root.resolve())

    assert result.sandbox is not None
    assert result.sandbox.mode == "repository"
    assert result.sandbox.command_results[0].passed is True
    assert result.sandbox.rollout is not None
    assert result.sandbox.rollout.recommendation == "approved_for_rollout"

    orch.cleanup_sandbox(result)


def test_scenario_sandbox_repository_mode_rollback(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Repository-mode sandbox with a failing command → rollback recommendation.

    Example usage::

        orchestrator = Orchestrator.from_config(AppConfig(
            sandbox_mode="repository",
            sandbox_verification_commands=["python -m pytest tests/ --strict"],
            rollback_on_verification_failure=True,
        ))
        result = orchestrator.process_event(event, context, repo_root=repo_root)
        assert result.sandbox.rollout.recommendation == "rollback"
    """
    monkeypatch.setattr("aion.repair.semgrep_available", lambda: False)

    repo_root = tmp_path / "rollback-repo"
    repo_root.mkdir()
    target = repo_root / "service.py"
    target.write_text((VULN / "01_raw_sqlite3.py").read_text(encoding="utf-8"), encoding="utf-8")
    (repo_root / "context.json").write_text(
        (VULN / "01_context.json").read_text(encoding="utf-8"), encoding="utf-8"
    )

    orch = Orchestrator.from_config(
        AppConfig(
            sandbox_mode="repository",
            sandbox_verification_commands=[f'{sys.executable} -c "import sys; sys.exit(1)"'],
            rollback_on_verification_failure=True,
        )
    )
    event = orch.ingest_event({
        "event_type": "runtime_alert",
        "target_file": str(target.resolve()),
        "metadata": {"repo_root": str(repo_root.resolve())},
    })
    context = ContextProfile(**json.loads((repo_root / "context.json").read_text(encoding="utf-8")))
    result = orch.process_event(event, context, repo_root=repo_root.resolve())

    assert result.sandbox is not None
    assert result.sandbox.command_results[0].passed is False
    assert result.sandbox.rollout is not None
    assert result.sandbox.rollout.recommendation == "rollback"

    orch.cleanup_sandbox(result)


# ---------------------------------------------------------------------------
# Scenario 5 — Event queue processing
#
# AION can process a list of OrchestrationEvent objects in a single call and
# return aggregate metrics.  This scenario exercises:
#   - one event that auto-repairs (high-confidence known type)
#   - one event that goes to human review (type not in approved set)
# ---------------------------------------------------------------------------


def test_scenario_event_queue_processing(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Process a mixed queue of events and inspect the summary metrics.

    The orchestrator is configured to auto-repair only ``hardcoded_secret``.
    - Event 1 targets a hardcoded-secret file → auto_repair_sandbox
    - Event 2 targets a raw-SQLite file       → needs_human_review

    Example usage::

        # Configure which issue types get automatic sandboxed repair.
        orch = Orchestrator.from_config(AppConfig(
            auto_repair_issue_types=["hardcoded_secret"],
            sandbox_mode="repository",
            sandbox_verification_commands=["python -m pytest tests/"],
            auto_approve_verified_fixes=True,
        ))

        results, summary = orch.process_event_queue(
            events,
            context_loader=lambda ev: load_context(ev),
            repo_root_loader=lambda ev: None,
        )
        print(summary.auto_repair_count, summary.human_review_count)
    """
    monkeypatch.setattr("aion.repair.semgrep_available", lambda: False)

    # Target 1: hardcoded_secret → will be auto-repaired
    auto_target = tmp_path / "secret_service.py"
    auto_target.write_text((VULN / "02_hardcoded_secret.py").read_text(encoding="utf-8"), encoding="utf-8")
    auto_context_path = tmp_path / "secret_context.json"
    auto_context_path.write_text((VULN / "02_context.json").read_text(encoding="utf-8"), encoding="utf-8")

    # Target 2: raw_sqlite_query → not in auto_repair_issue_types → human review
    review_target = tmp_path / "sqlite_service.py"
    review_target.write_text((VULN / "01_raw_sqlite3.py").read_text(encoding="utf-8"), encoding="utf-8")
    review_context_path = tmp_path / "sqlite_context.json"
    review_context_path.write_text((VULN / "01_context.json").read_text(encoding="utf-8"), encoding="utf-8")

    # Single orchestrator: only hardcoded_secret is approved for auto-repair
    orch = Orchestrator.from_config(
        AppConfig(
            auto_repair_issue_types=["hardcoded_secret"],
            sandbox_mode="file",
            auto_approve_verified_fixes=True,
        )
    )
    events = [
        orch.ingest_event({
            "event_type": "runtime_alert",
            "target_file": str(auto_target.resolve()),
            "metadata": {"context_file": str(auto_context_path.resolve())},
        }),
        orch.ingest_event({
            "event_type": "code_scan",
            "target_file": str(review_target.resolve()),
            "metadata": {"context_file": str(review_context_path.resolve())},
        }),
    ]

    def _load_context(event: OrchestrationEvent) -> ContextProfile:
        ctx_file = event.metadata.get("context_file")
        if ctx_file:
            return ContextProfile(**json.loads(Path(str(ctx_file)).read_text(encoding="utf-8")))
        return ContextProfile()

    results, summary = orch.process_event_queue(events, _load_context, lambda _: None)

    assert summary.total_events == 2
    assert summary.auto_repair_count == 1
    assert summary.human_review_count == 1
    assert summary.verified_count >= 1

    for result in results:
        orch.cleanup_sandbox(result)


# ---------------------------------------------------------------------------
# Scenario 6 — Drift detection lifecycle
#
# DriftDetector compares two point-in-time snapshots of a codebase to surface
# regressions (new vulnerabilities) and improvements (resolved vulnerabilities).
#
#   Phase A: baseline on safe code → health_score 1.0
#   Phase B: introduce vulnerability → regression detected
#   Phase C: fix the file → resolved incident detected
# ---------------------------------------------------------------------------


def test_scenario_drift_detection_lifecycle(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Full drift detection cycle: baseline → regression → resolution.

    Example usage::

        dd = DriftDetector(snapshots_dir=Path(".aion/snapshots"))

        baseline = dd.snapshot(src_dir, context)
        dd.save_snapshot(baseline, name="baseline")

        # … time passes, code changes …

        current = dd.snapshot(src_dir, context)
        report  = dd.compare(baseline, current)
        if report.has_regression:
            print("New incidents:", report.new_incidents)
    """
    monkeypatch.setattr("aion.repair.semgrep_available", lambda: False)

    safe_code = (SAFE / "01_orm_correct.py").read_text(encoding="utf-8")
    vuln_code = (VULN / "01_raw_sqlite3.py").read_text(encoding="utf-8")

    target = tmp_path / "app.py"
    target.write_text(safe_code, encoding="utf-8")

    dd = DriftDetector(snapshots_dir=tmp_path / "snaps")
    context = ContextProfile()

    # Phase A — baseline on clean code
    baseline = dd.snapshot(target, context)
    dd.save_snapshot(baseline, name="baseline")
    assert baseline.health_score == 1.0
    assert baseline.incidents == []

    loaded = dd.load_snapshot("baseline")
    assert loaded is not None
    assert loaded.health_score == 1.0

    # Phase B — introduce a vulnerability and detect regression
    target.write_text(vuln_code, encoding="utf-8")
    current = dd.snapshot(target, context)
    regression_report = dd.compare(baseline, current)

    assert regression_report.has_regression is True
    assert len(regression_report.new_incidents) >= 1
    assert regression_report.health_delta < 0
    assert str(target) in regression_report.regressed_files

    # Phase C — fix the file and detect resolution
    target.write_text(safe_code, encoding="utf-8")
    resolved = dd.snapshot(target, context)
    resolution_report = dd.compare(current, resolved)

    assert len(resolution_report.resolved_incidents) >= 1
    assert resolution_report.has_regression is False
    assert resolution_report.health_delta >= 0


# ---------------------------------------------------------------------------
# Scenario 7 — Self-evolving knowledge base
#
# The KnowledgeBase stores repair outcomes.  After enough successes the
# PolicyEngine receives a confidence boost that can tip a borderline incident
# from "needs_human_review" into "auto_repair_sandbox" — closing the
# self-evolving feedback loop.
# ---------------------------------------------------------------------------


def test_scenario_self_evolving_knowledge_base(tmp_path: Path) -> None:
    """Knowledge base accumulates repairs and boosts future policy decisions.

    Example usage::

        kb = KnowledgeBase(base_dir=Path(".aion/knowledge"))
        kb.record_success(incident, verification)  # after each verified fix
        boost = kb.confidence_boost(incident)

        engine = PolicyEngine(min_confidence=0.85, knowledge_base=kb)
        decision = engine.decide(event, [low_confidence_incident])
        # once enough successes are recorded, action becomes "auto_repair_sandbox"
    """
    kb = KnowledgeBase(base_dir=tmp_path / "knowledge")
    incident = _make_incident(issue_type="hardcoded_secret", confidence=0.80)
    event = OrchestrationEvent(event_id="kb-e2e", event_type="code_scan", target_file="service.py")

    # Without KB the borderline incident (0.80 < 0.85) triggers human review.
    engine_no_kb = PolicyEngine(min_confidence=0.85)
    assert engine_no_kb.decide(event, [incident]).action == "needs_human_review"

    # Record enough successful repairs to accumulate a meaningful boost.
    artifact = PatchArtifact(
        target_file="service.py",
        original_content="SECRET = 'abc'",
        patched_content='import os\nSECRET = os.getenv("SECRET", "")',
        diff="",
    )
    verification = VerificationResult(
        artifact=artifact, verdict="verified_fix",
        syntax_ok=True, semgrep_ok=True, assertions_ok=True,
    )
    for _ in range(10):
        kb.record_success(incident, verification)

    assert kb.confidence_boost(incident) > 0

    # KB patterns are persisted to disk and survive re-instantiation.
    kb2 = KnowledgeBase(base_dir=tmp_path / "knowledge")
    assert kb2.confidence_boost(incident) > 0

    # Patterns are isolated by issue type: a different type gets no boost.
    other_incident = _make_incident(issue_type="raw_sqlite_query", confidence=0.80, strategy="parameterize_sqlite_query")
    assert kb.confidence_boost(other_incident) == 0.0

    # With the boost the engine now approves the same incident for auto-repair.
    engine_with_kb = PolicyEngine(min_confidence=0.85, knowledge_base=kb)
    decision = engine_with_kb.decide(event, [incident])
    assert decision.action == "auto_repair_sandbox", (
        f"Expected auto_repair_sandbox after KB boost; got {decision.action}: {decision.reasons}"
    )


def test_scenario_knowledge_base_failure_recording(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Failed verifications are also recorded so the success-rate stays accurate.

    Example usage::

        kb.record_failure(incident)  # when verification does NOT produce "verified_fix"
        patterns = kb.get_patterns(incident.issue_type)
        print(patterns[0].failure_count)  # incremented
    """
    monkeypatch.setattr("aion.repair.semgrep_available", lambda: False)
    kb = KnowledgeBase(base_dir=tmp_path / "knowledge")
    incident = _make_incident(issue_type="hardcoded_secret", strategy="env_secret")

    artifact = PatchArtifact(
        target_file="service.py",
        original_content="SECRET = 'abc'",
        patched_content='import os\nSECRET = os.getenv("SECRET", "")',
        diff="",
    )
    verification = VerificationResult(
        artifact=artifact, verdict="verified_fix",
        syntax_ok=True, semgrep_ok=True, assertions_ok=True,
    )
    kb.record_success(incident, verification)
    kb.record_failure(incident)

    patterns = kb.get_patterns("hardcoded_secret")
    assert patterns[0].success_count == 1
    assert patterns[0].failure_count == 1


# ---------------------------------------------------------------------------
# Scenario 8 — Release candidate lifecycle
#
# After a sandbox-verified fix is ready, a ReleaseCandidate tracks its journey
# through phased rollout.  The full lifecycle includes:
#   create → approve → advance (canary) → advance (staged) → … → complete
# and the alternate failure path:
#   create → reject
#   create → approve → advance → rollback
# ---------------------------------------------------------------------------


def _build_orchestration_result(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> tuple:
    """Helper: produce an OrchestrationResult with a verified sandbox fix."""
    monkeypatch.setattr("aion.repair.semgrep_available", lambda: False)
    repo_root = tmp_path / "release-repo"
    repo_root.mkdir()
    target = repo_root / "service.py"
    target.write_text((VULN / "02_hardcoded_secret.py").read_text(encoding="utf-8"), encoding="utf-8")
    ctx_path = repo_root / "context.json"
    ctx_path.write_text((VULN / "02_context.json").read_text(encoding="utf-8"), encoding="utf-8")

    orch = Orchestrator.from_config(
        AppConfig(
            sandbox_mode="repository",
            sandbox_verification_commands=[f'{sys.executable} -c "print(\'release-ok\')"'],
            auto_approve_verified_fixes=True,
        )
    )
    event = orch.ingest_event({
        "event_type": "runtime_alert",
        "target_file": str(target.resolve()),
        "metadata": {"repo_root": str(repo_root.resolve())},
    })
    context = ContextProfile(**json.loads(ctx_path.read_text(encoding="utf-8")))
    result = orch.process_event(event, context, repo_root=repo_root.resolve())
    return result, orch


def test_scenario_release_candidate_approve_and_advance(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Create a release candidate, approve it, and advance it through all phases.

    Example usage::

        manager = ReleaseManager(Path(".aion/releases"))
        candidate = manager.create_candidate(orchestration_result)
        candidate = manager.approve(candidate.candidate_id, approver="alice")
        while candidate.state != "completed":
            candidate = manager.advance(candidate.candidate_id)
    """
    result, orch = _build_orchestration_result(monkeypatch, tmp_path)
    manager = ReleaseManager(tmp_path / "releases")

    candidate = manager.create_candidate(result)
    assert candidate.state == "candidate"
    assert len(candidate.phases) == 4  # canary, staged, broad, full
    assert candidate.recommendation == "approved_for_rollout"

    candidate = manager.approve(candidate.candidate_id, "alice")
    assert candidate.state == "approved"
    assert "alice" in candidate.approvals

    # Advance through all four phases
    for expected_phase in ["canary", "staged", "broad", "full"]:
        assert candidate.phases[candidate.current_phase_index].name == expected_phase
        candidate = manager.advance(candidate.candidate_id)

    assert candidate.state == "completed"
    assert all(phase.completed for phase in candidate.phases)

    orch.cleanup_sandbox(result)


def test_scenario_release_candidate_reject(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Reject a release candidate before rollout.

    Example usage::

        candidate = manager.reject(candidate.candidate_id,
                                   approver="bob",
                                   reason="policy violation")
        assert candidate.state == "rejected"
    """
    result, orch = _build_orchestration_result(monkeypatch, tmp_path)
    manager = ReleaseManager(tmp_path / "releases")

    candidate = manager.create_candidate(result)
    candidate = manager.reject(candidate.candidate_id, "bob", "policy violation")

    assert candidate.state == "rejected"
    assert any("policy violation" in h for h in candidate.history)

    orch.cleanup_sandbox(result)


def test_scenario_release_candidate_rollback(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Approve then rollback a release after it has started executing.

    Example usage::

        candidate = manager.approve(candidate.candidate_id, "alice")
        candidate = manager.advance(candidate.candidate_id)   # canary phase
        candidate = manager.rollback(candidate.candidate_id, reason="metrics dropped")
        assert candidate.state == "rolled_back"
    """
    result, orch = _build_orchestration_result(monkeypatch, tmp_path)
    manager = ReleaseManager(tmp_path / "releases")

    candidate = manager.create_candidate(result)
    candidate = manager.approve(candidate.candidate_id, "alice")
    candidate = manager.advance(candidate.candidate_id)   # enter canary
    assert candidate.state == "executing"

    candidate = manager.rollback(candidate.candidate_id, "metrics dropped")
    assert candidate.state == "rolled_back"
    assert any("metrics dropped" in h for h in candidate.history)

    orch.cleanup_sandbox(result)


# ---------------------------------------------------------------------------
# Scenario 9 — Runtime defense planning
#
# The RuntimeDefensePlanner recommends containment actions that match the event
# type and incident severity, independent of the patch pipeline.
#
#   runtime_alert + critical/high → gateway_block + waf_rule + code_patch
#   code_scan                     → code_patch only
#   dependency_alert              → dependency_pin
#   missing_auth_decorator        → adds feature_flag action
# ---------------------------------------------------------------------------


def test_scenario_runtime_defense_runtime_alert() -> None:
    """Runtime alert on a high-severity issue triggers gateway block and WAF rule.

    Example usage::

        planner = RuntimeDefensePlanner()
        plan = planner.plan(event, incidents, rollout=None)
        action_types = [a.action_type for a in plan.actions]
        assert "gateway_block" in action_types
    """
    planner = RuntimeDefensePlanner()
    event = OrchestrationEvent(
        event_id="rt1", event_type="runtime_alert", target_file="service.py"
    )
    incidents = [
        Incident(
            id="i1", target_file="service.py", issue_type="command_injection",
            issue="shell injection", severity="critical", line=5, confidence=0.95,
        )
    ]

    plan = planner.plan(event, incidents, rollout=None)
    action_types = [a.action_type for a in plan.actions]

    assert "gateway_block" in action_types
    assert "waf_rule" in action_types
    assert "code_patch" in action_types


def test_scenario_runtime_defense_code_scan() -> None:
    """Code-scan events produce a code-patch action only.

    Example usage::

        plan = planner.plan(code_scan_event, incidents, rollout=None)
        assert plan.actions[0].action_type == "code_patch"
    """
    planner = RuntimeDefensePlanner()
    event = OrchestrationEvent(
        event_id="cs1", event_type="code_scan", target_file="service.py"
    )
    incidents = [
        Incident(
            id="i2", target_file="service.py", issue_type="hardcoded_secret",
            issue="secret in source", severity="high", line=2, confidence=0.90,
        )
    ]

    plan = planner.plan(event, incidents, rollout=None)
    action_types = [a.action_type for a in plan.actions]

    assert action_types == ["code_patch"]


def test_scenario_runtime_defense_dependency_alert() -> None:
    """Dependency alerts produce a dependency-pin action.

    Example usage::

        dep_event = OrchestrationEvent(..., event_type="dependency_alert")
        plan = planner.plan(dep_event, incidents, rollout=None)
        assert plan.actions[0].action_type == "dependency_pin"
    """
    planner = RuntimeDefensePlanner()
    event = OrchestrationEvent(
        event_id="dep1", event_type="dependency_alert", target_file="requirements.txt"
    )
    incidents = [
        Incident(
            id="i3", target_file="requirements.txt", issue_type="vulnerable_dependency",
            issue="outdated library", severity="high", line=1, confidence=0.80,
        )
    ]

    plan = planner.plan(event, incidents, rollout=None)
    action_types = [a.action_type for a in plan.actions]

    assert "dependency_pin" in action_types


def test_scenario_runtime_defense_missing_auth_adds_feature_flag() -> None:
    """Missing auth decorator triggers an additional feature_flag containment action.

    Example usage::

        # The feature_flag action can disable the sensitive route immediately
        # while auth is being restored.
        plan = planner.plan(event, [missing_auth_incident], rollout=None)
        assert any(a.action_type == "feature_flag" for a in plan.actions)
    """
    planner = RuntimeDefensePlanner()
    event = OrchestrationEvent(
        event_id="auth1", event_type="code_scan", target_file="views.py"
    )
    incidents = [
        Incident(
            id="i4", target_file="views.py", issue_type="missing_auth_decorator",
            issue="endpoint has no auth", severity="high", line=10, confidence=0.95,
        )
    ]

    plan = planner.plan(event, incidents, rollout=None)
    action_types = [a.action_type for a in plan.actions]

    assert "feature_flag" in action_types


# ---------------------------------------------------------------------------
# Scenario 10 — Event Inbox
#
# The EventInbox queues incoming events, tracks their status, and links results.
# ---------------------------------------------------------------------------


def test_scenario_event_inbox_lifecycle(tmp_path: Path) -> None:
    """Events are enqueued, processed, and status-tracked via the inbox.

    Example usage::

        inbox = EventInbox(root=Path(".aion/inbox"))
        item  = inbox.enqueue(event)
        assert item.status == "pending"

        result_path = inbox.result_file(item)
        result_path.write_text(result.model_dump_json(), encoding="utf-8")
        item = inbox.mark_processed(item, result_path)
        assert item.status == "processed"
    """
    inbox = EventInbox(root=tmp_path / "inbox")
    event = OrchestrationEvent(
        event_id="inbox-e2e", event_type="code_scan", target_file="service.py"
    )

    item = inbox.enqueue(event)
    assert item.status == "pending"
    assert inbox.get_item(item.item_id) is not None
    assert len(inbox.list_items(status="pending")) == 1

    # Simulate processing: write a stub result and mark item as processed.
    result_path = inbox.result_file(item)
    result_path.write_text('{"processed": true}', encoding="utf-8")
    item = inbox.mark_processed(item, result_path)

    assert item.status == "processed"
    assert item.result_path == str(result_path)
    assert inbox.list_items(status="pending") == []
    assert len(inbox.list_items(status="processed")) == 1

    # Failure path: mark a fresh event as failed.
    event2 = OrchestrationEvent(
        event_id="inbox-fail", event_type="runtime_alert", target_file="broken.py"
    )
    item2 = inbox.enqueue(event2)
    item2 = inbox.mark_failed(item2, "connection timeout")
    assert item2.status == "failed"
    assert item2.error == "connection timeout"
