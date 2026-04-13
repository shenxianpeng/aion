import json
import sys
from pathlib import Path

import pytest
from typer.testing import CliRunner

from aion.cli import app
from aion.knowledge_base import KnowledgeBase
from aion.models import ContextProfile, Finding, Incident, PatchArtifact, SemgrepFinding, VerificationResult
from aion.orchestrator import Orchestrator, PolicyEngine
from aion.repair import IncidentDetector, PatchGenerator, RepairExecutor, Verifier


def _load_context(path: str) -> ContextProfile:
    return ContextProfile(**json.loads(Path(path).read_text(encoding="utf-8")))


@pytest.mark.parametrize(
    ("source_path", "context_path", "expected_strategy"),
    [
        ("tests/fixtures/vulnerable/01_raw_sqlite3.py", "tests/fixtures/vulnerable/01_context.json", "parameterize_sqlite_query"),
        ("tests/fixtures/vulnerable/02_hardcoded_secret.py", "tests/fixtures/vulnerable/02_context.json", "env_secret"),
        ("tests/fixtures/vulnerable/03_missing_auth_decorator.py", "tests/fixtures/vulnerable/03_context.json", "inject_auth_decorator"),
        ("tests/fixtures/vulnerable/04_insecure_yaml_load.py", "tests/fixtures/vulnerable/04_context.json", "safe_yaml_load"),
        ("tests/fixtures/vulnerable/05_command_injection.py", "tests/fixtures/vulnerable/05_context.json", "shlex_quote_command"),
        ("tests/fixtures/vulnerable/06_eval_injection.py", "tests/fixtures/vulnerable/06_context.json", "ast_literal_eval"),
        ("tests/fixtures/vulnerable/07_subprocess_injection.py", "tests/fixtures/vulnerable/07_context.json", "shlex_quote_subprocess"),
        ("tests/fixtures/vulnerable/08_weak_cryptography.py", "tests/fixtures/vulnerable/08_context.json", "upgrade_hash_algorithm"),
    ],
)
def test_repair_pipeline_generates_verified_fix(
    monkeypatch: pytest.MonkeyPatch,
    source_path: str,
    context_path: str,
    expected_strategy: str,
) -> None:
    monkeypatch.setattr("aion.repair.semgrep_available", lambda: False)
    target = Path(source_path)
    context = _load_context(context_path)

    incidents = IncidentDetector().detect(target, context)

    assert incidents
    assert incidents[0].remediation_strategy == expected_strategy

    artifact = PatchGenerator().generate(target, incidents, context)

    assert artifact is not None
    assert artifact.static_validation_passed is True
    assert [plan.strategy for plan in artifact.plans] == [expected_strategy]

    verification = Verifier().verify(artifact)

    assert verification.verdict == "verified_fix"
    assert verification.syntax_ok is True
    assert verification.assertions_ok is True


def test_repair_pipeline_skips_safe_fixture(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("aion.repair.semgrep_available", lambda: False)
    target = Path("tests/fixtures/safe/01_orm_correct.py")
    context = _load_context("tests/fixtures/safe/01_context.json")

    incidents = IncidentDetector().detect(target, context)
    artifact = PatchGenerator().generate(target, incidents, context)

    assert incidents == []
    assert artifact is None


def test_verifier_accepts_parameterized_sqlite_variant_without_fixture_exact_string(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setattr("aion.repair.semgrep_available", lambda: False)
    target = tmp_path / "service.py"
    target.write_text(
        "\n".join(
            [
                "import sqlite3",
                "",
                "def load_user(user_id):",
                "    conn = sqlite3.connect('db.sqlite3')",
                "    cursor = conn.cursor()",
                '    cursor.execute(f"SELECT email FROM users WHERE id = {user_id}")',
                "    return cursor.fetchone()",
                "",
            ]
        ),
        encoding="utf-8",
    )

    detector = IncidentDetector()
    artifact = PatchGenerator().generate(target, detector.detect(target, ContextProfile()), ContextProfile())

    assert artifact is not None
    verification = Verifier().verify(artifact)
    assert verification.verdict == "verified_fix"


def test_repair_pipeline_handles_multi_route_auth_gap(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr("aion.repair.semgrep_available", lambda: False)
    target = tmp_path / "routes.py"
    target.write_text(
        "\n".join(
            [
                "from fastapi import APIRouter",
                "",
                "router = APIRouter()",
                "",
                '@router.get("/users")',
                '@require_permissions("admin")',
                "def list_users():",
                '    return {"users": ["alice"]}',
                "",
                '@router.get("/audit")',
                "def audit_log():",
                '    return {"ok": True}',
                "",
            ]
        ),
        encoding="utf-8",
    )
    context = ContextProfile(auth_decorators=["@login_required", "@require_permissions"])

    detector = IncidentDetector()
    incidents = detector.detect(target, context)
    artifact = PatchGenerator().generate(target, incidents, context)

    assert [incident.issue_type for incident in incidents] == ["missing_auth_decorator"]
    assert artifact is not None
    assert artifact.patched_content.count("@require_permissions") == 2

    verification = Verifier().verify(artifact)
    assert verification.verdict == "verified_fix"


def test_repair_pipeline_handles_app_route_shape(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr("aion.repair.semgrep_available", lambda: False)
    target = tmp_path / "app_routes.py"
    target.write_text(
        "\n".join(
            [
                "from fastapi import FastAPI",
                "",
                "app = FastAPI()",
                "",
                '@app.get("/admin")',
                "def admin_dashboard():",
                '    return {"ok": True}',
                "",
            ]
        ),
        encoding="utf-8",
    )
    context = ContextProfile(auth_decorators=["@login_required"])

    detector = IncidentDetector()
    incidents = detector.detect(target, context)
    artifact = PatchGenerator().generate(target, incidents, context)

    assert [incident.issue_type for incident in incidents] == ["missing_auth_decorator"]
    assert artifact is not None
    assert "@login_required" in artifact.patched_content
    assert "@app.get" in artifact.patched_content

    verification = Verifier().verify(artifact)
    assert verification.verdict == "verified_fix"


def test_incident_detector_merges_semgrep_and_llm_findings_into_incidents(tmp_path: Path) -> None:
    target = tmp_path / "demo.py"
    target.write_text("print('hello')\n", encoding="utf-8")

    class FakeSemgrepRunner:
        def run(self, _target: Path) -> list[SemgrepFinding]:
            return [
                SemgrepFinding(
                    check_id="python.lang.security.audit.eval-detected.eval-detected",
                    path=str(target),
                    line=3,
                    severity="ERROR",
                    message="Avoid eval",
                )
            ]

    class FakeLLMAnalyzer:
        def analyze(self, *_args, **_kwargs) -> list[Finding]:
            return [
                Finding(
                    issue="Hardcoded secret in code",
                    severity="critical",
                    line=5,
                    context_gap="Project stores secrets in environment variables.",
                    fix="Load the value with os.getenv().",
                )
            ]

    detector = IncidentDetector(semgrep_runner=FakeSemgrepRunner(), llm_analyzer=FakeLLMAnalyzer())

    outcome = detector.analyze(
        target,
        ContextProfile(),
        fallback_signals=["hardcoded secret-like assignment detected"],
    )

    assert {incident.issue_type for incident in outcome.incidents} == {"eval_injection", "hardcoded_secret"}
    assert all(incident.source == "scan" for incident in outcome.incidents)
    assert outcome.mode == "semgrep+llm"


def test_incident_detector_deduplicates_supported_issue_types_across_sources(tmp_path: Path) -> None:
    target = tmp_path / "demo.py"
    target.write_text("result = eval(user_input)\n", encoding="utf-8")

    class FakeSemgrepRunner:
        def run(self, _target: Path) -> list[SemgrepFinding]:
            return [
                SemgrepFinding(
                    check_id="python.lang.security.audit.eval-detected.eval-detected",
                    path=str(target),
                    line=1,
                    severity="ERROR",
                    message="Avoid eval",
                )
            ]

    detector = IncidentDetector(semgrep_runner=FakeSemgrepRunner())

    outcome = detector.analyze(target, ContextProfile(), fallback_signals=[])

    eval_incidents = [incident for incident in outcome.incidents if incident.issue_type == "eval_injection"]
    assert len(eval_incidents) == 1
    assert eval_incidents[0].line == 1


def test_orchestrator_runs_incident_end_to_end(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("aion.repair.semgrep_available", lambda: False)
    target = Path("tests/fixtures/vulnerable/02_hardcoded_secret.py")
    context = _load_context("tests/fixtures/vulnerable/02_context.json")

    result = Orchestrator().run_incident(target, context)

    assert result.session.artifact is not None
    assert result.verification is not None
    assert result.verification.verdict == "verified_fix"


def test_policy_engine_requires_human_review_for_unknown_issue() -> None:
    event = Orchestrator().ingest_event({"event_type": "code_scan", "target_file": "demo.py"})
    decision = PolicyEngine().decide(
        event,
        [
            Incident(
                id="abc123",
                target_file="demo.py",
                issue_type="unknown_rule",
                issue="Unknown issue",
                severity="high",
                line=1,
                confidence=0.99,
            )
        ],
    )

    assert decision.action == "needs_human_review"
    assert "not approved for automatic remediation" in decision.reasons[0]


def test_orchestrator_process_event_runs_in_sandbox(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("aion.repair.semgrep_available", lambda: False)
    orchestrator = Orchestrator()
    target = Path("tests/fixtures/vulnerable/02_hardcoded_secret.py").resolve()
    context = _load_context("tests/fixtures/vulnerable/02_context.json")
    event = orchestrator.ingest_event({"event_type": "runtime_alert", "target_file": str(target)})

    result = orchestrator.process_event(event, context)

    assert result.policy.action == "auto_repair_sandbox"
    assert result.sandbox is not None
    assert Path(result.sandbox.staged_target_file).exists()
    assert result.sandbox.mode == "file"
    assert result.sandbox.verification is not None
    assert result.sandbox.verification.verdict == "verified_fix"
    orchestrator.cleanup_sandbox(result)
    assert not Path(result.sandbox.workspace_root).exists()


def test_orchestrator_from_config_uses_repository_sandbox(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr("aion.repair.semgrep_available", lambda: False)
    repo_root = tmp_path / "demo-repo"
    repo_root.mkdir()
    source_path = repo_root / "service.py"
    source_path.write_text(Path("tests/fixtures/vulnerable/02_hardcoded_secret.py").read_text(encoding="utf-8"), encoding="utf-8")
    context_path = repo_root / "context.json"
    context_path.write_text(Path("tests/fixtures/vulnerable/02_context.json").read_text(encoding="utf-8"), encoding="utf-8")

    from aion.config import AppConfig

    orchestrator = Orchestrator.from_config(
        AppConfig(
            sandbox_mode="repository",
            sandbox_verification_commands=[f'{sys.executable} -c "print(\'sandbox-ok\')"'],
            auto_approve_verified_fixes=True,
        )
    )
    event = orchestrator.ingest_event(
        {
            "event_type": "runtime_alert",
            "target_file": str(source_path.resolve()),
            "metadata": {"repo_root": str(repo_root.resolve())},
        }
    )
    result = orchestrator.process_event(event, _load_context(str(context_path)), repo_root=repo_root.resolve())

    assert result.sandbox is not None
    assert result.sandbox.mode == "repository"
    assert f"{repo_root.name}/service.py" in result.sandbox.staged_target_file
    assert result.sandbox.command_results[0].passed is True
    assert result.sandbox.rollout is not None
    assert result.sandbox.rollout.recommendation == "approved_for_rollout"
    orchestrator.cleanup_sandbox(result)


def test_orchestrator_rolls_back_when_sandbox_command_fails(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr("aion.repair.semgrep_available", lambda: False)
    repo_root = tmp_path / "rollback-repo"
    repo_root.mkdir()
    source_path = repo_root / "service.py"
    source_path.write_text(Path("tests/fixtures/vulnerable/01_raw_sqlite3.py").read_text(encoding="utf-8"), encoding="utf-8")
    context_path = repo_root / "context.json"
    context_path.write_text(Path("tests/fixtures/vulnerable/01_context.json").read_text(encoding="utf-8"), encoding="utf-8")

    from aion.config import AppConfig

    orchestrator = Orchestrator.from_config(
        AppConfig(
            sandbox_mode="repository",
            sandbox_verification_commands=[f'{sys.executable} -c "import sys; sys.exit(2)"'],
            rollback_on_verification_failure=True,
        )
    )
    event = orchestrator.ingest_event(
        {
            "event_type": "runtime_alert",
            "target_file": str(source_path.resolve()),
            "metadata": {"repo_root": str(repo_root.resolve())},
        }
    )
    result = orchestrator.process_event(event, _load_context(str(context_path)), repo_root=repo_root.resolve())

    assert result.sandbox is not None
    assert result.sandbox.command_results[0].passed is False
    assert result.sandbox.rollout is not None
    assert result.sandbox.rollout.recommendation == "rollback"
    orchestrator.cleanup_sandbox(result)


def test_repair_executor_records_attempt(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr("aion.repair.semgrep_available", lambda: False)
    target = Path("tests/fixtures/vulnerable/01_raw_sqlite3.py")
    context = _load_context("tests/fixtures/vulnerable/01_context.json")
    executor = RepairExecutor()

    record = executor.run(target, context, verify=True)
    record_path = tmp_path / "records" / "sqlite.json"
    executor.write_record(record, record_path)

    assert record.artifact is not None
    assert record.verification is not None
    assert record.verification.verdict == "verified_fix"
    assert json.loads(record_path.read_text(encoding="utf-8"))["verification"]["verdict"] == "verified_fix"


def test_cli_repair_verify_and_run_incident_json(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr("aion.repair.semgrep_available", lambda: False)
    runner = CliRunner()
    artifact_path = tmp_path / "artifact.json"
    target = Path("tests/fixtures/vulnerable/03_missing_auth_decorator.py")
    context_path = Path("tests/fixtures/vulnerable/03_context.json")

    repair_result = runner.invoke(
        app,
        ["repair", str(target), "--context-file", str(context_path), "--artifact-path", str(artifact_path), "--output", "json"],
    )

    assert repair_result.exit_code == 0
    repair_payload = json.loads(repair_result.stdout)
    assert repair_payload["artifact"]["plans"][0]["strategy"] == "inject_auth_decorator"
    assert artifact_path.exists()

    verify_result = runner.invoke(app, ["verify", "--artifact-path", str(artifact_path), "--output", "json"])

    assert verify_result.exit_code == 0
    verify_payload = json.loads(verify_result.stdout)
    assert verify_payload["verdict"] == "verified_fix"

    run_result = runner.invoke(
        app,
        ["run-incident", str(target), "--context-file", str(context_path), "--output", "json"],
    )

    assert run_result.exit_code == 0
    run_payload = json.loads(run_result.stdout)
    assert run_payload["verification"]["verdict"] == "verified_fix"


def test_cli_repair_eval_outputs_metrics_and_records(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr("aion.repair.semgrep_available", lambda: False)
    runner = CliRunner()
    records_dir = tmp_path / "repair-eval-records"

    result = runner.invoke(
        app,
        ["repair-eval", "tests/fixtures", "--records-dir", str(records_dir), "--output", "json"],
    )

    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["metrics"]["repair_success_count"] == 8
    assert payload["metrics"]["verification_pass_count"] == 8
    assert payload["metrics"]["false_fix_count"] == 0
    assert len(list(records_dir.glob("*.json"))) == 16


def test_cli_process_event_outputs_json_and_persists_result(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr("aion.repair.semgrep_available", lambda: False)
    runner = CliRunner()
    event_path = tmp_path / "event.json"
    result_path = tmp_path / "orchestration.json"
    event_path.write_text(
        json.dumps(
            {
                "event_type": "runtime_alert",
                "target_file": str(Path("tests/fixtures/vulnerable/03_missing_auth_decorator.py").resolve()),
                "metadata": {
                    "context_file": str(Path("tests/fixtures/vulnerable/03_context.json").resolve()),
                },
            }
        ),
        encoding="utf-8",
    )

    result = runner.invoke(
        app,
        ["process-event", str(event_path), "--result-path", str(result_path), "--output", "json"],
    )

    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["policy"]["action"] == "auto_repair_sandbox"
    assert payload["sandbox"]["verification"]["verdict"] == "verified_fix"
    assert json.loads(result_path.read_text(encoding="utf-8"))["policy"]["action"] == "auto_repair_sandbox"


def test_cli_process_event_honors_repo_policy_config(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr("aion.repair.semgrep_available", lambda: False)
    runner = CliRunner()
    repo_root = tmp_path / "policy-repo"
    repo_root.mkdir()
    (repo_root / ".aion.yaml").write_text(
        "\n".join(
            [
                "auto_repair_issue_types:",
                "  - raw_sqlite_query",
                "auto_repair_min_confidence: 0.99",
                "sandbox_mode: repository",
                f"sandbox_verification_commands:\n  - {sys.executable} -c \"print('ok')\"",
            ]
        ),
        encoding="utf-8",
    )
    target = repo_root / "service.py"
    target.write_text(Path("tests/fixtures/vulnerable/02_hardcoded_secret.py").read_text(encoding="utf-8"), encoding="utf-8")
    context = repo_root / "context.json"
    context.write_text(Path("tests/fixtures/vulnerable/02_context.json").read_text(encoding="utf-8"), encoding="utf-8")
    event_path = tmp_path / "policy-event.json"
    event_path.write_text(
        json.dumps(
            {
                "event_type": "runtime_alert",
                "target_file": str(target.resolve()),
                "metadata": {
                    "repo_root": str(repo_root.resolve()),
                    "context_file": str(context.resolve()),
                },
            }
        ),
        encoding="utf-8",
    )

    result = runner.invoke(app, ["process-event", str(event_path), "--output", "json"])

    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["policy"]["action"] == "needs_human_review"
    assert payload["sandbox"] is None


def test_cli_process_event_queue_uses_results_dir_and_cleanup(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr("aion.repair.semgrep_available", lambda: False)
    runner = CliRunner()

    auto_repo = tmp_path / "auto-repo"
    auto_repo.mkdir()
    (auto_repo / ".aion.yaml").write_text(
        "\n".join(
            [
                "sandbox_mode: repository",
                f"sandbox_verification_commands:\n  - {sys.executable} -c \"print('queue-ok')\"",
                "auto_approve_verified_fixes: true",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    auto_target = auto_repo / "service.py"
    auto_target.write_text(Path("tests/fixtures/vulnerable/03_missing_auth_decorator.py").read_text(encoding="utf-8"), encoding="utf-8")
    auto_context = auto_repo / "context.json"
    auto_context.write_text(Path("tests/fixtures/vulnerable/03_context.json").read_text(encoding="utf-8"), encoding="utf-8")

    review_repo = tmp_path / "review-repo"
    review_repo.mkdir()
    (review_repo / ".aion.yaml").write_text(
        "\n".join(
            [
                "auto_repair_issue_types:",
                "  - hardcoded_secret",
            ]
        ),
        encoding="utf-8",
    )
    review_target = review_repo / "service.py"
    review_target.write_text(Path("tests/fixtures/vulnerable/01_raw_sqlite3.py").read_text(encoding="utf-8"), encoding="utf-8")
    review_context = review_repo / "context.json"
    review_context.write_text(Path("tests/fixtures/vulnerable/01_context.json").read_text(encoding="utf-8"), encoding="utf-8")

    queue_path = tmp_path / "events.json"
    queue_path.write_text(
        json.dumps(
            [
                {
                    "event_type": "runtime_alert",
                    "target_file": str(auto_target.resolve()),
                    "metadata": {
                        "repo_root": str(auto_repo.resolve()),
                        "context_file": str(auto_context.resolve()),
                    },
                },
                {
                    "event_type": "code_scan",
                    "target_file": str(review_target.resolve()),
                    "metadata": {
                        "repo_root": str(review_repo.resolve()),
                        "context_file": str(review_context.resolve()),
                    },
                },
            ]
        ),
        encoding="utf-8",
    )
    results_dir = tmp_path / "queue-results"

    result = runner.invoke(
        app,
        ["process-event-queue", str(queue_path), "--results-dir", str(results_dir), "--cleanup-sandbox", "--output", "json"],
    )

    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["summary"]["total_events"] == 2
    assert payload["summary"]["auto_repair_count"] == 1
    assert payload["summary"]["human_review_count"] == 1
    assert payload["summary"]["verified_count"] == 1
    assert payload["summary"]["approved_count"] == 1
    assert payload["summary"]["rollback_count"] == 0
    assert len(list(results_dir.glob("*.json"))) == 2
    sandbox_path = Path(payload["results"][0]["sandbox"]["workspace_root"])
    assert not sandbox_path.exists()
    assert payload["results"][0]["sandbox"]["rollout"]["recommendation"] == "approved_for_rollout"


# ---------------------------------------------------------------------------
# Knowledge base ↔ policy engine self-evolving integration
# ---------------------------------------------------------------------------


def _make_incident(
    issue_type: str = "hardcoded_secret",
    severity: str = "critical",
    confidence: float = 0.80,
    strategy: str = "env_secret",
) -> Incident:
    return Incident(
        id=f"{issue_type}-test",
        target_file="app.py",
        issue_type=issue_type,
        issue="test incident",
        severity=severity,
        line=1,
        confidence=confidence,
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


def test_policy_engine_uses_knowledge_base_boost(tmp_path: Path) -> None:
    """Confidence boost from prior successes tips a borderline incident into auto-repair."""
    kb = KnowledgeBase(base_dir=tmp_path / "knowledge")
    incident = _make_incident(confidence=0.80)

    # Without the KB boost the incident should fall below min_confidence=0.85.
    engine_no_kb = PolicyEngine(min_confidence=0.85)
    event = Orchestrator().ingest_event({"event_type": "code_scan", "target_file": "app.py"})
    assert engine_no_kb.decide(event, [incident]).action == "needs_human_review"

    # Record enough successes so the boost pushes effective confidence above 0.85.
    verification = _make_verification()
    for _ in range(10):
        kb.record_success(incident, verification)

    engine_with_kb = PolicyEngine(min_confidence=0.85, knowledge_base=kb)
    decision = engine_with_kb.decide(event, [incident])
    assert decision.action == "auto_repair_sandbox", (
        f"Expected auto_repair_sandbox after KB boost but got {decision.action}: {decision.reasons}"
    )


def test_policy_engine_without_knowledge_base_unchanged(tmp_path: Path) -> None:
    """PolicyEngine without a KB behaves exactly as before — confidence checked raw."""
    incident = _make_incident(confidence=0.99)
    engine = PolicyEngine(min_confidence=0.85)
    event = Orchestrator().ingest_event({"event_type": "code_scan", "target_file": "app.py"})
    decision = engine.decide(event, [incident])
    assert decision.action == "auto_repair_sandbox"


def test_orchestrator_records_success_in_knowledge_base(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """process_event should record verified fixes in the attached knowledge base."""
    monkeypatch.setattr("aion.repair.semgrep_available", lambda: False)
    kb = KnowledgeBase(base_dir=tmp_path / "knowledge")
    orchestrator = Orchestrator(knowledge_base=kb)

    target = Path("tests/fixtures/vulnerable/02_hardcoded_secret.py").resolve()
    context = _load_context("tests/fixtures/vulnerable/02_context.json")
    event = orchestrator.ingest_event({"event_type": "code_scan", "target_file": str(target)})

    result = orchestrator.process_event(event, context)

    assert result.sandbox is not None
    assert result.sandbox.verification is not None
    assert result.sandbox.verification.verdict == "verified_fix"

    # The knowledge base should now hold a success record for hardcoded_secret.
    patterns = kb.get_patterns("hardcoded_secret")
    assert len(patterns) >= 1
    assert patterns[0].success_count >= 1

    orchestrator.cleanup_sandbox(result)


def test_orchestrator_records_failure_in_knowledge_base(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """process_event should record a failure when sandbox verification verdict is not verified_fix."""
    monkeypatch.setattr("aion.repair.semgrep_available", lambda: False)
    kb = KnowledgeBase(base_dir=tmp_path / "knowledge")

    # Pre-seed one success so the pattern exists, then trigger a verification failure
    # by making Verifier.verify always return "unsafe_patch".
    incident = _make_incident(issue_type="hardcoded_secret", strategy="env_secret")
    verification = _make_verification("verified_fix")
    kb.record_success(incident, verification)
    initial_failure_count = kb.get_patterns("hardcoded_secret")[0].failure_count

    # Monkeypatch Verifier.verify to return an unsafe patch verdict.
    def _bad_verify(self: Verifier, artifact: PatchArtifact) -> VerificationResult:
        return _make_verification("unsafe_patch")

    monkeypatch.setattr("aion.orchestrator.Verifier.verify", _bad_verify)

    orchestrator = Orchestrator(knowledge_base=kb)
    target = Path("tests/fixtures/vulnerable/02_hardcoded_secret.py").resolve()
    context = _load_context("tests/fixtures/vulnerable/02_context.json")
    event = orchestrator.ingest_event({"event_type": "code_scan", "target_file": str(target)})

    result = orchestrator.process_event(event, context)
    orchestrator.cleanup_sandbox(result)

    assert result.sandbox is not None
    assert result.sandbox.verification is not None
    assert result.sandbox.verification.verdict == "unsafe_patch"

    patterns = kb.get_patterns("hardcoded_secret")
    assert len(patterns) >= 1
    assert patterns[0].failure_count > initial_failure_count


def test_orchestrator_from_config_passes_knowledge_base(tmp_path: Path) -> None:
    """Orchestrator.from_config should pass the KB to the PolicyEngine."""
    from aion.config import AppConfig
    kb = KnowledgeBase(base_dir=tmp_path / "knowledge")
    config = AppConfig()
    orchestrator = Orchestrator.from_config(config, knowledge_base=kb)
    assert orchestrator.knowledge_base is kb
    assert orchestrator.policy_engine.knowledge_base is kb
