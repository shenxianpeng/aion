import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from aion.cli import app
from aion.models import ContextProfile, Incident
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
    assert result.sandbox.verification is not None
    assert result.sandbox.verification.verdict == "verified_fix"
    orchestrator.cleanup_sandbox(result)
    assert not Path(result.sandbox.workspace_root).exists()


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
    assert payload["metrics"]["repair_success_count"] == 3
    assert payload["metrics"]["verification_pass_count"] == 3
    assert payload["metrics"]["false_fix_count"] == 0
    assert len(list(records_dir.glob("*.json"))) == 6


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
