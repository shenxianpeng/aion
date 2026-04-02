import json
import sys
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
