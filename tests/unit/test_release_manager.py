import json
import sys
from pathlib import Path

import pytest
from typer.testing import CliRunner

from aion.cli import app
from aion.config import AppConfig
from aion.orchestrator import Orchestrator
from aion.release_manager import ReleaseManager


def _make_result(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    monkeypatch.setattr("aion.repair.semgrep_available", lambda: False)
    repo_root = tmp_path / "release-repo"
    repo_root.mkdir()
    target = repo_root / "service.py"
    target.write_text(Path("tests/fixtures/vulnerable/02_hardcoded_secret.py").read_text(encoding="utf-8"), encoding="utf-8")
    context_path = repo_root / "context.json"
    context_path.write_text(Path("tests/fixtures/vulnerable/02_context.json").read_text(encoding="utf-8"), encoding="utf-8")
    orchestrator = Orchestrator.from_config(
        AppConfig(
            sandbox_mode="repository",
            sandbox_verification_commands=[f'{sys.executable} -c "print(\'release-ok\')"'],
            auto_approve_verified_fixes=True,
        )
    )
    event = orchestrator.ingest_event(
        {
            "event_type": "runtime_alert",
            "target_file": str(target.resolve()),
            "metadata": {"repo_root": str(repo_root.resolve())},
        }
    )
    from aion.models import ContextProfile

    context = ContextProfile(**json.loads(context_path.read_text(encoding="utf-8")))
    result = orchestrator.process_event(event, context, repo_root=repo_root.resolve())
    return result, orchestrator


def test_release_manager_lifecycle(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    result, orchestrator = _make_result(monkeypatch, tmp_path)
    releases_root = tmp_path / "releases"
    manager = ReleaseManager(releases_root)

    candidate = manager.create_candidate(result)
    assert candidate.state == "candidate"

    candidate = manager.approve(candidate.candidate_id, "alice")
    assert candidate.state == "approved"
    assert candidate.approvals == ["alice"]

    candidate = manager.advance(candidate.candidate_id)
    assert candidate.state == "executing"
    assert candidate.phases[0].completed is True

    candidate = manager.rollback(candidate.candidate_id, "operator requested rollback")
    assert candidate.state == "rolled_back"

    orchestrator.cleanup_sandbox(result)


def test_cli_release_commands(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    result, orchestrator = _make_result(monkeypatch, tmp_path)
    runner = CliRunner()
    result_path = tmp_path / "orchestration.json"
    releases_root = tmp_path / "releases"
    result_path.write_text(result.model_dump_json(indent=2), encoding="utf-8")

    create = runner.invoke(
        app,
        ["create-release-candidate", str(result_path), "--releases-root", str(releases_root), "--output", "json"],
    )
    assert create.exit_code == 0
    candidate = json.loads(create.stdout)
    candidate_id = candidate["candidate_id"]

    approve = runner.invoke(
        app,
        ["approve-release", candidate_id, "--approver", "alice", "--releases-root", str(releases_root), "--output", "json"],
    )
    assert approve.exit_code == 0
    assert json.loads(approve.stdout)["state"] == "approved"

    advance = runner.invoke(
        app,
        ["advance-release", candidate_id, "--releases-root", str(releases_root), "--output", "json"],
    )
    assert advance.exit_code == 0
    assert json.loads(advance.stdout)["state"] == "executing"

    listed = runner.invoke(app, ["list-releases", "--releases-root", str(releases_root), "--output", "json"])
    listed_payload = json.loads(listed.stdout)
    assert len(listed_payload) == 1

    rollback = runner.invoke(
        app,
        ["rollback-release", candidate_id, "--reason", "failed metrics", "--releases-root", str(releases_root), "--output", "json"],
    )
    assert rollback.exit_code == 0
    assert json.loads(rollback.stdout)["state"] == "rolled_back"

    orchestrator.cleanup_sandbox(result)


def test_cli_reject_release(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    result, orchestrator = _make_result(monkeypatch, tmp_path)
    runner = CliRunner()
    result_path = tmp_path / "orchestration.json"
    releases_root = tmp_path / "releases"
    result_path.write_text(result.model_dump_json(indent=2), encoding="utf-8")

    create = runner.invoke(
        app,
        ["create-release-candidate", str(result_path), "--releases-root", str(releases_root), "--output", "json"],
    )
    assert create.exit_code == 0
    candidate_id = json.loads(create.stdout)["candidate_id"]

    reject = runner.invoke(
        app,
        [
            "reject-release",
            candidate_id,
            "--approver", "bob",
            "--reason", "policy violation",
            "--releases-root", str(releases_root),
            "--output", "json",
        ],
    )
    assert reject.exit_code == 0
    payload = json.loads(reject.stdout)
    assert payload["state"] == "rejected"
    assert any("policy violation" in h for h in payload["history"])

    orchestrator.cleanup_sandbox(result)
