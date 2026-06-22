"""End-to-end scenarios for AION's core: scan/detect → deterministic repair →
verification → auto-update, plus drift detection.

These exercise the surviving, supported pipeline only. The previous control-plane
scenarios (orchestrator, webhook, inbox, release manager, runtime defense) were
removed when that surface was cut from the project.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from aion.auto_update import AutoUpdateEngine
from aion.cli import app
from aion.config import UpdateConfig
from aion.drift_detector import DriftDetector
from aion.models import ContextProfile
from aion.repair import IncidentDetector, PatchGenerator, Verifier


# Every deterministically-repaired vulnerability type, end to end.
VULN_FIXTURES = [
    ("01_raw_sqlite3.py", "01_context.json", "parameterize_sqlite_query"),
    ("02_hardcoded_secret.py", "02_context.json", "env_secret"),
    ("04_insecure_yaml_load.py", "04_context.json", "safe_yaml_load"),
    ("05_command_injection.py", "05_context.json", "shlex_quote_command"),
    ("06_eval_injection.py", "06_context.json", "ast_literal_eval"),
    ("07_subprocess_injection.py", "07_context.json", "shlex_quote_subprocess"),
    ("08_weak_cryptography.py", "08_context.json", "upgrade_hash_algorithm"),
]


def _context(name: str) -> ContextProfile:
    return ContextProfile(**json.loads(Path(f"tests/fixtures/vulnerable/{name}").read_text(encoding="utf-8")))


@pytest.mark.parametrize(("source", "context", "strategy"), VULN_FIXTURES)
def test_scenario_single_file_repair_lifecycle(
    monkeypatch: pytest.MonkeyPatch, source: str, context: str, strategy: str
) -> None:
    monkeypatch.setattr("aion.repair.semgrep_available", lambda: False)
    target = Path(f"tests/fixtures/vulnerable/{source}")
    ctx = _context(context)

    incidents = IncidentDetector().detect(target, ctx)
    assert incidents
    assert incidents[0].remediation_strategy == strategy

    artifact = PatchGenerator().generate(target, incidents, ctx)
    assert artifact is not None
    assert [plan.strategy for plan in artifact.plans] == [strategy]

    verification = Verifier().verify(artifact)
    assert verification.verdict == "verified_fix"
    assert verification.syntax_ok is True
    assert verification.assertions_ok is True


def test_scenario_safe_fixture_produces_no_patch(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("aion.repair.semgrep_available", lambda: False)
    target = Path("tests/fixtures/safe/01_orm_correct.py")
    ctx = ContextProfile(**json.loads(Path("tests/fixtures/safe/01_context.json").read_text(encoding="utf-8")))

    incidents = IncidentDetector().detect(target, ctx)
    assert incidents == []
    assert PatchGenerator().generate(target, incidents, ctx) is None


def test_scenario_missing_auth_is_report_only(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr("aion.repair.semgrep_available", lambda: False)
    target = tmp_path / "routes.py"
    target.write_text(
        "\n".join(
            [
                "from fastapi import APIRouter",
                "",
                "router = APIRouter()",
                "",
                '@router.get("/audit")',
                "def audit_log():",
                '    return {"ok": True}',
                "",
            ]
        ),
        encoding="utf-8",
    )
    ctx = ContextProfile(auth_decorators=["@login_required", "@require_permissions"])

    incidents = IncidentDetector().detect(target, ctx)
    assert [i.issue_type for i in incidents] == ["missing_auth_decorator"]
    assert incidents[0].recommended_action == "review"
    # Surfaced for review, never auto-patched.
    assert PatchGenerator().generate(target, incidents, ctx) is None


def test_scenario_auto_update_dry_run_end_to_end(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr("aion.repair.semgrep_available", lambda: False)
    monkeypatch.setattr("aion.auto_update.semgrep_available", lambda: False)

    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "service.py").write_text(
        'API_KEY = "sk-live-deadbeefcafe"\n\n\ndef call():\n    return {"Authorization": API_KEY}\n',
        encoding="utf-8",
    )

    engine = AutoUpdateEngine(root=repo, update_config=UpdateConfig())
    result = engine.run(dry_run=True)

    assert result.incidents_found >= 1
    assert result.patches_generated >= 1
    assert result.patches_verified >= 1
    assert result.errors == []


def test_scenario_cli_auto_update_dry_run(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr("aion.repair.semgrep_available", lambda: False)
    monkeypatch.setattr("aion.auto_update.semgrep_available", lambda: False)

    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "service.py").write_text('API_KEY = "sk-live-xyz"\n', encoding="utf-8")

    result = CliRunner().invoke(app, ["auto-update", "--target", str(repo), "--dry-run"])
    assert result.exit_code == 0
    assert "Patches verified: 1" in result.output


def test_scenario_drift_detection_lifecycle(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr("aion.repair.semgrep_available", lambda: False)
    target = tmp_path / "service.py"
    target.write_text("def healthy():\n    return 1\n", encoding="utf-8")
    ctx = ContextProfile()

    detector = DriftDetector(snapshots_dir=tmp_path / "snaps")
    baseline = detector.snapshot(target, ctx)
    detector.save_snapshot(baseline, name="baseline")
    assert baseline.incidents == []

    # Introduce a regression.
    target.write_text('API_KEY = "sk-live-deadbeef"\n', encoding="utf-8")
    current = detector.snapshot(target, ctx)

    report = detector.compare(baseline, current)
    assert report.has_regression
    assert len(report.new_incidents) >= 1
    assert report.health_delta < 0
