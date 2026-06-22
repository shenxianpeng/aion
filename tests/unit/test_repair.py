import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from aion.cli import app
from aion.models import ContextProfile, Finding, SemgrepFinding
from aion.repair import IncidentDetector, PatchGenerator, RepairExecutor, Verifier


def _load_context(path: str) -> ContextProfile:
    return ContextProfile(**json.loads(Path(path).read_text(encoding="utf-8")))


@pytest.mark.parametrize(
    ("source_path", "context_path", "expected_strategy"),
    [
        ("tests/fixtures/vulnerable/01_raw_sqlite3.py", "tests/fixtures/vulnerable/01_context.json", "parameterize_sqlite_query"),
        ("tests/fixtures/vulnerable/02_hardcoded_secret.py", "tests/fixtures/vulnerable/02_context.json", "env_secret"),
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


def test_missing_auth_is_reported_but_not_auto_repaired(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
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
    context = ContextProfile(auth_decorators=["@login_required", "@require_permissions"])

    detector = IncidentDetector()
    incidents = detector.detect(target, context)

    # The gap is still surfaced for a human...
    assert [incident.issue_type for incident in incidents] == ["missing_auth_decorator"]
    assert incidents[0].recommended_action == "review"
    assert incidents[0].remediation_strategy == ""

    # ...but no deterministic patch is generated for it (auto-injection is unsafe).
    artifact = PatchGenerator().generate(target, incidents, context)
    assert artifact is None


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


def test_cli_repair_and_verify_json(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr("aion.repair.semgrep_available", lambda: False)
    runner = CliRunner()
    artifact_path = tmp_path / "artifact.json"
    target = Path("tests/fixtures/vulnerable/02_hardcoded_secret.py")
    context_path = Path("tests/fixtures/vulnerable/02_context.json")

    repair_result = runner.invoke(
        app,
        ["repair", str(target), "--context-file", str(context_path), "--artifact-path", str(artifact_path), "--output", "json"],
    )

    assert repair_result.exit_code == 0
    repair_payload = json.loads(repair_result.stdout)
    assert repair_payload["artifact"]["plans"][0]["strategy"] == "env_secret"
    assert artifact_path.exists()

    verify_result = runner.invoke(app, ["verify", "--artifact-path", str(artifact_path), "--output", "json"])

    assert verify_result.exit_code == 0
    verify_payload = json.loads(verify_result.stdout)
    assert verify_payload["verdict"] == "verified_fix"
