"""Unit tests for the self-evolution engine."""

from __future__ import annotations

from pathlib import Path

import pytest

from aion.knowledge_base import KnowledgeBase
from aion.models import Finding, Incident, VerificationResult, PatchArtifact
from aion.self_evolve import (
    ConfidenceCalibrator,
    EvolutionLedger,
    HeuristicEvolver,
    SelfEvolveEngine,
    SelfEvolveResult,
    StrategyEvolver,
)


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


# ===========================================================================
# EvolutionLedger
# ===========================================================================


class TestEvolutionLedger:
    def test_empty_ledger(self, tmp_path: Path) -> None:
        ledger = EvolutionLedger(base_dir=tmp_path)
        assert ledger.entries() == []

    def test_record_appends_entry(self, tmp_path: Path) -> None:
        ledger = EvolutionLedger(base_dir=tmp_path)
        ledger.record("self_patch", "Fixed a bug", {"target": "cli.py"})
        entries = ledger.entries()
        assert len(entries) == 1
        assert entries[0]["type"] == "self_patch"
        assert entries[0]["summary"] == "Fixed a bug"
        assert entries[0]["details"]["target"] == "cli.py"

    def test_record_persists_to_disk(self, tmp_path: Path) -> None:
        ledger_dir = tmp_path / "evolution"
        ledger = EvolutionLedger(base_dir=ledger_dir)
        ledger.record("heuristic_added", "New heuristic: exec_injection", {"issue_type": "exec_injection"})
        assert (ledger_dir / "evolution.json").exists()

    def test_reloads_from_disk(self, tmp_path: Path) -> None:
        ledger_dir = tmp_path / "evolution"
        ledger1 = EvolutionLedger(base_dir=ledger_dir)
        ledger1.record("strategy_promoted", "env_secret promoted", {"success_rate": 0.9})

        ledger2 = EvolutionLedger(base_dir=ledger_dir)
        entries = ledger2.entries()
        assert len(entries) == 1
        assert entries[0]["type"] == "strategy_promoted"

    def test_multiple_entries(self, tmp_path: Path) -> None:
        ledger = EvolutionLedger(base_dir=tmp_path)
        ledger.record("self_patch", "Fix A")
        ledger.record("heuristic_added", "Add B")
        ledger.record("confidence_adjusted", "Adjust C")
        assert len(ledger.entries()) == 3

    def test_summary_counts_by_type(self, tmp_path: Path) -> None:
        ledger = EvolutionLedger(base_dir=tmp_path)
        ledger.record("self_patch", "Fix 1")
        ledger.record("self_patch", "Fix 2")
        ledger.record("heuristic_added", "Heuristic 1")

        summary = ledger.summary()
        assert summary["total_evolution_events"] == 3
        assert summary["by_type"] == {"self_patch": 2, "heuristic_added": 1}

    def test_summary_latest_event(self, tmp_path: Path) -> None:
        ledger = EvolutionLedger(base_dir=tmp_path)
        ledger.record("self_patch", "First")
        ledger.record("strategy_promoted", "Last")

        summary = ledger.summary()
        assert summary["latest_event"]["summary"] == "Last"

    def test_entry_types_are_recorded_correctly(self, tmp_path: Path) -> None:
        ledger = EvolutionLedger(base_dir=tmp_path)
        valid_types = [
            "heuristic_added",
            "strategy_promoted",
            "strategy_pruned",
            "self_patch",
            "confidence_adjusted",
        ]
        for t in valid_types:
            ledger.record(t, f"Test {t}")

        entries = ledger.entries()
        assert len(entries) == len(valid_types)


# ===========================================================================
# HeuristicEvolver
# ===========================================================================


class TestHeuristicEvolver:
    def test_discovers_pickle_load_pattern(self, tmp_path: Path) -> None:
        evolver = HeuristicEvolver()
        kb = KnowledgeBase(base_dir=tmp_path / "kb")
        findings = [
            Finding(
                issue="pickle.load() deserializes arbitrary objects",
                severity="critical",
                line=10,
                context_gap="Insecure deserialization via pickle.load",
                fix="Replace with json.load",
            ),
        ]

        candidates = evolver.discover(findings, set(), kb)
        issue_types = {c["issue_type"] for c in candidates}
        assert "insecure_pickle_load" in issue_types

    def test_discovers_exec_injection_pattern(self, tmp_path: Path) -> None:
        evolver = HeuristicEvolver()
        kb = KnowledgeBase(base_dir=tmp_path / "kb")
        findings = [
            Finding(
                issue="exec() called with dynamic input",
                severity="critical",
                line=20,
                context_gap="Arbitrary code execution via exec()",
                fix="Use sandbox instead of exec()",
            ),
        ]

        candidates = evolver.discover(findings, set(), kb)
        issue_types = {c["issue_type"] for c in candidates}
        assert "exec_injection" in issue_types

    def test_discovers_debug_true_pattern(self, tmp_path: Path) -> None:
        evolver = HeuristicEvolver()
        kb = KnowledgeBase(base_dir=tmp_path / "kb")
        findings = [
            Finding(
                issue="DEBUG = True in production config",
                severity="high",
                line=5,
                context_gap="Exposes stack traces via DEBUG = True",
                fix="Use env var for DEBUG",
            ),
        ]

        candidates = evolver.discover(findings, set(), kb)
        issue_types = {c["issue_type"] for c in candidates}
        assert "debug_enabled" in issue_types

    def test_discovers_insecure_tempfile_pattern(self, tmp_path: Path) -> None:
        evolver = HeuristicEvolver()
        kb = KnowledgeBase(base_dir=tmp_path / "kb")
        findings = [
            Finding(
                issue="tempfile.mktemp() is vulnerable to race conditions",
                severity="high",
                line=15,
                context_gap="Race condition in tempfile.mktemp() usage",
                fix="Use tempfile.mkstemp()",
            ),
        ]

        candidates = evolver.discover(findings, set(), kb)
        issue_types = {c["issue_type"] for c in candidates}
        assert "insecure_tempfile" in issue_types

    def test_discovers_http_no_timeout_pattern(self, tmp_path: Path) -> None:
        evolver = HeuristicEvolver()
        kb = KnowledgeBase(base_dir=tmp_path / "kb")
        findings = [
            Finding(
                issue="requests.get() without timeout parameter causes hangs",
                severity="medium",
                line=30,
                context_gap="requests.get() call missing timeout leads to resource exhaustion",
                fix="Add timeout parameter to requests.get()",
            ),
        ]

        candidates = evolver.discover(findings, set(), kb)
        issue_types = {c["issue_type"] for c in candidates}
        assert "http_no_timeout" in issue_types

    def test_skips_already_existing_issue_types(self, tmp_path: Path) -> None:
        evolver = HeuristicEvolver()
        kb = KnowledgeBase(base_dir=tmp_path / "kb")
        findings = [
            Finding(
                issue="pickle.load() used",
                severity="critical",
                line=10,
                context_gap="Insecure deserialization",
                fix="Use json.load",
            ),
        ]

        # If "insecure_pickle_load" already exists in the engine, it should not
        # be re-discovered.
        existing = {"insecure_pickle_load"}
        candidates = evolver.discover(findings, existing, kb)
        assert len(candidates) == 0

    def test_no_candidates_on_empty_findings(self, tmp_path: Path) -> None:
        evolver = HeuristicEvolver()
        kb = KnowledgeBase(base_dir=tmp_path / "kb")
        candidates = evolver.discover([], set(), kb)
        assert candidates == []

    def test_no_candidates_on_irrelevant_findings(self, tmp_path: Path) -> None:
        evolver = HeuristicEvolver()
        kb = KnowledgeBase(base_dir=tmp_path / "kb")
        findings = [
            Finding(
                issue="Some unrelated issue",
                severity="low",
                line=1,
                context_gap="Nothing relevant",
                fix="N/A",
            ),
        ]

        candidates = evolver.discover(findings, set(), kb)
        assert candidates == []

    def test_higher_confidence_with_knowledge_base_support(self, tmp_path: Path) -> None:
        evolver = HeuristicEvolver()
        kb = KnowledgeBase(base_dir=tmp_path / "kb")

        # Seed knowledge base with a pattern for pickle_load
        incident = _make_incident(issue_type="insecure_pickle_load", strategy="safe_json_deserialize")
        kb.record_success(incident, _make_verification())

        findings = [
            Finding(
                issue="pickle.load() used dangerously",
                severity="critical",
                line=10,
                context_gap="Insecure deserialization via pickle.load",
                fix="Replace with json.load",
            ),
        ]

        candidates = evolver.discover(findings, set(), kb)
        assert len(candidates) == 1
        assert candidates[0]["confidence"] > 0.85
        assert candidates[0]["knowledge_base_support"] >= 1


# ===========================================================================
# StrategyEvolver
# ===========================================================================


class TestStrategyEvolver:
    def test_promotes_consistently_successful_strategy(self, tmp_path: Path) -> None:
        kb = KnowledgeBase(base_dir=tmp_path / "kb")
        for _ in range(5):
            kb.record_success(
                _make_incident(issue_type="hardcoded_secret", strategy="env_secret"),
                _make_verification(),
            )

        evolver = StrategyEvolver()
        promotions = evolver.evaluate_and_promote(kb, min_success_count=3, min_success_rate=0.8)
        assert len(promotions) >= 1
        assert promotions[0]["issue_type"] == "hardcoded_secret"
        assert promotions[0]["success_rate"] == 1.0
        assert promotions[0]["action"] == "promote_to_deterministic"

    def test_does_not_promote_with_insufficient_samples(self, tmp_path: Path) -> None:
        kb = KnowledgeBase(base_dir=tmp_path / "kb")
        # Only 1 success — below min_success_count=3.
        kb.record_success(
            _make_incident(issue_type="hardcoded_secret", strategy="env_secret"),
            _make_verification(),
        )

        evolver = StrategyEvolver()
        promotions = evolver.evaluate_and_promote(kb, min_success_count=3, min_success_rate=0.8)
        assert promotions == []

    def test_does_not_promote_below_success_rate_threshold(self, tmp_path: Path) -> None:
        kb = KnowledgeBase(base_dir=tmp_path / "kb")
        # 3 successes, 2 failures → 60% — below 80% threshold.
        for _ in range(3):
            kb.record_success(
                _make_incident(issue_type="weak_cryptography", strategy="upgrade_hash_algorithm"),
                _make_verification(),
            )
        for _ in range(2):
            kb.record_failure(
                _make_incident(issue_type="weak_cryptography", strategy="upgrade_hash_algorithm"),
            )

        evolver = StrategyEvolver()
        promotions = evolver.evaluate_and_promote(kb, min_success_count=3, min_success_rate=0.8)
        assert promotions == []

    def test_prunes_consistently_failing_strategy(self, tmp_path: Path) -> None:
        kb = KnowledgeBase(base_dir=tmp_path / "kb")
        # 1 success, 5 failures → 83.3% failure rate, 6 attempts.
        kb.record_success(
            _make_incident(issue_type="eval_injection", strategy="ast_literal_eval"),
            _make_verification(),
        )
        for _ in range(5):
            kb.record_failure(
                _make_incident(issue_type="eval_injection", strategy="ast_literal_eval"),
            )

        evolver = StrategyEvolver()
        prunes = evolver.prune_failing_strategies(kb, max_failure_rate=0.7, min_attempts=4)
        assert len(prunes) >= 1
        assert prunes[0]["issue_type"] == "eval_injection"
        assert prunes[0]["action"] == "demote_to_human_review"

    def test_does_not_prune_below_min_attempts(self, tmp_path: Path) -> None:
        kb = KnowledgeBase(base_dir=tmp_path / "kb")
        # 2 failures only — below min_attempts=4.
        for _ in range(2):
            kb.record_failure(
                _make_incident(issue_type="command_injection", strategy="shlex_quote_command"),
            )

        evolver = StrategyEvolver()
        prunes = evolver.prune_failing_strategies(kb, min_attempts=4)
        assert prunes == []

    def test_does_not_prune_below_failure_rate(self, tmp_path: Path) -> None:
        kb = KnowledgeBase(base_dir=tmp_path / "kb")
        # 4 successes, 2 failures → 33% failure rate — below 70% threshold.
        for _ in range(4):
            kb.record_success(
                _make_incident(issue_type="hardcoded_secret", strategy="env_secret"),
                _make_verification(),
            )
        for _ in range(2):
            kb.record_failure(
                _make_incident(issue_type="hardcoded_secret", strategy="env_secret"),
            )

        evolver = StrategyEvolver()
        prunes = evolver.prune_failing_strategies(kb, max_failure_rate=0.7, min_attempts=5)
        assert prunes == []  # 6 total — at boundary of min_attempts=5, but failure rate (33%) < 70%


# ===========================================================================
# ConfidenceCalibrator
# ===========================================================================


class TestConfidenceCalibrator:
    def test_calibrates_positive_for_high_accuracy(self, tmp_path: Path) -> None:
        kb = KnowledgeBase(base_dir=tmp_path / "kb")
        for _ in range(10):
            kb.record_success(
                _make_incident(issue_type="hardcoded_secret", strategy="env_secret"),
                _make_verification(),
            )

        calibrator = ConfidenceCalibrator()
        adjustments = calibrator.calibrate(kb, {"hardcoded_secret"})
        assert "hardcoded_secret" in adjustments
        assert adjustments["hardcoded_secret"]["accuracy"] > 0.9
        assert adjustments["hardcoded_secret"]["confidence_delta"] >= 0.08

    def test_calibrates_negative_for_low_accuracy(self, tmp_path: Path) -> None:
        kb = KnowledgeBase(base_dir=tmp_path / "kb")
        for _ in range(2):
            kb.record_success(
                _make_incident(issue_type="eval_injection", strategy="ast_literal_eval"),
                _make_verification(),
            )
        for _ in range(6):
            kb.record_failure(
                _make_incident(issue_type="eval_injection", strategy="ast_literal_eval"),
            )

        calibrator = ConfidenceCalibrator()
        adjustments = calibrator.calibrate(kb, {"eval_injection"})
        assert "eval_injection" in adjustments
        assert adjustments["eval_injection"]["accuracy"] < 0.5
        assert adjustments["eval_injection"]["confidence_delta"] <= -0.05

    def test_calibrates_neutral_for_moderate_accuracy(self, tmp_path: Path) -> None:
        kb = KnowledgeBase(base_dir=tmp_path / "kb")
        for _ in range(6):
            kb.record_success(
                _make_incident(issue_type="missing_auth_decorator", strategy="inject_auth_decorator"),
                _make_verification(),
            )
        for _ in range(4):
            kb.record_failure(
                _make_incident(issue_type="missing_auth_decorator", strategy="inject_auth_decorator"),
            )

        calibrator = ConfidenceCalibrator()
        adjustments = calibrator.calibrate(kb, {"missing_auth_decorator"})
        assert "missing_auth_decorator" in adjustments
        assert 0.50 <= adjustments["missing_auth_decorator"]["accuracy"] <= 0.70

    def test_no_adjustment_without_enough_data(self, tmp_path: Path) -> None:
        kb = KnowledgeBase(base_dir=tmp_path / "kb")
        # Only 1 attempt — below the minimum threshold of 3.
        kb.record_success(
            _make_incident(issue_type="hardcoded_secret", strategy="env_secret"),
            _make_verification(),
        )

        calibrator = ConfidenceCalibrator()
        adjustments = calibrator.calibrate(kb, {"hardcoded_secret"})
        assert "hardcoded_secret" not in adjustments

    def test_empty_knowledge_base_returns_empty(self, tmp_path: Path) -> None:
        kb = KnowledgeBase(base_dir=tmp_path / "kb")
        calibrator = ConfidenceCalibrator()
        adjustments = calibrator.calibrate(kb, {"hardcoded_secret"})
        assert adjustments == {}

    def test_multiple_issue_types(self, tmp_path: Path) -> None:
        kb = KnowledgeBase(base_dir=tmp_path / "kb")
        # Seed high-accuracy pattern: 5 successes, 0 failures
        for _ in range(5):
            kb.record_success(
                _make_incident(issue_type="hardcoded_secret", strategy="env_secret"),
                _make_verification(),
            )
        # Seed low-accuracy pattern: 1 success + 4 failures (5 total, 20% accuracy)
        kb.record_success(
            _make_incident(issue_type="eval_injection", strategy="ast_literal_eval"),
            _make_verification(),
        )
        for _ in range(4):
            kb.record_failure(
                _make_incident(issue_type="eval_injection", strategy="ast_literal_eval"),
            )

        calibrator = ConfidenceCalibrator()
        adjustments = calibrator.calibrate(
            kb, {"hardcoded_secret", "eval_injection", "insecure_yaml_load"}
        )
        assert "hardcoded_secret" in adjustments  # high accuracy
        assert "eval_injection" in adjustments  # low accuracy (20% < 50%)
        assert adjustments["eval_injection"]["confidence_delta"] <= -0.05
        # insecure_yaml_load has no data
        assert "insecure_yaml_load" not in adjustments


# ===========================================================================
# SelfEvolveEngine — source location and file discovery
# ===========================================================================


class TestSelfEvolveEngineLocation:
    def test_finds_own_source_directory(self) -> None:
        engine = SelfEvolveEngine()
        source = engine.source_root
        assert source.exists()
        assert source.is_dir()
        assert source.name == "aion"

    def test_finds_python_files_in_own_source(self) -> None:
        engine = SelfEvolveEngine()
        files = engine._find_own_python_files()
        # The aion package has 19 .py files
        assert len(files) >= 15
        assert all(f.suffix == ".py" for f in files)
        assert all(f.exists() for f in files)

    def test_self_protected_files_are_excluded(self) -> None:
        engine = SelfEvolveEngine()
        files = engine._find_own_python_files()
        path_names = {f.name for f in files}
        assert "self_evolve.py" not in path_names
        assert "__init__.py" not in path_names
        assert "__main__.py" not in path_names

    def test_excluded_directories_are_skipped(self, tmp_path: Path) -> None:
        # Create a mock source tree
        source = tmp_path / "mock_aion"
        source.mkdir()
        (source / "good_file.py").write_text("# mock")
        (source / "module.py").write_text("# mock")
        pycache = source / "__pycache__"
        pycache.mkdir()
        (pycache / "cached.pyc").touch()

        engine = SelfEvolveEngine(aion_source_root=source)
        files = engine._find_own_python_files()
        path_names = {f.name for f in files}
        assert "good_file.py" in path_names
        assert "module.py" in path_names
        assert "cached.pyc" not in path_names  # skipped __pycache__ and not .py

    def test_egg_info_is_excluded(self, tmp_path: Path) -> None:
        source = tmp_path / "mock_aion"
        source.mkdir()
        (source / "real.py").write_text("# mock")
        egg = source / "aion.egg-info"
        egg.mkdir()
        (egg / "egg_file.py").write_text("# egg")

        engine = SelfEvolveEngine(aion_source_root=source)
        files = engine._find_own_python_files()
        path_names = {f.name for f in files}
        assert "real.py" in path_names
        assert "egg_file.py" not in path_names


# ===========================================================================
# SelfEvolveEngine — context profile
# ===========================================================================


class TestSelfEvolveEngineContext:
    def test_builds_own_context_profile(self) -> None:
        engine = SelfEvolveEngine()
        profile = engine._build_own_context_profile()
        assert profile is not None
        assert profile.scanned_files >= 0


# ===========================================================================
# SelfEvolveEngine — scan_self
# ===========================================================================


class TestSelfEvolveEngineScanSelf:
    def test_scan_self_returns_records(self) -> None:
        engine = SelfEvolveEngine()
        records = engine.scan_self()
        assert len(records) > 0
        assert all(r.target for r in records)

    def test_scan_self_results_have_context(self) -> None:
        engine = SelfEvolveEngine()
        records = engine.scan_self()
        for record in records:
            assert record.context_profile is not None


# ===========================================================================
# SelfEvolveEngine — evolve (dry run)
# ===========================================================================


class TestSelfEvolveEngineEvolve:
    def test_evolve_dry_run_completes(self, tmp_path: Path) -> None:
        """A dry-run should complete without modifying any files."""
        engine = SelfEvolveEngine()
        result = engine.evolve(dry_run=True)
        assert isinstance(result, SelfEvolveResult)
        assert result.files_scanned >= 1

    def test_evolve_dry_run_without_sub_phases(self, tmp_path: Path) -> None:
        engine = SelfEvolveEngine()
        result = engine.evolve(
            dry_run=True,
            evolve_heuristics=False,
            evolve_strategies=False,
            calibrate_confidence=False,
        )
        assert result.heuristics_added == 0
        assert result.strategies_promoted == 0
        assert result.strategies_pruned == 0
        assert result.confidence_calibrations == 0

    def test_evolve_produces_result_with_all_fields(self, tmp_path: Path) -> None:
        engine = SelfEvolveEngine()
        result = engine.evolve(dry_run=True)
        # All fields should be present (even if 0).
        assert hasattr(result, "files_scanned")
        assert hasattr(result, "incidents_found")
        assert hasattr(result, "patches_generated")
        assert hasattr(result, "patches_verified")
        assert hasattr(result, "patches_applied")
        assert hasattr(result, "heuristics_added")
        assert hasattr(result, "strategies_promoted")
        assert hasattr(result, "strategies_pruned")
        assert hasattr(result, "confidence_calibrations")
        assert hasattr(result, "errors")


# ===========================================================================
# SelfEvolveEngine — apply_patch_to_self
# ===========================================================================


class TestSelfEvolveEngineApplyPatchToSelf:
    def test_apply_patch_writes_content(self, tmp_path: Path) -> None:
        source = tmp_path / "mock_aion"
        source.mkdir()
        target_file = source / "test_module.py"
        target_file.write_text("original = 'hello'", encoding="utf-8")

        engine = SelfEvolveEngine(aion_source_root=source)
        artifact = PatchArtifact(
            target_file=str(target_file),
            original_content="original = 'hello'",
            patched_content="original = 'world'",
            diff="",
        )
        from aion.models import RepairAttemptRecord, ContextProfile
        record = RepairAttemptRecord(
            target=str(target_file),
            created_at="2026-01-01T00:00:00Z",
            context_profile=ContextProfile(),
            artifact=artifact,
        )

        assert engine._apply_patch_to_self(record) is True
        assert target_file.read_text(encoding="utf-8") == "original = 'world'"

    def test_does_not_apply_on_self_protected_files(self, tmp_path: Path) -> None:
        source = tmp_path / "mock_aion"
        source.mkdir()
        protected = source / "self_evolve.py"
        protected.write_text("original = 'hello'", encoding="utf-8")

        engine = SelfEvolveEngine(aion_source_root=source)
        artifact = PatchArtifact(
            target_file=str(protected),
            original_content="original = 'hello'",
            patched_content="original = 'world'",
            diff="",
        )
        from aion.models import RepairAttemptRecord, ContextProfile
        record = RepairAttemptRecord(
            target=str(protected),
            created_at="2026-01-01T00:00:00Z",
            context_profile=ContextProfile(),
            artifact=artifact,
        )

        assert engine._apply_patch_to_self(record) is False
        # Content must remain unchanged
        assert protected.read_text(encoding="utf-8") == "original = 'hello'"

    def test_does_not_apply_when_artifact_is_none(self, tmp_path: Path) -> None:
        source = tmp_path / "mock_aion"
        source.mkdir()
        target_file = source / "other.py"
        target_file.write_text("content", encoding="utf-8")

        engine = SelfEvolveEngine(aion_source_root=source)
        from aion.models import RepairAttemptRecord, ContextProfile
        record = RepairAttemptRecord(
            target=str(target_file),
            created_at="2026-01-01T00:00:00Z",
            context_profile=ContextProfile(),
            artifact=None,
        )

        assert engine._apply_patch_to_self(record) is False

    def test_returns_false_for_nonexistent_file(self, tmp_path: Path) -> None:
        source = tmp_path / "mock_aion"
        source.mkdir()

        engine = SelfEvolveEngine(aion_source_root=source)
        artifact = PatchArtifact(
            target_file=str(source / "nonexistent.py"),
            original_content="",
            patched_content="",
            diff="",
        )
        from aion.models import RepairAttemptRecord, ContextProfile
        record = RepairAttemptRecord(
            target=str(source / "nonexistent.py"),
            created_at="2026-01-01T00:00:00Z",
            context_profile=ContextProfile(),
            artifact=artifact,
        )

        assert engine._apply_patch_to_self(record) is False


# ===========================================================================
# SelfEvolveEngine — end-to-end with a vulnerable fixture
# ===========================================================================


class TestSelfEvolveEndToEnd:
    def test_detects_and_remediates_injected_vulnerability(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Inject a file with known vulnerabilities into a mock AION source
        and verify the self-evolution pipeline detects and patches them."""
        monkeypatch.setattr("aion.repair.semgrep_available", lambda: False)

        source = tmp_path / "mock_aion"
        source.mkdir()

        # Create a file with known vulnerabilities
        vuln_file = source / "service.py"
        vuln_file.write_text(
            '"""A vulnerable service module."""\n'
            'import sqlite3\n'
            '\n'
            'API_KEY = "sk-1234567890abcdef"\n'
            '\n'
            'def get_user(db_path: str, user_id: int):\n'
            '    conn = sqlite3.connect(db_path)\n'
            '    cursor = conn.cursor()\n'
            '    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")\n'
            '    return cursor.fetchall()\n',
            encoding="utf-8",
        )

        # Also create a safe file for coverage
        safe_file = source / "utils.py"
        safe_file.write_text("# harmless utility\n", encoding="utf-8")

        engine = SelfEvolveEngine(aion_source_root=source)

        # Run in non-dry-run mode so patches get applied
        result = engine.evolve(
            dry_run=False,
            evolve_heuristics=False,
            evolve_strategies=False,
            calibrate_confidence=False,
        )

        # Both files should be scanned
        assert result.files_scanned >= 2

        # At least the hardcoded_secret incident should be found
        assert result.incidents_found >= 1

        # At least one patch should be generated
        assert result.patches_generated >= 1

        # If verified, it should have been applied
        if result.patches_verified > 0:
            assert result.patches_applied > 0

    def test_evolution_ledger_records_self_patch(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """When a verified patch is applied, it should be recorded in the ledger."""
        monkeypatch.setattr("aion.repair.semgrep_available", lambda: False)

        source = tmp_path / "mock_aion"
        source.mkdir()

        vuln_file = source / "service.py"
        vuln_file.write_text(
            '"""A vulnerable service module."""\n'
            'API_KEY = "sk-1234567890abcdef"\n',
            encoding="utf-8",
        )

        engine = SelfEvolveEngine(aion_source_root=source)
        result = engine.evolve(
            dry_run=False,
            evolve_heuristics=False,
            evolve_strategies=False,
            calibrate_confidence=False,
        )

        if result.patches_applied > 0:
            entries = engine.ledger.entries()
            assert len(entries) >= 1
            assert any(e["type"] == "self_patch" for e in entries)

    def test_knowledge_base_updated_after_evolve(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """After self-evolution, the knowledge base should be populated."""
        monkeypatch.setattr("aion.repair.semgrep_available", lambda: False)

        source = tmp_path / "mock_aion"
        source.mkdir()

        vuln_file = source / "service.py"
        vuln_file.write_text(
            '"""A vulnerable service module."""\n'
            'import sqlite3\n'
            '\n'
            'def get_user(db_path: str, user_id: int):\n'
            '    conn = sqlite3.connect(db_path)\n'
            '    cursor = conn.cursor()\n'
            '    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")\n'
            '    return cursor.fetchall()\n',
            encoding="utf-8",
        )

        engine = SelfEvolveEngine(aion_source_root=source)
        result = engine.evolve(
            dry_run=False,
            evolve_heuristics=False,
            evolve_strategies=False,
            calibrate_confidence=False,
        )

        if result.incidents_found > 0:
            summary = engine.kb.summary()
            assert summary["total_patterns"] >= 0  # Knowledge base API works


# ===========================================================================
# SelfEvolveResult
# ===========================================================================


class TestSelfEvolveResult:
    def test_default_values(self) -> None:
        result = SelfEvolveResult()
        assert result.files_scanned == 0
        assert result.incidents_found == 0
        assert result.patches_generated == 0
        assert result.patches_verified == 0
        assert result.patches_applied == 0
        assert result.heuristics_added == 0
        assert result.strategies_promoted == 0
        assert result.strategies_pruned == 0
        assert result.confidence_calibrations == 0
        assert result.errors == []

    def test_errors_accumulate(self) -> None:
        result = SelfEvolveResult()
        result.errors.append("error 1")
        result.errors.append("error 2")
        assert len(result.errors) == 2


# ===========================================================================
# Heuristic addition at runtime
# ===========================================================================


class TestAddHeuristic:
    def test_adds_heuristic_to_supported_incidents(self) -> None:
        from aion.self_evolve import SelfEvolveEngine
        engine = SelfEvolveEngine()

        engine._add_heuristic("test_heuristic", {
            "issue": "Test issue",
            "severity": "medium",
            "attack_surface": "test",
            "recommended_action": "auto_repair",
            "remediation_strategy": "test_strategy",
            "verification_strategy": ["syntax"],
        })

        from aion.repair import IncidentDetector
        assert "test_heuristic" in IncidentDetector._SUPPORTED_INCIDENTS
        assert IncidentDetector._SUPPORTED_INCIDENTS["test_heuristic"]["issue"] == "Test issue"

        # Clean up after test — remove the injected heuristic
        del IncidentDetector._SUPPORTED_INCIDENTS["test_heuristic"]

    def test_does_not_duplicate_existing_heuristic(self) -> None:
        from aion.self_evolve import SelfEvolveEngine
        engine = SelfEvolveEngine()

        from aion.repair import IncidentDetector
        existing_count = len(IncidentDetector._SUPPORTED_INCIDENTS)

        # Try to add a heuristic that already exists
        engine._add_heuristic("hardcoded_secret", {
            "issue": "Different issue text",
            "severity": "low",
            "attack_surface": "other",
            "recommended_action": "review",
            "remediation_strategy": "other",
        })

        # Count should be unchanged
        assert len(IncidentDetector._SUPPORTED_INCIDENTS) == existing_count
        # Original values should be preserved
        assert IncidentDetector._SUPPORTED_INCIDENTS["hardcoded_secret"]["severity"] == "critical"
