"""Self-Evolution Engine — the core of AION's promise: Code Once, Live Forever.

This module enables AION to scan, repair, and evolve **its own source code**.
It is what makes AION a *self-evolving* code engine rather than just a code-engine
for other projects.

Capabilities
------------

- **Self-Scan**: Run AION's own detection pipeline on its source tree.
- **Self-Repair**: Generate, verify, and apply patches to its own code.
- **Heuristic Evolution**: Discover new detection patterns from LLM findings
  and add them to the built-in heuristics.
- **Strategy Evolution**: Promote successful LLM-suggested repair strategies
  into the deterministic ``PatchGenerator``.
- **Adaptive Confidence**: Tune confidence thresholds based on historical
  accuracy of each heuristic.
- **Evolution Ledger**: Persistent log of every evolutionary change so that
  the engine's growth is auditable and reversible.

Architecture::

    ┌──────────────────────────────────────────────┐
    │              SelfEvolveEngine                 │
    │                                               │
    │  locate_self()  →  find own .py files         │
    │  evolve()       →  scan → repair → verify     │
    │  evolve_heuristics() → add new detection rules│
    │  evolve_strategies() → add new repair methods │
    │  apply_evolution()   → write patches to disk  │
    │                                               │
    │  ┌─────────────────────────────────────────┐  │
    │  │  EvolutionLedger  (evolution.json)      │  │
    │  │  • heuristic additions                  │  │
    │  │  • strategy promotions                  │  │
    │  │  • self-patches applied                 │  │
    │  │  • confidence adjustments               │  │
    │  └─────────────────────────────────────────┘  │
    └──────────────────────────────────────────────┘
"""

from __future__ import annotations

import ast
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .knowledge_base import KnowledgeBase
from .models import (
    ContextProfile,
    Finding,
    Incident,
    RepairAttemptRecord,
    RepairPattern,
    VerificationResult,
    normalize_path,
)
from .repair import IncidentDetector, PatchGenerator, RepairExecutor, Verifier
from .semgrep_runner import SemgrepRunner, semgrep_available


# ------------------------------------------------------------------
# Evolution Ledger
# ------------------------------------------------------------------


class EvolutionEntry:
    """A single entry in the evolution ledger."""

    def __init__(
        self,
        entry_type: str,
        summary: str,
        details: dict[str, Any] | None = None,
    ) -> None:
        self.entry_type = entry_type  # heuristic_added, strategy_promoted, self_patch, confidence_adjusted
        self.timestamp = datetime.now(timezone.utc).isoformat()
        self.summary = summary
        self.details = details or {}

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": self.entry_type,
            "timestamp": self.timestamp,
            "summary": self.summary,
            "details": self.details,
        }


class EvolutionLedger:
    """Persistent, append-only log of the engine's evolutionary changes.

    Stored at ``<base_dir>/evolution.json`` inside the ``.aion`` directory.
    """

    def __init__(self, base_dir: Path | None = None) -> None:
        self.base_dir = base_dir or Path(".aion/evolution")
        self._ledger_path = self.base_dir / "evolution.json"
        self._entries: list[dict[str, Any]] = []
        self._loaded = False

    def record(self, entry_type: str, summary: str, details: dict[str, Any] | None = None) -> EvolutionEntry:
        """Append a new entry and persist immediately."""
        entry = EvolutionEntry(entry_type, summary, details)
        self._ensure_loaded()
        self._entries.append(entry.to_dict())
        self._persist()
        return entry

    def entries(self) -> list[dict[str, Any]]:
        """Return all ledger entries."""
        self._ensure_loaded()
        return list(self._entries)

    def summary(self) -> dict[str, Any]:
        """Return a high-level summary of evolution history."""
        self._ensure_loaded()
        by_type: dict[str, int] = {}
        for entry in self._entries:
            t = entry.get("type", "unknown")
            by_type[t] = by_type.get(t, 0) + 1
        return {
            "total_evolution_events": len(self._entries),
            "by_type": by_type,
            "latest_event": self._entries[-1] if self._entries else None,
        }

    def _ensure_loaded(self) -> None:
        if self._loaded:
            return
        if self._ledger_path.exists():
            raw = json.loads(self._ledger_path.read_text(encoding="utf-8"))
            if isinstance(raw, list):
                self._entries = raw
        self._loaded = True

    def _persist(self) -> None:
        self.base_dir.mkdir(parents=True, exist_ok=True)
        self._ledger_path.write_text(
            json.dumps(self._entries, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )


# ------------------------------------------------------------------
# Heuristic Evolution
# ------------------------------------------------------------------


class HeuristicEvolver:
    """Discovers new detection heuristics from LLM findings and promotes them
    into AION's built-in ``_SUPPORTED_INCIDENTS`` registry.

    When the LLM analyzer consistently flags a pattern that the built-in
    heuristics don't catch, this evolver can synthesize a new regex-based
    heuristic and add it to the engine's detection arsenal.
    """

    # Patterns that the evolver can automatically synthesize heuristics for.
    # Each entry maps a keyword signature to a new heuristic definition.
    SYNTHESIZABLE_PATTERNS: dict[str, dict[str, object]] = {
        "pickle_load": {
            "issue_type": "insecure_pickle_load",
            "issue": "pickle.load() deserializes arbitrary Python objects and can execute code.",
            "severity": "critical",
            "attack_surface": "deserialization",
            "recommended_action": "auto_repair",
            "remediation_strategy": "safe_json_deserialize",
            "verification_strategy": ["syntax", "pickle_replaced"],
            "detection_pattern": "pickle.load(",
            "detection_desc": "pickle.load called without trusted data source",
        },
        "exec_function": {
            "issue_type": "exec_injection",
            "issue": "exec() with dynamic input enables arbitrary code execution.",
            "severity": "critical",
            "attack_surface": "code_execution",
            "recommended_action": "auto_repair",
            "remediation_strategy": "sandbox_exec",
            "verification_strategy": ["syntax", "exec_removed"],
            "detection_pattern": "exec(",
            "detection_desc": "exec() called with potentially dynamic argument",
        },
        "http_no_timeout": {
            "issue_type": "http_no_timeout",
            "issue": "HTTP request without timeout can hang indefinitely and cause resource exhaustion.",
            "severity": "medium",
            "attack_surface": "network",
            "recommended_action": "auto_repair",
            "remediation_strategy": "add_http_timeout",
            "verification_strategy": ["syntax", "timeout_added"],
            "detection_pattern": "requests.get(",
            "detection_desc": "requests.get without timeout parameter",
        },
        "debug_true": {
            "issue_type": "debug_enabled",
            "issue": "DEBUG=True in production exposes stack traces and internals.",
            "severity": "high",
            "attack_surface": "configuration",
            "recommended_action": "auto_repair",
            "remediation_strategy": "env_debug_flag",
            "verification_strategy": ["syntax", "debug_env_var"],
            "detection_pattern": "DEBUG = True",
            "detection_desc": "DEBUG is hardcoded to True",
        },
        "tempfile_mktemp": {
            "issue_type": "insecure_tempfile",
            "issue": "tempfile.mktemp() is deprecated and vulnerable to race conditions.",
            "severity": "high",
            "attack_surface": "filesystem",
            "recommended_action": "auto_repair",
            "remediation_strategy": "use_mkstemp",
            "verification_strategy": ["syntax", "mktemp_replaced"],
            "detection_pattern": "tempfile.mktemp(",
            "detection_desc": "tempfile.mktemp used instead of mkstemp",
        },
    }

    def discover(
        self,
        findings: list[Finding],
        existing_incident_types: set[str],
        kb: KnowledgeBase,
    ) -> list[dict[str, object]]:
        """Analyze LLM findings to discover candidate heuristics not yet in the engine.

        Returns a list of heuristic definitions ready to be added.
        """
        candidates: list[dict[str, object]] = []

        # Aggregate keywords from findings
        all_text = " ".join(
            f"{f.issue} {f.context_gap} {f.fix}" for f in findings
        ).lower()

        for pattern_key, definition in self.SYNTHESIZABLE_PATTERNS.items():
            issue_type = str(definition["issue_type"])
            if issue_type in existing_incident_types:
                continue  # already handled

            search_text = str(definition["detection_pattern"]).lower()
            if search_text in all_text:
                # Check if knowledge base has related patterns (the pattern
                # was seen before, suggesting it's a recurring issue).
                kb_patterns = kb.get_patterns(issue_type)
                if kb_patterns:
                    candidates.append({
                        **definition,
                        "source": "heuristic_evolution",
                        "confidence": 0.88,
                        "knowledge_base_support": len(kb_patterns),
                    })
                else:
                    # First-time discovery; lower confidence but still a candidate
                    candidates.append({
                        **definition,
                        "source": "heuristic_evolution",
                        "confidence": 0.75,
                        "knowledge_base_support": 0,
                    })

        return candidates


# ------------------------------------------------------------------
# Strategy Evolution
# ------------------------------------------------------------------

class StrategyEvolver:
    """Promotes successful LLM-suggested repair strategies into the
    deterministic ``PatchGenerator``.

    When the LLM analyzer proposes a fix that consistently works across
    multiple repair attempts, this evolver can synthesize a corresponding
    deterministic repair strategy so future occurrences are fixed instantly
    without requiring an LLM call.
    """

    def evaluate_and_promote(
        self,
        knowledge_base: KnowledgeBase,
        min_success_count: int = 3,
        min_success_rate: float = 0.8,
    ) -> list[dict[str, object]]:
        """Scan the knowledge base for patterns that are candidates for promotion
        into deterministic repair strategies.

        Returns promoted strategies ready to be added to the engine.
        """
        patterns = knowledge_base._patterns  # access internal list directly
        promoted: list[dict[str, object]] = []

        for pattern in patterns:
            total = pattern.success_count + pattern.failure_count
            if total == 0:
                continue
            success_rate = pattern.success_count / total

            if pattern.success_count >= min_success_count and success_rate >= min_success_rate:
                # This strategy is consistently successful — it should be promoted
                # to auto_repair if it isn't already.
                promoted.append({
                    "issue_type": pattern.issue_type,
                    "severity": pattern.severity,
                    "strategy": pattern.strategy,
                    "confidence_boost": pattern.confidence_boost,
                    "success_rate": round(success_rate, 4),
                    "total_attempts": total,
                    "action": "promote_to_deterministic",
                })

        return promoted

    def prune_failing_strategies(
        self,
        knowledge_base: KnowledgeBase,
        max_failure_rate: float = 0.7,
        min_attempts: int = 5,
    ) -> list[dict[str, object]]:
        """Identify strategies that consistently fail and should be demoted."""
        patterns = knowledge_base._patterns
        pruned: list[dict[str, object]] = []

        for pattern in patterns:
            total = pattern.success_count + pattern.failure_count
            if total < min_attempts:
                continue
            failure_rate = pattern.failure_count / total

            if failure_rate >= max_failure_rate:
                pruned.append({
                    "issue_type": pattern.issue_type,
                    "strategy": pattern.strategy,
                    "failure_rate": round(failure_rate, 4),
                    "total_attempts": total,
                    "action": "demote_to_human_review",
                })

        return pruned


# ------------------------------------------------------------------
# Confidence Calibration
# ------------------------------------------------------------------


class ConfidenceCalibrator:
    """Auto-tunes confidence thresholds per heuristic based on historical
    accuracy from the knowledge base."""

    def calibrate(
        self,
        knowledge_base: KnowledgeBase,
        issue_types: set[str],
    ) -> dict[str, dict[str, float]]:
        """Return adjusted confidence boosts for each issue type."""
        adjustments: dict[str, dict[str, float]] = {}

        for issue_type in issue_types:
            patterns = knowledge_base.get_patterns(issue_type)
            if not patterns:
                continue

            total_success = sum(p.success_count for p in patterns)
            total_failure = sum(p.failure_count for p in patterns)
            total = total_success + total_failure
            if total < 3:
                continue

            accuracy = total_success / total

            # Adjust confidence delta based on accuracy:
            # - Above 90% accuracy → +0.08 boost
            # - 70-90% accuracy → +0.03 boost
            # - Below 50% accuracy → -0.05 penalty (reduce confidence)
            # - Otherwise → neutral
            if accuracy >= 0.90:
                delta = 0.08
            elif accuracy >= 0.70:
                delta = 0.03
            elif accuracy < 0.50:
                delta = -0.05
            else:
                delta = 0.0

            adjustments[issue_type] = {
                "accuracy": round(accuracy, 4),
                "total_attempts": total,
                "confidence_delta": delta,
            }

        return adjustments


# ------------------------------------------------------------------
# Self-Evolution Engine
# ------------------------------------------------------------------


class SelfEvolveResult:
    """Summary of a single self-evolution run."""

    def __init__(self) -> None:
        self.files_scanned: int = 0
        self.incidents_found: int = 0
        self.patches_generated: int = 0
        self.patches_verified: int = 0
        self.patches_applied: int = 0
        self.heuristics_added: int = 0
        self.strategies_promoted: int = 0
        self.strategies_pruned: int = 0
        self.confidence_calibrations: int = 0
        self.errors: list[str] = []


class SelfEvolveEngine:
    """The core self-evolution engine.

    This is what makes AION *self-evolving*: it runs its own scanning, detection,
    repair, and verification pipeline on its own source code, applies verified
    patches to itself, and continuously improves its heuristics and strategies.

    Usage::

        engine = SelfEvolveEngine()
        result = engine.evolve(dry_run=False)
        print(f"Self-evolved: {result.patches_applied} patches applied")
    """

    # File names that AION should NEVER modify during self-evolution,
    # as they are core to self-evolution itself.
    SELF_PROTECTED_FILES: frozenset[str] = frozenset({
        "self_evolve.py",
        "__init__.py",
        "__main__.py",
    })

    def __init__(self, aion_source_root: Path | None = None) -> None:
        self.source_root = (aion_source_root or self._find_own_source()).resolve()
        self.ledger_dir = self.source_root / ".aion" / "evolution"
        self.knowledge_dir = self.source_root / ".aion" / "knowledge"
        self.ledger = EvolutionLedger(base_dir=self.ledger_dir)
        self.kb = KnowledgeBase(base_dir=self.knowledge_dir)

        # Evolution sub-engines
        self.heuristic_evolver = HeuristicEvolver()
        self.strategy_evolver = StrategyEvolver()
        self.confidence_calibrator = ConfidenceCalibrator()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def evolve(
        self,
        *,
        dry_run: bool = False,
        evolve_heuristics: bool = True,
        evolve_strategies: bool = True,
        calibrate_confidence: bool = True,
    ) -> SelfEvolveResult:
        """Execute the full self-evolution pipeline.

        1. Phase 1 — Self-Scan & Self-Repair: Scan own code, detect incidents,
           generate patches, verify them, apply verified patches.
        2. Phase 2 — Heuristic Evolution: Discover new detection patterns.
        3. Phase 3 — Strategy Evolution: Promote/demote repair strategies.
        4. Phase 4 — Confidence Calibration: Auto-tune thresholds.
        """
        result = SelfEvolveResult()

        # --- Phase 1: Self-Scan & Self-Repair ---
        self._evolve_own_code(result, dry_run=dry_run)

        # --- Phase 2: Heuristic Evolution ---
        if evolve_heuristics:
            self._evolve_heuristics_phase(result, dry_run=dry_run)

        # --- Phase 3: Strategy Evolution ---
        if evolve_strategies:
            self._evolve_strategies_phase(result, dry_run=dry_run)

        # --- Phase 4: Confidence Calibration ---
        if calibrate_confidence:
            self._calibrate_confidence_phase(result, dry_run=dry_run)

        return result

    def scan_self(self) -> list[RepairAttemptRecord]:
        """Run detection only — find incidents in own code without repairing."""
        source_files = self._find_own_python_files()
        context = self._build_own_context_profile()

        detector = IncidentDetector(semgrep_runner=self._build_semgrep_runner())
        records: list[RepairAttemptRecord] = []

        for file_path in source_files:
            incidents = detector.detect(file_path, context)
            record = RepairAttemptRecord(
                target=normalize_path(file_path),
                created_at=datetime.now(timezone.utc).isoformat(),
                context_profile=context,
                incidents=incidents,
            )
            records.append(record)

        return records

    # ------------------------------------------------------------------
    # Phase 1: Self-Scan & Self-Repair
    # ------------------------------------------------------------------

    def _evolve_own_code(self, result: SelfEvolveResult, *, dry_run: bool) -> None:
        """Run the full scan → detect → repair → verify → apply pipeline on AION itself."""
        source_files = self._find_own_python_files()
        result.files_scanned = len(source_files)

        if not source_files:
            result.errors.append("No AION Python source files found.")
            return

        context = self._build_own_context_profile()
        executor = RepairExecutor(
            detector=IncidentDetector(semgrep_runner=self._build_semgrep_runner()),
            generator=PatchGenerator(),
            verifier=Verifier(),
            knowledge_base=self.kb,
        )

        verified_records: list[RepairAttemptRecord] = []
        for file_path in source_files:
            record = executor.run(file_path, context, verify=True)
            if record.incidents:
                result.incidents_found += len(record.incidents)
            if record.artifact is not None:
                result.patches_generated += 1
            if record.verification is not None and record.verification.verdict == "verified_fix":
                result.patches_verified += 1
                verified_records.append(record)

        if not verified_records:
            return

        # Apply verified patches to own source files
        if not dry_run:
            for record in verified_records:
                applied = self._apply_patch_to_self(record)
                if applied:
                    result.patches_applied += 1
                    self.ledger.record(
                        "self_patch",
                        f"Applied verified patch to {record.target}",
                        {
                            "target": record.target,
                            "incident_types": [i.issue_type for i in record.incidents],
                            "verdict": record.verification.verdict if record.verification else "unknown",
                        },
                    )
        else:
            result.patches_applied = len(verified_records)

    def _apply_patch_to_self(self, record: RepairAttemptRecord) -> bool:
        """Apply a verified patch to AION's own source.

        Returns True if the patch was applied successfully.
        """
        if record.artifact is None:
            return False

        target_path = self._resolve_target_path(record.target)
        if target_path is None:
            return False

        # Safety check: never modify self-protected files
        if target_path.name in self.SELF_PROTECTED_FILES:
            return False

        try:
            # Write patched content (replaces original)
            target_path.write_text(record.artifact.patched_content, encoding="utf-8")
            return True
        except OSError:
            return False

    # ------------------------------------------------------------------
    # Phase 2: Heuristic Evolution
    # ------------------------------------------------------------------

    def _evolve_heuristics_phase(self, result: SelfEvolveResult, *, dry_run: bool) -> None:
        """Analyze LLM findings to discover and add new detection heuristics."""
        existing_types = set(IncidentDetector._SUPPORTED_INCIDENTS.keys())

        # Collect all findings from knowledge base and recent scans
        all_findings = self._collect_findings_from_kb()

        candidates = self.heuristic_evolver.discover(
            findings=all_findings,
            existing_incident_types=existing_types,
            kb=self.kb,
        )

        for candidate in candidates:
            if not dry_run:
                issue_type = str(candidate["issue_type"])
                self._add_heuristic(issue_type, candidate)
                result.heuristics_added += 1
                self.ledger.record(
                    "heuristic_added",
                    f"New heuristic: {issue_type} — {candidate.get('detection_desc', '')}",
                    {
                        "issue_type": issue_type,
                        "severity": candidate.get("severity"),
                        "confidence": candidate.get("confidence"),
                    },
                )
            else:
                result.heuristics_added += 1

    def _add_heuristic(self, issue_type: str, definition: dict[str, object]) -> None:
        """Add a new heuristic to IncidentDetector._SUPPORTED_INCIDENTS at runtime."""
        if issue_type in IncidentDetector._SUPPORTED_INCIDENTS:
            return

        IncidentDetector._SUPPORTED_INCIDENTS[issue_type] = {
            "issue": str(definition.get("issue", "")),
            "severity": str(definition.get("severity", "medium")),
            "attack_surface": str(definition.get("attack_surface", "code")),
            "recommended_action": str(definition.get("recommended_action", "auto_repair")),
            "remediation_strategy": str(definition.get("remediation_strategy", "")),
            "verification_strategy": list(definition.get("verification_strategy", [])),
        }

    # ------------------------------------------------------------------
    # Phase 3: Strategy Evolution
    # ------------------------------------------------------------------

    def _evolve_strategies_phase(self, result: SelfEvolveResult, *, dry_run: bool) -> None:
        """Promote successful strategies and prune failing ones."""
        promotions = self.strategy_evolver.evaluate_and_promote(
            knowledge_base=self.kb,
            min_success_count=2,
            min_success_rate=0.75,
        )

        for promo in promotions:
            result.strategies_promoted += 1
            issue_type = str(promo["issue_type"])
            if not dry_run:
                self.ledger.record(
                    "strategy_promoted",
                    f"Strategy {promo['strategy']} for {issue_type} promoted "
                    f"(success rate: {float(promo['success_rate']):.1%})",
                    promo,
                )

        prunes = self.strategy_evolver.prune_failing_strategies(
            knowledge_base=self.kb,
            max_failure_rate=0.75,
            min_attempts=4,
        )

        for pruned in prunes:
            result.strategies_pruned += 1
            if not dry_run:
                self.ledger.record(
                    "strategy_pruned",
                    f"Strategy {pruned['strategy']} for {pruned['issue_type']} pruned "
                    f"(failure rate: {float(pruned['failure_rate']):.1%})",
                    pruned,
                )

    # ------------------------------------------------------------------
    # Phase 4: Confidence Calibration
    # ------------------------------------------------------------------

    def _calibrate_confidence_phase(self, result: SelfEvolveResult, *, dry_run: bool) -> None:
        """Auto-tune confidence thresholds per heuristic based on historical data."""
        existing_types = set(IncidentDetector._SUPPORTED_INCIDENTS.keys())
        adjustments = self.confidence_calibrator.calibrate(
            knowledge_base=self.kb,
            issue_types=existing_types,
        )

        for issue_type, adj in adjustments.items():
            if adj["confidence_delta"] != 0.0:
                result.confidence_calibrations += 1
                if not dry_run:
                    self.ledger.record(
                        "confidence_adjusted",
                        f"Confidence for {issue_type} adjusted by {adj['confidence_delta']:+.2f} "
                        f"(accuracy: {adj['accuracy']:.1%})",
                        adj,
                    )

    # ------------------------------------------------------------------
    # Helper: locate own source
    # ------------------------------------------------------------------

    def _find_own_source(self) -> Path:
        """Heuristically locate AION's own source directory."""
        # The current file is at src/aion/self_evolve.py
        this_file = Path(__file__).resolve()
        # Walk up: self_evolve.py → aion/ → src/ → project root
        aion_pkg = this_file.parent  # src/aion/
        return aion_pkg

    def _find_own_python_files(self) -> list[Path]:
        """Discover all Python files in AION's own source, excluding protected ones."""
        excluded_dirs = {
            ".git", ".venv", "venv", "node_modules", "__pycache__",
            ".nox", ".tox", "site-packages", "dist-packages",
            ".aion", ".pytest_cache", "dist", "site",
        }
        candidates = []
        for path in sorted(self.source_root.rglob("*.py")):
            if any(part in excluded_dirs for part in path.parts):
                continue
            if path.name in self.SELF_PROTECTED_FILES:
                continue
            # Skip egg-info and other generated dirs
            if "egg-info" in str(path):
                continue
            candidates.append(path)
        return candidates

    def _build_own_context_profile(self) -> ContextProfile:
        """Build a context profile for AION's own codebase.

        This lets the engine understand its own architecture (what ORM it uses,
        what auth patterns are present, etc.) so it can make informed repair decisions.
        """
        from .context_extractor import ContextExtractor

        project_root = self.source_root.parent.parent  # src/aion → src → project root
        extractor = ContextExtractor(root=project_root)
        return extractor.extract()

    def _build_semgrep_runner(self) -> SemgrepRunner | None:
        """Build a Semgrep runner if it's available."""
        if semgrep_available():
            return SemgrepRunner()
        return None

    def _resolve_target_path(self, target_str: str) -> Path | None:
        """Resolve a target file string to a Path within AION's source."""
        target = Path(target_str)
        if target.is_absolute():
            return target if target.exists() else None
        # Try relative to source root
        resolved = self.source_root / target.name
        if resolved.exists():
            return resolved
        return None

    def _collect_findings_from_kb(self) -> list[Finding]:
        """Synthesize pseudo-findings from knowledge base patterns for heuristic discovery."""
        findings: list[Finding] = []

        for pattern in self.kb._patterns:
            # Create a synthetic Finding from a KnowledgeBase pattern
            findings.append(
                Finding(
                    issue=pattern.issue_type,
                    severity=pattern.severity,
                    line=0,
                    context_gap=f"Pattern: {pattern.strategy} (success={pattern.success_count}, failure={pattern.failure_count})",
                    fix=f"Strategy: {pattern.strategy}",
                )
            )

        return findings
