from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from .models import Incident, RepairPattern, VerificationResult


class KnowledgeBase:
    """Persistent store of repair patterns learned from past fix attempts.

    Every time a repair is verified successfully the outcome is recorded here.
    Future repairs can query the knowledge base to obtain a *confidence boost*
    that reflects the historical success rate for that issue type.

    Patterns are persisted as JSON at ``<base_dir>/patterns.json`` so that
    knowledge survives across AION invocations — the engine truly evolves.

    Typical workflow::

        kb = KnowledgeBase()

        # After a successful repair:
        kb.record_success(incident, verification)

        # Before generating a patch, check the boost:
        boost = kb.confidence_boost(incident)   # e.g. 0.04
        adjusted_confidence = incident.confidence + boost
    """

    def __init__(self, base_dir: Path | None = None) -> None:
        self.base_dir = base_dir or Path(".aion/knowledge")
        self._patterns_path = self.base_dir / "patterns.json"
        self._patterns: list[RepairPattern] = []
        self._loaded = False

    # ------------------------------------------------------------------
    # Learning
    # ------------------------------------------------------------------

    def record_success(self, incident: Incident, verification: VerificationResult) -> RepairPattern:  # noqa: ARG002
        """Record that *incident* was successfully repaired and verified."""
        self._ensure_loaded()
        now = datetime.now(tz=timezone.utc).isoformat()
        strategy = incident.remediation_strategy or ""

        for existing in self._patterns:
            if existing.issue_type == incident.issue_type and existing.strategy == strategy:
                existing.success_count += 1
                existing.last_seen = now
                self._persist()
                return existing

        pattern = RepairPattern(
            issue_type=incident.issue_type,
            severity=incident.severity,
            strategy=strategy,
            confidence_boost=0.05,
            success_count=1,
            failure_count=0,
            last_seen=now,
        )
        self._patterns.append(pattern)
        self._persist()
        return pattern

    def record_failure(self, incident: Incident) -> None:
        """Record that a repair attempt for *incident* failed verification."""
        self._ensure_loaded()
        now = datetime.now(tz=timezone.utc).isoformat()
        strategy = incident.remediation_strategy or ""

        for existing in self._patterns:
            if existing.issue_type == incident.issue_type and existing.strategy == strategy:
                existing.failure_count += 1
                existing.last_seen = now
                self._persist()
                return

    # ------------------------------------------------------------------
    # Querying
    # ------------------------------------------------------------------

    def get_patterns(self, issue_type: str) -> list[RepairPattern]:
        """Return all patterns for *issue_type*."""
        self._ensure_loaded()
        return [p for p in self._patterns if p.issue_type == issue_type]

    def confidence_boost(self, incident: Incident) -> float:
        """Return an additive confidence boost based on past repairs.

        Returns ``0.0`` when no prior data exists.
        """
        patterns = self.get_patterns(incident.issue_type)
        if not patterns:
            return 0.0
        strategy = incident.remediation_strategy or ""
        strategy_patterns = [p for p in patterns if p.strategy == strategy] or patterns
        best = max(
            strategy_patterns,
            key=lambda p: p.success_count / max(1, p.success_count + p.failure_count),
        )
        success_rate = best.success_count / max(1, best.success_count + best.failure_count)
        return round(best.confidence_boost * success_rate, 4)

    def summary(self) -> dict[str, object]:
        """Return a plain-dict summary of all learned patterns."""
        self._ensure_loaded()
        return {
            "total_patterns": len(self._patterns),
            "patterns": [p.model_dump() for p in self._patterns],
        }

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _ensure_loaded(self) -> None:
        if self._loaded:
            return
        if self._patterns_path.exists():
            raw = json.loads(self._patterns_path.read_text(encoding="utf-8"))
            self._patterns = [RepairPattern.model_validate(item) for item in raw]
        self._loaded = True

    def _persist(self) -> None:
        self.base_dir.mkdir(parents=True, exist_ok=True)
        self._patterns_path.write_text(
            json.dumps([p.model_dump() for p in self._patterns], indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
