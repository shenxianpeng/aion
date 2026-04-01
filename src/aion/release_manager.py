from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

from .models import OrchestrationResult, ReleaseCandidate, RolloutPhase


class ReleaseManager:
    def __init__(self, root: Path):
        self.root = root
        self.root.mkdir(parents=True, exist_ok=True)

    def create_candidate(self, result: OrchestrationResult) -> ReleaseCandidate:
        rollout = result.sandbox.rollout if result.sandbox is not None else None
        recommendation = rollout.recommendation if rollout is not None else "needs_human_review"
        candidate = ReleaseCandidate(
            candidate_id=self._candidate_id(result.event.event_id, result.event.target_file),
            created_at=datetime.now(timezone.utc).isoformat(),
            source_event_id=result.event.event_id,
            target_file=result.event.target_file,
            recommendation=recommendation,
            phases=[
                RolloutPhase(name="canary", percentage=5),
                RolloutPhase(name="staged", percentage=25),
                RolloutPhase(name="broad", percentage=50),
                RolloutPhase(name="full", percentage=100),
            ],
            history=[f"candidate created from event {result.event.event_id}"],
        )
        self._write_candidate(candidate)
        return candidate

    def list_candidates(self, state: str | None = None) -> list[ReleaseCandidate]:
        candidates = [ReleaseCandidate(**json.loads(path.read_text(encoding="utf-8"))) for path in sorted(self.root.glob("*.json"))]
        if state is None:
            return candidates
        return [candidate for candidate in candidates if candidate.state == state]

    def get_candidate(self, candidate_id: str) -> ReleaseCandidate:
        path = self.root / f"{candidate_id}.json"
        return ReleaseCandidate(**json.loads(path.read_text(encoding="utf-8")))

    def approve(self, candidate_id: str, approver: str) -> ReleaseCandidate:
        candidate = self.get_candidate(candidate_id)
        approvals = list(candidate.approvals)
        if approver not in approvals:
            approvals.append(approver)
        updated = candidate.model_copy(
            update={
                "state": "approved",
                "approvals": approvals,
                "history": [*candidate.history, f"approved by {approver}"],
            }
        )
        self._write_candidate(updated)
        return updated

    def reject(self, candidate_id: str, approver: str, reason: str) -> ReleaseCandidate:
        candidate = self.get_candidate(candidate_id)
        updated = candidate.model_copy(
            update={
                "state": "rejected",
                "history": [*candidate.history, f"rejected by {approver}: {reason}"],
            }
        )
        self._write_candidate(updated)
        return updated

    def advance(self, candidate_id: str) -> ReleaseCandidate:
        candidate = self.get_candidate(candidate_id)
        phases = [phase.model_copy() for phase in candidate.phases]
        index = candidate.current_phase_index
        if candidate.state in {"candidate", "rejected", "rolled_back"}:
            raise ValueError(f"cannot advance release in state {candidate.state}")
        if index >= len(phases):
            raise ValueError("release is already complete")

        phases[index].completed = True
        next_index = index + 1
        next_state = "completed" if next_index >= len(phases) else "executing"
        completed_phase = phases[index]
        updated = candidate.model_copy(
            update={
                "state": next_state,
                "phases": phases,
                "current_phase_index": next_index,
                "history": [*candidate.history, f"advanced through {completed_phase.name} ({completed_phase.percentage}%)"],
            }
        )
        self._write_candidate(updated)
        return updated

    def rollback(self, candidate_id: str, reason: str) -> ReleaseCandidate:
        candidate = self.get_candidate(candidate_id)
        updated = candidate.model_copy(
            update={
                "state": "rolled_back",
                "history": [*candidate.history, f"rolled back: {reason}"],
            }
        )
        self._write_candidate(updated)
        return updated

    def _write_candidate(self, candidate: ReleaseCandidate) -> None:
        path = self.root / f"{candidate.candidate_id}.json"
        temp_path = self.root / f".{candidate.candidate_id}.json.tmp"
        temp_path.write_text(candidate.model_dump_json(indent=2), encoding="utf-8")
        temp_path.replace(path)

    def _candidate_id(self, event_id: str, target_file: str) -> str:
        now = datetime.now(timezone.utc).isoformat()
        digest = hashlib.sha256(f"{event_id}:{target_file}:{now}".encode("utf-8")).hexdigest()
        return digest[:14]
