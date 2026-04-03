from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from pathlib import Path

from .models import (
    ContextProfile,
    DriftReport,
    Incident,
    SecuritySnapshot,
)
from .repair import IncidentDetector

# Directories that are never included in snapshots.
_EXCLUDED_DIRS: frozenset[str] = frozenset({
    ".git",
    ".venv",
    "venv",
    "node_modules",
    "__pycache__",
    ".nox",
    ".tox",
    "site-packages",
    "dist-packages",
    ".aion",
})

_SEVERITY_WEIGHTS: dict[str, float] = {
    "critical": 1.0,
    "high": 0.7,
    "medium": 0.4,
    "low": 0.2,
}


class DriftDetector:
    """Detects security drift between point-in-time snapshots of a codebase.

    Typical workflow::

        detector = DriftDetector()

        # Save baseline once.
        snap = detector.snapshot(Path("src"), context_profile)
        detector.save_snapshot(snap, name="baseline")

        # Later: compare current state against saved baseline.
        baseline = detector.load_snapshot("baseline")
        current  = detector.snapshot(Path("src"), context_profile)
        report   = detector.compare(baseline, current)
        print(report.health_delta, report.new_incidents)
    """

    def __init__(self, snapshots_dir: Path | None = None) -> None:
        self.snapshots_dir = snapshots_dir or Path(".aion/snapshots")

    # ------------------------------------------------------------------
    # Core operations
    # ------------------------------------------------------------------

    def snapshot(self, target: Path, context_profile: ContextProfile) -> SecuritySnapshot:
        """Scan *target* and return a snapshot of its current security state."""
        detector = IncidentDetector()
        files = self._collect_python_files(target)

        all_incidents: list[Incident] = []
        file_hashes: dict[str, str] = {}

        for f in files:
            try:
                content = f.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            file_hashes[str(f)] = hashlib.sha256(content.encode()).hexdigest()
            all_incidents.extend(detector.detect(f, context_profile))

        return SecuritySnapshot(
            target=str(target),
            created_at=datetime.now(tz=timezone.utc).isoformat(),
            file_hashes=file_hashes,
            incidents=all_incidents,
            health_score=self._compute_health_score(all_incidents, len(files)),
        )

    def save_snapshot(self, snapshot: SecuritySnapshot, name: str = "baseline") -> Path:
        """Persist *snapshot* to ``<snapshots_dir>/<name>.json``."""
        self.snapshots_dir.mkdir(parents=True, exist_ok=True)
        path = self.snapshots_dir / f"{name}.json"
        path.write_text(snapshot.model_dump_json(indent=2), encoding="utf-8")
        return path

    def load_snapshot(self, name: str = "baseline") -> SecuritySnapshot | None:
        """Load a previously saved snapshot; returns ``None`` if not found."""
        path = self.snapshots_dir / f"{name}.json"
        if not path.exists():
            return None
        return SecuritySnapshot.model_validate_json(path.read_text(encoding="utf-8"))

    def compare(self, baseline: SecuritySnapshot, current: SecuritySnapshot) -> DriftReport:
        """Return a :class:`DriftReport` that describes drift from *baseline* to *current*."""
        baseline_ids = {incident.id: incident for incident in baseline.incidents}
        current_ids = {incident.id: incident for incident in current.incidents}

        new_incidents = [i for id_, i in current_ids.items() if id_ not in baseline_ids]
        resolved_incidents = [i for id_, i in baseline_ids.items() if id_ not in current_ids]

        # A file is "regressed" when its hash changed AND it now has new incidents.
        new_incident_files = {i.target_file for i in new_incidents}
        regressed_files = [
            path
            for path, hash_ in current.file_hashes.items()
            if path in baseline.file_hashes
            and hash_ != baseline.file_hashes[path]
            and path in new_incident_files
        ]

        health_delta = round(current.health_score - baseline.health_score, 3)
        return DriftReport(
            baseline_snapshot_time=baseline.created_at,
            current_snapshot_time=current.created_at,
            new_incidents=new_incidents,
            resolved_incidents=resolved_incidents,
            regressed_files=regressed_files,
            health_delta=health_delta,
            baseline_health_score=baseline.health_score,
            current_health_score=current.health_score,
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _collect_python_files(self, target: Path) -> list[Path]:
        if target.is_file():
            return [target]
        files: list[Path] = []
        for path in sorted(target.rglob("*.py")):
            if any(part in _EXCLUDED_DIRS for part in path.parts):
                continue
            files.append(path)
        return files

    def _compute_health_score(self, incidents: list[Incident], file_count: int) -> float:
        """Return a 0.0–1.0 health score.

        Each incident penalises the score proportional to its severity.  The
        total penalty is normalised by *file_count* so that larger repositories
        are not unfairly penalised.
        """
        if file_count == 0:
            return 1.0
        total_penalty = sum(_SEVERITY_WEIGHTS.get(i.severity, 0.2) for i in incidents)
        # Cap at 1.0 per file on average so the score stays in [0, 1].
        normalised = min(total_penalty / file_count, 1.0)
        return round(1.0 - normalised, 3)
