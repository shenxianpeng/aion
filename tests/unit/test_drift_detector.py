from __future__ import annotations

import json
from pathlib import Path

import pytest

from aion.drift_detector import DriftDetector
from aion.models import ContextProfile, SecuritySnapshot


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _context() -> ContextProfile:
    return ContextProfile()


def _vulnerable_content() -> str:
    return (
        'import sqlite3\n'
        'conn = sqlite3.connect("db.sqlite")\n'
        'cursor = conn.cursor()\n'
        'user_id = "123"\n'
        'cursor.execute(f"SELECT * FROM users WHERE id = \'{user_id}\'")\n'
    )


def _safe_content() -> str:
    return (
        'import sqlite3\n'
        'conn = sqlite3.connect("db.sqlite")\n'
        'cursor = conn.cursor()\n'
        'user_id = "123"\n'
        'cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))\n'
    )


# ---------------------------------------------------------------------------
# DriftDetector.snapshot
# ---------------------------------------------------------------------------


def test_snapshot_single_file(tmp_path: Path) -> None:
    f = tmp_path / "app.py"
    f.write_text(_vulnerable_content(), encoding="utf-8")

    detector = DriftDetector(snapshots_dir=tmp_path / "snaps")
    snap = detector.snapshot(f, _context())

    assert snap.target == str(f)
    assert str(f) in snap.file_hashes
    assert len(snap.incidents) >= 1
    assert 0.0 <= snap.health_score <= 1.0


def test_snapshot_safe_file_has_perfect_health(tmp_path: Path) -> None:
    f = tmp_path / "safe.py"
    f.write_text(_safe_content(), encoding="utf-8")

    detector = DriftDetector(snapshots_dir=tmp_path / "snaps")
    snap = detector.snapshot(f, _context())

    assert snap.incidents == []
    assert snap.health_score == 1.0


def test_snapshot_directory(tmp_path: Path) -> None:
    src = tmp_path / "src"
    src.mkdir()
    (src / "a.py").write_text(_safe_content(), encoding="utf-8")
    (src / "b.py").write_text(_vulnerable_content(), encoding="utf-8")

    detector = DriftDetector(snapshots_dir=tmp_path / "snaps")
    snap = detector.snapshot(src, _context())

    assert len(snap.file_hashes) == 2
    assert len(snap.incidents) >= 1


def test_snapshot_excludes_venv(tmp_path: Path) -> None:
    (tmp_path / ".venv").mkdir()
    (tmp_path / ".venv" / "helper.py").write_text(_vulnerable_content(), encoding="utf-8")
    (tmp_path / "main.py").write_text(_safe_content(), encoding="utf-8")

    detector = DriftDetector(snapshots_dir=tmp_path / "snaps")
    snap = detector.snapshot(tmp_path, _context())

    assert all(".venv" not in p for p in snap.file_hashes)


# ---------------------------------------------------------------------------
# DriftDetector.save_snapshot / load_snapshot
# ---------------------------------------------------------------------------


def test_save_and_load_snapshot(tmp_path: Path) -> None:
    snaps_dir = tmp_path / "snaps"
    detector = DriftDetector(snapshots_dir=snaps_dir)

    f = tmp_path / "app.py"
    f.write_text(_safe_content(), encoding="utf-8")
    snap = detector.snapshot(f, _context())

    saved_path = detector.save_snapshot(snap, name="baseline")
    assert saved_path.exists()
    assert saved_path.name == "baseline.json"

    loaded = detector.load_snapshot("baseline")
    assert loaded is not None
    assert loaded.target == snap.target
    assert loaded.health_score == snap.health_score


def test_load_snapshot_returns_none_when_missing(tmp_path: Path) -> None:
    detector = DriftDetector(snapshots_dir=tmp_path / "snaps")
    result = detector.load_snapshot("nonexistent")
    assert result is None


# ---------------------------------------------------------------------------
# DriftDetector.compare
# ---------------------------------------------------------------------------


def test_compare_no_drift(tmp_path: Path) -> None:
    f = tmp_path / "safe.py"
    f.write_text(_safe_content(), encoding="utf-8")

    detector = DriftDetector(snapshots_dir=tmp_path / "snaps")
    baseline = detector.snapshot(f, _context())
    current = detector.snapshot(f, _context())

    report = detector.compare(baseline, current)

    assert report.new_incidents == []
    assert report.has_regression is False
    assert report.health_delta == 0.0


def test_compare_detects_new_incident(tmp_path: Path) -> None:
    f = tmp_path / "app.py"
    f.write_text(_safe_content(), encoding="utf-8")

    detector = DriftDetector(snapshots_dir=tmp_path / "snaps")
    baseline = detector.snapshot(f, _context())

    # Introduce a vulnerability after the baseline.
    f.write_text(_vulnerable_content(), encoding="utf-8")
    current = detector.snapshot(f, _context())

    report = detector.compare(baseline, current)

    assert len(report.new_incidents) >= 1
    assert report.has_regression is True
    assert report.health_delta < 0


def test_compare_detects_resolved_incident(tmp_path: Path) -> None:
    f = tmp_path / "app.py"
    f.write_text(_vulnerable_content(), encoding="utf-8")

    detector = DriftDetector(snapshots_dir=tmp_path / "snaps")
    baseline = detector.snapshot(f, _context())

    # Fix the vulnerability.
    f.write_text(_safe_content(), encoding="utf-8")
    current = detector.snapshot(f, _context())

    report = detector.compare(baseline, current)

    assert len(report.resolved_incidents) >= 1
    assert report.has_regression is False
    assert report.health_delta >= 0


def test_compare_regression_marks_regressed_files(tmp_path: Path) -> None:
    f = tmp_path / "app.py"
    f.write_text(_safe_content(), encoding="utf-8")

    detector = DriftDetector(snapshots_dir=tmp_path / "snaps")
    baseline = detector.snapshot(f, _context())

    f.write_text(_vulnerable_content(), encoding="utf-8")
    current = detector.snapshot(f, _context())

    report = detector.compare(baseline, current)

    assert str(f) in report.regressed_files


# ---------------------------------------------------------------------------
# Health score
# ---------------------------------------------------------------------------


def test_health_score_zero_files() -> None:
    detector = DriftDetector()
    score = detector._compute_health_score([], 0)
    assert score == 1.0


def test_health_score_decreases_with_critical_incidents(tmp_path: Path) -> None:
    vuln = tmp_path / "vuln.py"
    vuln.write_text(_vulnerable_content(), encoding="utf-8")

    safe = tmp_path / "safe.py"
    safe.write_text(_safe_content(), encoding="utf-8")

    detector = DriftDetector(snapshots_dir=tmp_path / "snaps")
    snap_vuln = detector.snapshot(vuln, _context())
    snap_safe = detector.snapshot(safe, _context())

    assert snap_vuln.health_score < snap_safe.health_score
