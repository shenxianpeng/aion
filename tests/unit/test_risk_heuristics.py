import json
from pathlib import Path

from aion.models import ContextProfile
from aion.risk_heuristics import fallback_reasons


def test_detects_low_level_db_bypass(tmp_path: Path) -> None:
    source = tmp_path / "demo.py"
    source.write_text("import sqlite3\n", encoding="utf-8")
    profile = ContextProfile(orm="sqlalchemy")

    reasons = fallback_reasons(source, profile)

    assert any("orm" in reason.lower() for reason in reasons)


def test_detects_hardcoded_secret(tmp_path: Path) -> None:
    source = tmp_path / "demo.py"
    source.write_text('API_KEY = "secret"\n', encoding="utf-8")

    reasons = fallback_reasons(source, ContextProfile())

    assert any("secret" in reason.lower() for reason in reasons)


def test_detects_route_missing_auth(tmp_path: Path) -> None:
    source = tmp_path / "demo.py"
    source.write_text(
        "\n".join(
            [
                "from fastapi import APIRouter",
                "router = APIRouter()",
                "@router.get('/admin')",
                "def admin_panel():",
                "    return {'ok': True}",
            ]
        ),
        encoding="utf-8",
    )
    profile = ContextProfile(auth_decorators=["@require_permissions"])

    reasons = fallback_reasons(source, profile)

    assert any("auth" in reason.lower() for reason in reasons)
