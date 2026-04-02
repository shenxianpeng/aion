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


def test_detects_insecure_yaml_load(tmp_path: Path) -> None:
    source = tmp_path / "demo.py"
    source.write_text(
        "\n".join(
            [
                "import yaml",
                "def load(data: str) -> dict:",
                "    return yaml.load(data)",
            ]
        ),
        encoding="utf-8",
    )

    reasons = fallback_reasons(source, ContextProfile())

    assert any("yaml" in reason.lower() for reason in reasons)


def test_detects_os_system_injection(tmp_path: Path) -> None:
    source = tmp_path / "demo.py"
    source.write_text(
        "\n".join(
            [
                "import os",
                "def run(name: str) -> int:",
                '    return os.system(f"cmd {name}")',
            ]
        ),
        encoding="utf-8",
    )

    reasons = fallback_reasons(source, ContextProfile())

    assert any("command injection" in reason.lower() for reason in reasons)


def test_detects_eval_injection(tmp_path: Path) -> None:
    source = tmp_path / "demo.py"
    source.write_text(
        "\n".join(
            [
                "def evaluate(user_input: str) -> object:",
                "    return eval(user_input)",
            ]
        ),
        encoding="utf-8",
    )

    reasons = fallback_reasons(source, ContextProfile())

    assert any("eval" in reason.lower() for reason in reasons)


def test_detects_subprocess_shell_injection(tmp_path: Path) -> None:
    source = tmp_path / "demo.py"
    source.write_text(
        "\n".join(
            [
                "import subprocess",
                "def run(target: str) -> int:",
                '    return subprocess.call(f"scan {target}", shell=True)',
            ]
        ),
        encoding="utf-8",
    )

    reasons = fallback_reasons(source, ContextProfile())

    assert any("subprocess" in reason.lower() for reason in reasons)


def test_detects_weak_cryptography(tmp_path: Path) -> None:
    source = tmp_path / "demo.py"
    source.write_text(
        "\n".join(
            [
                "import hashlib",
                "def compute_checksum(data: bytes) -> str:",
                "    return hashlib.md5(data).hexdigest()",
            ]
        ),
        encoding="utf-8",
    )

    reasons = fallback_reasons(source, ContextProfile())

    assert any("md5" in reason.lower() or "weak" in reason.lower() for reason in reasons)
