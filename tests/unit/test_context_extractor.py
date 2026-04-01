from pathlib import Path

from aion.context_extractor import ContextExtractor


def test_extracts_project_context_and_respects_ignores(tmp_path: Path) -> None:
    (tmp_path / ".gitignore").write_text("ignored.py\n", encoding="utf-8")
    (tmp_path / "ignored.py").write_text("import sqlite3\n", encoding="utf-8")
    (tmp_path / "venv").mkdir()
    (tmp_path / "venv" / "skip.py").write_text("import requests\n", encoding="utf-8")
    (tmp_path / "app.py").write_text(
        "\n".join(
            [
                "import sqlalchemy",
                "",
                "@login_required",
                "def handler():",
                "    session.query(User).all()",
            ]
        ),
        encoding="utf-8",
    )

    extractor = ContextExtractor(root=tmp_path, cache_path=tmp_path / "context-cache.json")
    profile = extractor.extract()

    assert profile.scanned_files == 1
    assert profile.orm == "sqlalchemy"
    assert "@login_required" in profile.auth_decorators
    assert "session.query()" in profile.db_patterns
    assert "sqlalchemy" in profile.imports
    assert "handler" in profile.function_names


def test_uses_file_hash_cache_on_second_run(tmp_path: Path) -> None:
    source = tmp_path / "app.py"
    source.write_text("import sqlalchemy\n", encoding="utf-8")
    cache_path = tmp_path / "context-cache.json"

    ContextExtractor(root=tmp_path, cache_path=cache_path).extract()
    cached_extractor = ContextExtractor(root=tmp_path, cache_path=cache_path)

    def fail_if_called(*_args, **_kwargs):
        raise AssertionError("cache miss")

    cached_extractor._extract_file = fail_if_called  # type: ignore[method-assign]
    profile = cached_extractor.extract()

    assert profile.orm == "sqlalchemy"
