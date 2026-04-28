"""Tests for the auto-update engine."""

from pathlib import Path

from aion.auto_update import AutoUpdateEngine, AutoUpdateResult
from aion.config import UpdateConfig


def test_auto_update_result_defaults() -> None:
    """AutoUpdateResult initializes with all zeros."""
    result = AutoUpdateResult()
    assert result.files_scanned == 0
    assert result.incidents_found == 0
    assert result.patches_generated == 0
    assert result.patches_verified == 0
    assert result.prs_created == 0
    assert result.errors == []


def test_auto_update_engine_init_without_config(tmp_path: Path) -> None:
    """AutoUpdateEngine initializes with defaults when no .aion.yaml exists."""
    engine = AutoUpdateEngine(root=tmp_path)
    assert engine.root == tmp_path.resolve()
    assert isinstance(engine.config, UpdateConfig)


def test_auto_update_engine_init_with_config(tmp_path: Path) -> None:
    """AutoUpdateEngine respects an explicit UpdateConfig."""
    config = UpdateConfig(
        ignore_paths=["tests/*", "*.generated.py"],
        open_pull_requests_limit=3,
        labels=["aion"],
        reviewers=["team:security"],
        assignees=["bot"],
        target_branch="develop",
        commit_message_prefix="[SEC]",
        directory="/src",
    )
    engine = AutoUpdateEngine(root=tmp_path, update_config=config)
    assert engine.config.ignore_paths == ["tests/*", "*.generated.py"]
    assert engine.config.open_pull_requests_limit == 3
    assert engine.config.labels == ["aion"]
    assert engine.config.reviewers == ["team:security"]
    assert engine.config.assignees == ["bot"]
    assert engine.config.target_branch == "develop"
    assert engine.config.commit_message_prefix == "[SEC]"
    assert engine.config.directory == "/src"


def test_find_python_files_respects_ignore_paths(tmp_path: Path) -> None:
    """_find_python_files excludes files matching ignore_paths."""
    (tmp_path / "main.py").write_text("x = 1\n")
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "test_main.py").write_text("def test(): pass\n")
    (tmp_path / "generated").mkdir()
    (tmp_path / "generated" / "gen.py").write_text("# auto-generated\n")

    config = UpdateConfig(ignore_paths=["tests/*", "generated/*"])
    engine = AutoUpdateEngine(root=tmp_path, update_config=config)

    files = engine._find_python_files()
    names = [f.name for f in files]
    assert "main.py" in names
    assert "test_main.py" not in names
    assert "gen.py" not in names


def test_find_python_files_excludes_dot_dirs(tmp_path: Path) -> None:
    """_find_python_files excludes .git, .venv, etc."""
    (tmp_path / "main.py").write_text("x = 1\n")
    (tmp_path / ".venv" / "lib").mkdir(parents=True)
    (tmp_path / ".venv" / "lib" / "dep.py").write_text("x = 2\n")
    (tmp_path / ".git" / "hooks").mkdir(parents=True)
    (tmp_path / ".git" / "hooks" / "hook.py").write_text("x = 3\n")
    (tmp_path / "node_modules" / "pkg").mkdir(parents=True)
    (tmp_path / "node_modules" / "pkg" / "index.py").write_text("x = 4\n")
    (tmp_path / ".nox" / "session").mkdir(parents=True)
    (tmp_path / ".nox" / "session" / "tool.py").write_text("x = 5\n")
    (tmp_path / ".tox" / "env").mkdir(parents=True)
    (tmp_path / ".tox" / "env" / "tool.py").write_text("x = 6\n")

    engine = AutoUpdateEngine(root=tmp_path, update_config=UpdateConfig())
    files = engine._find_python_files()
    names = [f.name for f in files]
    assert names == ["main.py"]


def test_find_python_files_includes_subdirs(tmp_path: Path) -> None:
    """_find_python_files finds files in subdirectories."""
    (tmp_path / "main.py").write_text("x = 1\n")
    (tmp_path / "src" / "app").mkdir(parents=True)
    (tmp_path / "src" / "app" / "views.py").write_text("y = 2\n")
    (tmp_path / "src" / "app" / "models.py").write_text("z = 3\n")

    engine = AutoUpdateEngine(root=tmp_path, update_config=UpdateConfig())
    files = engine._find_python_files()
    names = sorted(f.name for f in files)
    assert names == ["main.py", "models.py", "views.py"]


def test_matches_ignore_pattern_glob(tmp_path: Path) -> None:
    """_matches_ignore_pattern supports glob patterns."""
    (tmp_path / "tests").mkdir(parents=True)
    (tmp_path / "tests" / "test_a.py").write_text("pass\n")

    config = UpdateConfig(ignore_paths=["tests/*"])
    engine = AutoUpdateEngine(root=tmp_path, update_config=config)

    test_file = tmp_path / "tests" / "test_a.py"
    assert engine._matches_ignore_pattern(test_file) is True

    main_file = tmp_path / "main.py"
    main_file.write_text("pass\n")
    assert engine._matches_ignore_pattern(main_file) is False


def test_matches_ignore_pattern_by_name(tmp_path: Path) -> None:
    """_matches_ignore_pattern matches on filename alone."""
    (tmp_path / "generated_api.py").write_text("# auto\n")

    config = UpdateConfig(ignore_paths=["generated_*.py"])
    engine = AutoUpdateEngine(root=tmp_path, update_config=config)

    assert engine._matches_ignore_pattern(tmp_path / "generated_api.py") is True
    tmp_file = tmp_path / "normal.py"
    tmp_file.write_text("# normal\n")
    assert engine._matches_ignore_pattern(tmp_file) is False


def test_branch_name_generates_unique_name(monkeypatch, tmp_path: Path) -> None:
    """_branch_name produces a concise, unique branch name."""
    from aion.models import PatchArtifact

    engine = AutoUpdateEngine(root=tmp_path)
    artifact = PatchArtifact(
        incident_ids=["inc-1"],
        target_file="/abs/path/to/my_service.py",
        original_content="",
        patched_content="",
        diff="",
    )
    name = engine._branch_name(artifact)
    assert name.startswith("aion/fix-my_service-")
    assert len(name) > len("aion/fix-my_service-")


def test_commit_summary_handles_one_issue(monkeypatch, tmp_path: Path) -> None:
    """_commit_summary formats a single issue type."""
    from aion.models import ContextProfile, Incident, RepairAttemptRecord

    engine = AutoUpdateEngine(root=tmp_path)
    record = RepairAttemptRecord(
        target="/path/to/file.py",
        created_at="2026-01-01T00:00:00+00:00",
        context_profile=ContextProfile(),
        incidents=[
            Incident(
                id="i1",
                source="scan",
                target_file="/path/to/file.py",
                issue_type="hardcoded_secret",
                issue="API key in source",
                severity="critical",
                line=10,
                confidence=0.95,
            )
        ],
        artifact=None,
    )
    summary = engine._commit_summary(record)
    assert summary == "hardcoded_secret in file.py"


def test_commit_summary_handles_multiple_issues(monkeypatch, tmp_path: Path) -> None:
    """_commit_summary formats up to 3 issue types."""
    from aion.models import ContextProfile, Incident, RepairAttemptRecord

    engine = AutoUpdateEngine(root=tmp_path)
    record = RepairAttemptRecord(
        target="/path/to/service.py",
        created_at="2026-01-01T00:00:00+00:00",
        context_profile=ContextProfile(),
        incidents=[
            Incident(
                id="i1", source="scan", target_file="/path/to/service.py",
                issue_type="hardcoded_secret", issue="a", severity="critical",
                line=1, confidence=0.9,
            ),
            Incident(
                id="i2", source="scan", target_file="/path/to/service.py",
                issue_type="raw_sqlite_query", issue="b", severity="high",
                line=2, confidence=0.8,
            ),
            Incident(
                id="i3", source="scan", target_file="/path/to/service.py",
                issue_type="command_injection", issue="c", severity="high",
                line=3, confidence=0.7,
            ),
        ],
        artifact=None,
    )
    summary = engine._commit_summary(record)
    assert summary == "command_injection, hardcoded_secret, raw_sqlite_query in service.py"


def test_pr_title_formats_issues(monkeypatch, tmp_path: Path) -> None:
    """_pr_title includes issue types and target filename."""
    from aion.models import ContextProfile, Incident, RepairAttemptRecord

    config = UpdateConfig(commit_message_prefix="[FIX]")
    engine = AutoUpdateEngine(root=tmp_path, update_config=config)
    record = RepairAttemptRecord(
        target="/path/to/app.py",
        created_at="2026-01-01T00:00:00+00:00",
        context_profile=ContextProfile(),
        incidents=[
            Incident(
                id="i1", source="scan", target_file="/path/to/app.py",
                issue_type="hardcoded_secret", issue="secret", severity="critical",
                line=1, confidence=0.9,
            ),
        ],
        artifact=None,
    )
    title = engine._pr_title(record)
    assert title == "[FIX] fix: hardcoded_secret in app.py"


def test_relative_path_computation(tmp_path: Path) -> None:
    """_relative_path returns a path relative to the repo root."""
    engine = AutoUpdateEngine(root=tmp_path)
    target = tmp_path / "src" / "sub" / "file.py"
    relative = engine._relative_path(target)
    assert relative == "src/sub/file.py"


def test_github_repo_from_env(monkeypatch, tmp_path: Path) -> None:
    """_github_repo reads from GITHUB_REPOSITORY env var."""
    monkeypatch.setenv("GITHUB_REPOSITORY", "owner/repo")
    engine = AutoUpdateEngine(root=tmp_path)
    assert engine._github_repo() == "owner/repo"


def test_run_no_files_returns_early(tmp_path: Path) -> None:
    """AutoUpdateEngine.run returns early when no Python files exist."""
    engine = AutoUpdateEngine(root=tmp_path)
    result = engine.run(dry_run=True)
    assert result.files_scanned == 0
    assert result.incidents_found == 0
    assert result.patches_generated == 0
    assert result.patches_verified == 0
    assert result.prs_created == 0
