from pathlib import Path

import pytest

from aion.config import ConfigError, load_app_config, load_update_configs


def test_load_app_config_reads_yaml_values(tmp_path: Path) -> None:
    (tmp_path / ".aion.yaml").write_text(
        "\n".join(
            [
                "provider: openai",
                "model: gpt-4.1",
                "ignore_paths:",
                "  - tests/*",
                "  - scripts/generated_*.py",
                "auto_repair_issue_types:",
                "  - hardcoded_secret",
                "auto_repair_min_confidence: 0.95",
                "sandbox_mode: file",
                "sandbox_verification_commands:",
                "  - python -c \"print('ok')\"",
                "auto_approve_verified_fixes: true",
                "rollback_on_verification_failure: false",
                "schedule:",
                "  interval: weekly",
                "  day: friday",
                "  time: \"18:00\"",
                "  timezone: UTC",
                "open_pull_requests_limit: 10",
                "labels:",
                "  - security",
                "  - aion",
            ]
        ),
        encoding="utf-8",
    )

    config = load_app_config(tmp_path)

    assert config.provider == "openai"
    assert config.model == "gpt-4.1"
    assert config.ignore_paths == ["tests/*", "scripts/generated_*.py"]
    assert config.auto_repair_issue_types == ["hardcoded_secret"]
    assert config.auto_repair_min_confidence == 0.95
    assert config.sandbox_mode == "file"
    assert config.sandbox_verification_commands == ['python -c "print(\'ok\')"']
    assert config.auto_approve_verified_fixes is True
    assert config.rollback_on_verification_failure is False
    assert config.schedule_interval == "weekly"
    assert config.schedule_day == "friday"
    assert config.schedule_time == "18:00"
    assert config.schedule_timezone == "UTC"
    assert config.open_pull_requests_limit == 10
    assert config.labels == ["security", "aion"]


def test_load_update_configs_flat_format(tmp_path: Path) -> None:
    """load_update_configs wraps the flat format in a single UpdateConfig."""
    (tmp_path / ".aion.yaml").write_text(
        "\n".join(
            [
                "provider: openai",
                "model: gpt-4.1",
                "ignore_paths:",
                "  - tests/*",
                "schedule:",
                "  interval: monthly",
                "  day: tuesday",
                "  time: \"10:30\"",
                "  timezone: Europe/Vilnius",
                "open_pull_requests_limit: 10",
                "labels:",
                "  - security",
                "  - aion",
                "reviewers:",
                "  - team:infra",
                "assignees:",
                "  - bot",
                "target_branch: main",
                "commit_message_prefix: \"[AION]\"",
            ]
        ),
        encoding="utf-8",
    )

    configs = load_update_configs(tmp_path)
    assert len(configs) == 1
    config = configs[0]
    assert config.provider == "openai"
    assert config.model == "gpt-4.1"
    assert config.ignore_paths == ["tests/*"]
    assert config.schedule_interval == "monthly"
    assert config.schedule_day == "tuesday"
    assert config.schedule_time == "10:30"
    assert config.schedule_timezone == "Europe/Vilnius"
    assert config.open_pull_requests_limit == 10
    assert config.labels == ["security", "aion"]
    assert config.reviewers == ["team:infra"]
    assert config.assignees == ["bot"]
    assert config.target_branch == "main"
    assert config.commit_message_prefix == "[AION]"


def test_load_update_configs_no_file_returns_default(tmp_path: Path) -> None:
    """load_update_configs returns a single default UpdateConfig when no .aion.yaml exists."""
    configs = load_update_configs(tmp_path)
    assert len(configs) == 1
    config = configs[0]
    assert config.provider is None
    assert config.ignore_paths == []
    assert config.open_pull_requests_limit == 5


def test_load_update_configs_with_all_fields(tmp_path: Path) -> None:
    """load_update_configs handles all supported fields."""
    (tmp_path / ".aion.yaml").write_text(
        "\n".join(
            [
                "directory: \"/\"",
                "schedule:",
                "  interval: weekly",
                "  day: friday",
                "  time: \"18:00\"",
                "  timezone: UTC",
                "provider: qwen",
                "model: qwen-plus",
                "ignore_paths:",
                "  - tests/*",
                "auto_repair_issue_types:",
                "  - raw_sqlite_query",
                "  - hardcoded_secret",
                "  - missing_auth_decorator",
                "auto_repair_min_confidence: 0.95",
                "sandbox_mode: file",
                "sandbox_verification_commands:",
                "  - pytest",
                "  - mypy src/",
                "auto_approve_verified_fixes: true",
                "rollback_on_verification_failure: false",
                "open_pull_requests_limit: 10",
                "labels:",
                "  - aion",
                "reviewers:",
                "  - user1",
                "  - user2",
                "assignees:",
                "  - bot",
                "target_branch: main",
                "commit_message_prefix: \"[SEC]\"",
            ]
        ),
        encoding="utf-8",
    )

    configs = load_update_configs(tmp_path)
    assert len(configs) == 1
    c = configs[0]
    assert c.provider == "qwen"
    assert c.model == "qwen-plus"
    assert c.schedule_interval == "weekly"
    assert c.schedule_day == "friday"
    assert c.schedule_time == "18:00"
    assert c.schedule_timezone == "UTC"
    assert c.auto_repair_issue_types == ["raw_sqlite_query", "hardcoded_secret", "missing_auth_decorator"]
    assert c.auto_repair_min_confidence == 0.95
    assert c.sandbox_mode == "file"
    assert c.sandbox_verification_commands == ["pytest", "mypy src/"]
    assert c.auto_approve_verified_fixes is True
    assert c.rollback_on_verification_failure is False
    assert c.open_pull_requests_limit == 10
    assert c.labels == ["aion"]
    assert c.reviewers == ["user1", "user2"]
    assert c.assignees == ["bot"]
    assert c.target_branch == "main"
    assert c.commit_message_prefix == "[SEC]"


def test_load_update_configs_invalid_indentation_raises(tmp_path: Path) -> None:
    """load_update_configs raises ConfigError on bad indentation in flat format."""
    (tmp_path / ".aion.yaml").write_text(
        "\n".join(
            [
                "provider: openai",
                "  bad-indent: value",
            ]
        ),
        encoding="utf-8",
    )

    with pytest.raises(ConfigError, match="unexpected indentation"):
        load_update_configs(tmp_path)


def test_updates_block_is_not_supported(tmp_path: Path) -> None:
    (tmp_path / ".aion.yaml").write_text(
        "\n".join(
            [
                "updates:",
                "  - directory: \"/\"",
                "    provider: qwen",
                "    model: qwen-plus",
            ]
        ),
        encoding="utf-8",
    )

    with pytest.raises(ConfigError, match="updates blocks are no longer supported"):
        load_app_config(tmp_path)
