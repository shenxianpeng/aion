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


def test_load_update_configs_legacy_flat_format(tmp_path: Path) -> None:
    """load_update_configs wraps the legacy flat format in a single UpdateConfig."""
    (tmp_path / ".aion.yaml").write_text(
        "\n".join(
            [
                "provider: openai",
                "model: gpt-4.1",
                "ignore_paths:",
                "  - tests/*",
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
    assert config.open_pull_requests_limit == 10
    assert config.labels == ["security", "aion"]
    assert config.reviewers == ["team:infra"]
    assert config.assignees == ["bot"]
    assert config.target_branch == "main"
    assert config.commit_message_prefix == "[AION]"


def test_load_update_configs_single_updates_block(tmp_path: Path) -> None:
    """load_update_configs parses a single updates block."""
    (tmp_path / ".aion.yaml").write_text(
        "\n".join(
            [
                "updates:",
                "  - directory: \"/\"",
                "    schedule:",
                "      interval: weekly",
                "      day: monday",
                "      time: \"09:00\"",
                "      timezone: Asia/Shanghai",
                "    provider: deepseek",
                "    model: deepseek-chat",
                "    ignore_paths:",
                "      - tests/*",
                "      - scripts/generated_*.py",
                "    auto_repair_issue_types:",
                "      - raw_sqlite_query",
                "      - hardcoded_secret",
                "    auto_repair_min_confidence: 0.90",
                "    open_pull_requests_limit: 5",
                "    labels:",
                "      - aion",
                "      - security",
                "    reviewers:",
                "      - team:security",
                "    target_branch: develop",
            ]
        ),
        encoding="utf-8",
    )

    configs = load_update_configs(tmp_path)
    assert len(configs) == 1
    c = configs[0]
    assert c.provider == "deepseek"
    assert c.model == "deepseek-chat"
    assert c.ignore_paths == ["tests/*", "scripts/generated_*.py"]
    assert c.auto_repair_issue_types == ["raw_sqlite_query", "hardcoded_secret"]
    assert c.auto_repair_min_confidence == 0.90
    assert c.schedule_interval == "weekly"
    assert c.schedule_day == "monday"
    assert c.schedule_time == "09:00"
    assert c.schedule_timezone == "Asia/Shanghai"
    assert c.open_pull_requests_limit == 5
    assert c.labels == ["aion", "security"]
    assert c.reviewers == ["team:security"]
    assert c.target_branch == "develop"


def test_load_update_configs_multiple_updates_blocks(tmp_path: Path) -> None:
    """load_update_configs parses multiple updates blocks."""
    (tmp_path / ".aion.yaml").write_text(
        "\n".join(
            [
                "updates:",
                "  - directory: \"/\"",
                "    schedule:",
                "      interval: daily",
                "    provider: openai",
                "    open_pull_requests_limit: 3",
                "  - directory: \"/src\"",
                "    schedule:",
                "      interval: weekly",
                "    provider: anthropic",
                "    open_pull_requests_limit: 2",
            ]
        ),
        encoding="utf-8",
    )

    configs = load_update_configs(tmp_path)
    assert len(configs) == 2
    assert configs[0].provider == "openai"
    assert configs[0].schedule_interval == "daily"
    assert configs[0].open_pull_requests_limit == 3
    assert configs[1].provider == "anthropic"
    assert configs[1].schedule_interval == "weekly"
    assert configs[1].open_pull_requests_limit == 2


def test_load_update_configs_no_file_returns_default(tmp_path: Path) -> None:
    """load_update_configs returns a single default UpdateConfig when no .aion.yaml exists."""
    configs = load_update_configs(tmp_path)
    assert len(configs) == 1
    config = configs[0]
    assert config.provider is None
    assert config.ignore_paths == []
    assert config.open_pull_requests_limit == 5


def test_load_update_configs_empty_updates_block_returns_default(tmp_path: Path) -> None:
    """load_update_configs returns defaults when updates: has no items."""
    (tmp_path / ".aion.yaml").write_text(
        "\n".join(
            [
                "# comment",
                "updates:",
                "  # no items",
            ]
        ),
        encoding="utf-8",
    )

    configs = load_update_configs(tmp_path)
    assert len(configs) == 1


def test_load_update_configs_with_all_fields(tmp_path: Path) -> None:
    """load_update_configs handles all supported fields."""
    (tmp_path / ".aion.yaml").write_text(
        "\n".join(
            [
                "updates:",
                "  - directory: \"/\"",
                "    schedule:",
                "      interval: weekly",
                "      day: friday",
                "      time: \"18:00\"",
                "      timezone: UTC",
                "    provider: qwen",
                "    model: qwen-plus",
                "    ignore_paths:",
                "      - tests/*",
                "    auto_repair_issue_types:",
                "      - raw_sqlite_query",
                "      - hardcoded_secret",
                "      - missing_auth_decorator",
                "    auto_repair_min_confidence: 0.95",
                "    sandbox_mode: file",
                "    sandbox_verification_commands:",
                "      - pytest",
                "      - mypy src/",
                "    auto_approve_verified_fixes: true",
                "    rollback_on_verification_failure: false",
                "    open_pull_requests_limit: 10",
                "    labels:",
                "      - aion",
                "    reviewers:",
                "      - user1",
                "      - user2",
                "    assignees:",
                "      - bot",
                "    target_branch: main",
                "    commit_message_prefix: \"[SEC]\"",
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
    """load_update_configs raises ConfigError on bad indentation in legacy format."""
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


def test_load_app_config_falls_back_to_first_updates_block(tmp_path: Path) -> None:
    """load_app_config returns the first updates block when updates: format is used."""
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

    config = load_app_config(tmp_path)
    assert config.provider == "qwen"
    assert config.model == "qwen-plus"
