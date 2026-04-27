from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class AppConfig:
    provider: str | None = None
    model: str | None = None
    ignore_paths: list[str] = field(default_factory=list)
    auto_repair_issue_types: list[str] = field(default_factory=lambda: [
        "raw_sqlite_query",
        "hardcoded_secret",
        "missing_auth_decorator",
        "insecure_yaml_load",
        "command_injection",
    ])
    auto_repair_min_confidence: float = 0.85
    sandbox_mode: str = "repository"
    sandbox_verification_commands: list[str] = field(default_factory=list)
    auto_approve_verified_fixes: bool = False
    rollback_on_verification_failure: bool = True
    # Auto-update fields
    schedule_interval: str = "weekly"
    schedule_day: str = "monday"
    schedule_time: str = "09:00"
    schedule_timezone: str = "UTC"
    open_pull_requests_limit: int = 5
    labels: list[str] = field(default_factory=list)
    reviewers: list[str] = field(default_factory=list)
    assignees: list[str] = field(default_factory=list)
    target_branch: str = "main"
    commit_message_prefix: str = "[AION]"
    directory: str = "/"


@dataclass
class UpdateConfig(AppConfig):
    """A single update block within a .aion.yaml ``updates`` list."""
    pass


class ConfigError(RuntimeError):
    pass


def load_app_config(root: Path) -> AppConfig:
    """Load configuration from .aion.yaml (legacy flat format)."""
    config_path = root / ".aion.yaml"
    if not config_path.exists():
        return AppConfig()

    raw = config_path.read_text(encoding="utf-8")
    if "updates:" in raw:
        # Updates-block format — extract the first block for backward compat
        configs = load_update_configs(root)
        return configs[0] if configs else AppConfig()

    return _parse_config(config_path)


def load_update_configs(root: Path) -> list[UpdateConfig]:
    """Load AION update configurations from .aion.yaml.

    Returns a list of UpdateConfig objects, one per ``updates`` block.
    Falls back to the legacy flat format when no ``updates:`` key is present.
    """
    config_path = root / ".aion.yaml"
    if not config_path.exists():
        return [UpdateConfig()]

    raw = config_path.read_text(encoding="utf-8")
    if "updates:" not in raw:
        # Legacy flat format — wrap in a single UpdateConfig
        legacy = {k: v for k, v in _parse_config(config_path).__dict__.items() if not k.startswith("_")}
        return [UpdateConfig(**legacy)]  # type: ignore[arg-type]

    return _parse_updates_config(config_path)


# ── legacy flat format parser ──────────────────────────────────────────────

def _parse_config(path: Path) -> AppConfig:
    lines = path.read_text(encoding="utf-8").splitlines()
    data: dict[str, object] = {}
    index = 0

    while index < len(lines):
        raw_line = lines[index]
        stripped = raw_line.strip()
        index += 1

        if not stripped or stripped.startswith("#"):
            continue
        if raw_line.startswith((" ", "\t")):
            raise ConfigError(f"unexpected indentation in {path}")
        if ":" not in raw_line:
            raise ConfigError(f"invalid config line: {raw_line}")

        key, value = raw_line.split(":", 1)
        key = key.strip()
        value = value.strip()

        if not value:
            items: list[str] = []
            while index < len(lines):
                nested_raw = lines[index]
                nested = nested_raw.strip()
                if not nested or nested.startswith("#"):
                    index += 1
                    continue
                if not nested_raw.startswith(("  ", "\t")):
                    break
                if not nested.startswith("- "):
                    raise ConfigError(f"invalid list item in {path}: {nested_raw}")
                items.append(_parse_scalar(nested[2:].strip()))
                index += 1
            data[key] = items
            continue

        data[key] = _parse_scalar(value)

    return _app_config_from_data(data)


def _app_config_from_data(data: dict[str, object]) -> AppConfig:
    ignore_paths = data.get("ignore_paths", [])
    if not isinstance(ignore_paths, list):
        raise ConfigError("ignore_paths must be a list")

    provider = data.get("provider")
    model = data.get("model")
    auto_repair_issue_types = data.get("auto_repair_issue_types", AppConfig().auto_repair_issue_types)
    if not isinstance(auto_repair_issue_types, list):
        raise ConfigError("auto_repair_issue_types must be a list")
    min_confidence = data.get("auto_repair_min_confidence", AppConfig().auto_repair_min_confidence)
    try:
        min_confidence_value = float(min_confidence)
    except (TypeError, ValueError) as exc:
        raise ConfigError("auto_repair_min_confidence must be a float") from exc
    sandbox_mode = str(data.get("sandbox_mode", AppConfig().sandbox_mode))
    if sandbox_mode not in {"file", "repository"}:
        raise ConfigError("sandbox_mode must be 'file' or 'repository'")
    sandbox_verification_commands = data.get("sandbox_verification_commands", [])
    if not isinstance(sandbox_verification_commands, list):
        raise ConfigError("sandbox_verification_commands must be a list")
    auto_approve_verified_fixes = _parse_bool(
        data.get("auto_approve_verified_fixes", AppConfig().auto_approve_verified_fixes),
        "auto_approve_verified_fixes",
    )
    rollback_on_verification_failure = _parse_bool(
        data.get("rollback_on_verification_failure", AppConfig().rollback_on_verification_failure),
        "rollback_on_verification_failure",
    )
    schedule_interval = str(data.get("schedule_interval", AppConfig().schedule_interval) if data.get("schedule") is None else dict(data["schedule"]).get("interval", AppConfig().schedule_interval))  # type: ignore[arg-type]
    schedule_day = str(data.get("schedule_day", AppConfig().schedule_day) if data.get("schedule") is None else dict(data["schedule"]).get("day", AppConfig().schedule_day))  # type: ignore[arg-type]
    schedule_time = str(data.get("schedule_time", AppConfig().schedule_time) if data.get("schedule") is None else dict(data["schedule"]).get("time", AppConfig().schedule_time))  # type: ignore[arg-type]
    schedule_timezone = str(data.get("schedule_timezone", AppConfig().schedule_timezone) if data.get("schedule") is None else dict(data["schedule"]).get("timezone", AppConfig().schedule_timezone))  # type: ignore[arg-type]

    open_pull_requests_limit = _parse_int(data.get("open_pull_requests_limit", AppConfig().open_pull_requests_limit), "open_pull_requests_limit", AppConfig().open_pull_requests_limit)
    labels = data.get("labels", [])
    if not isinstance(labels, list):
        labels = []
    reviewers = data.get("reviewers", [])
    if not isinstance(reviewers, list):
        reviewers = []
    assignees = data.get("assignees", [])
    if not isinstance(assignees, list):
        assignees = []
    target_branch = str(data.get("target_branch", AppConfig().target_branch))
    commit_message_prefix = str(data.get("commit_message_prefix", AppConfig().commit_message_prefix))
    directory = str(data.get("directory", AppConfig().directory))

    return AppConfig(
        provider=str(provider) if provider is not None else None,
        model=str(model) if model is not None else None,
        ignore_paths=[str(item) for item in ignore_paths],
        auto_repair_issue_types=[str(item) for item in auto_repair_issue_types],
        auto_repair_min_confidence=min_confidence_value,
        sandbox_mode=sandbox_mode,
        sandbox_verification_commands=[str(item) for item in sandbox_verification_commands],
        auto_approve_verified_fixes=auto_approve_verified_fixes,
        rollback_on_verification_failure=rollback_on_verification_failure,
        schedule_interval=schedule_interval,
        schedule_day=schedule_day,
        schedule_time=schedule_time,
        schedule_timezone=schedule_timezone,
        open_pull_requests_limit=open_pull_requests_limit,
        labels=[str(item) for item in labels],
        reviewers=[str(item) for item in reviewers],
        assignees=[str(item) for item in assignees],
        target_branch=target_branch,
        commit_message_prefix=commit_message_prefix,
        directory=directory,
    )


# ── updates-block parser (Dependabot-like) ─────────────────────────────────

def _parse_updates_config(path: Path) -> list[UpdateConfig]:
    """Parse .aion.yaml with ``updates:`` blocks.

    .. code-block:: yaml

        updates:
          - directory: "/"
            schedule:
              interval: "weekly"
              day: "monday"
            provider: openai
            model: gpt-4.1
            auto_repair_issue_types:
              - raw_sqlite_query
              - hardcoded_secret
            ignore_paths:
              - tests/*
    """
    lines = path.read_text(encoding="utf-8").splitlines()

    # Find the "updates:" line
    index = _find_line_starting_with(lines, 0, "updates:")
    if index >= len(lines):
        return [UpdateConfig()]

    index += 1  # skip "updates:" line

    configs: list[UpdateConfig] = []
    while index < len(lines):
        stripped = lines[index].strip()
        if not stripped or stripped.startswith("#"):
            index += 1
            continue
        if not stripped.startswith("- "):
            break
        block_data, index = _parse_update_block(lines, index)
        configs.append(_update_config_from_data(block_data))

    return configs if configs else [UpdateConfig()]


def _parse_update_block(lines: list[str], start_index: int) -> tuple[dict[str, object], int]:
    """Parse one ``- ...`` item under ``updates:``.

    Returns (parsed_data, next_line_index).
    """
    data: dict[str, object] = {}
    first_line = lines[start_index]
    base_indent = len(first_line) - len(first_line.lstrip())
    field_indent = base_indent + 2
    schedule_data: dict[str, str] = {}
    index = start_index

    # Consume the "- key: value" line if present
    stripped = first_line.strip()
    after_dash = stripped[2:]
    if ":" in after_dash:
        key, _, value = after_dash.partition(":")
        key = key.strip()
        value = value.strip()
        if value:
            data[key] = _parse_scalar(value)
        index += 1
    else:
        index += 1

    # Parse indented fields
    while index < len(lines):
        raw_line = lines[index]
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#"):
            index += 1
            continue

        current_indent = len(raw_line) - len(raw_line.lstrip())
        if current_indent <= base_indent and not stripped.startswith("- "):
            break
        if current_indent < field_indent:
            break

        if ":" not in raw_line:
            raise ConfigError(f"invalid config line: {raw_line}")

        key, _, value = raw_line.partition(":")
        key = key.strip()
        value = value.strip()

        if not value:
            index += 1
            if index < len(lines):
                next_line = lines[index]
                if next_line.strip().startswith("- "):
                    # List of values
                    items, index = _parse_list_lines(lines, index, field_indent)
                    data[key] = items
                    continue
                else:
                    # Nested dict (e.g. schedule)
                    nested, index = _parse_nested_dict(lines, index, field_indent)
                    if key == "schedule":
                        schedule_data = nested  # type: ignore[assignment]
                    else:
                        data[key] = nested
                    continue
            else:
                data[key] = []
                continue

        data[key] = _parse_scalar(value)
        index += 1

    if schedule_data:
        data["schedule"] = schedule_data

    return data, index


def _parse_list_lines(lines: list[str], start_index: int, parent_indent: int) -> tuple[list[str], int]:
    """Parse ``- value`` list items."""
    items: list[str] = []
    index = start_index
    marker_indent = parent_indent + 2
    while index < len(lines):
        stripped = lines[index].strip()
        if not stripped or stripped.startswith("#"):
            index += 1
            continue
        current_indent = len(lines[index]) - len(lines[index].lstrip())
        if current_indent < marker_indent:
            break
        if not stripped.startswith("- "):
            break
        items.append(_parse_scalar(stripped[2:].strip()))
        index += 1
    return items, index


def _parse_nested_dict(lines: list[str], start_index: int, parent_indent: int) -> tuple[dict[str, str], int]:
    """Parse ``key: value`` pairs on indented lines."""
    data: dict[str, str] = {}
    index = start_index
    field_indent = parent_indent + 2
    while index < len(lines):
        stripped = lines[index].strip()
        if not stripped or stripped.startswith("#"):
            index += 1
            continue
        current_indent = len(lines[index]) - len(lines[index].lstrip())
        if current_indent <= parent_indent:
            break
        if current_indent < field_indent:
            break
        if ":" not in lines[index]:
            break
        key, _, value = lines[index].partition(":")
        key = key.strip()
        value = value.strip()
        if value:
            data[key] = _parse_scalar(value)
        index += 1
    return data, index


def _update_config_from_data(data: dict[str, object]) -> UpdateConfig:
    """Build an UpdateConfig from parsed block data."""
    ignore_paths = data.get("ignore_paths", [])
    if not isinstance(ignore_paths, list):
        ignore_paths = []

    default_types = AppConfig().auto_repair_issue_types
    auto_repair_issue_types = data.get("auto_repair_issue_types", default_types)
    if not isinstance(auto_repair_issue_types, list):
        auto_repair_issue_types = default_types

    try:
        min_confidence_value = float(data.get("auto_repair_min_confidence", 0.85))
    except (TypeError, ValueError):
        min_confidence_value = 0.85

    sandbox_mode = str(data.get("sandbox_mode", "repository"))
    if sandbox_mode not in {"file", "repository"}:
        sandbox_mode = "repository"

    svc = data.get("sandbox_verification_commands", [])
    if not isinstance(svc, list):
        svc = []

    schedule = data.get("schedule")
    if isinstance(schedule, dict):
        sched_interval = str(schedule.get("interval", "weekly"))
        sched_day = str(schedule.get("day", "monday"))
        sched_time = str(schedule.get("time", "09:00"))
        sched_tz = str(schedule.get("timezone", "UTC"))
    else:
        sched_interval = str(data.get("schedule_interval", "weekly"))
        sched_day = str(data.get("schedule_day", "monday"))
        sched_time = str(data.get("schedule_time", "09:00"))
        sched_tz = str(data.get("schedule_timezone", "UTC"))

    labels = data.get("labels", [])
    if not isinstance(labels, list):
        labels = []
    reviewers = data.get("reviewers", [])
    if not isinstance(reviewers, list):
        reviewers = []
    assignees = data.get("assignees", [])
    if not isinstance(assignees, list):
        assignees = []

    return UpdateConfig(
        provider=str(data.get("provider", "")) if data.get("provider") else None,
        model=str(data.get("model", "")) if data.get("model") else None,
        ignore_paths=[str(item) for item in ignore_paths],
        auto_repair_issue_types=[str(item) for item in auto_repair_issue_types],
        auto_repair_min_confidence=min_confidence_value,
        sandbox_mode=sandbox_mode,
        sandbox_verification_commands=[str(item) for item in svc],
        auto_approve_verified_fixes=_parse_bool(data.get("auto_approve_verified_fixes", False), "auto_approve_verified_fixes"),
        rollback_on_verification_failure=_parse_bool(data.get("rollback_on_verification_failure", True), "rollback_on_verification_failure"),
        schedule_interval=sched_interval,
        schedule_day=sched_day,
        schedule_time=sched_time,
        schedule_timezone=sched_tz,
        open_pull_requests_limit=_parse_int(data.get("open_pull_requests_limit", 5), "open_pull_requests_limit", 5),
        labels=[str(item) for item in labels],
        reviewers=[str(item) for item in reviewers],
        assignees=[str(item) for item in assignees],
        target_branch=str(data.get("target_branch", "main")),
        commit_message_prefix=str(data.get("commit_message_prefix", "[AION]")),
        directory=str(data.get("directory", "/")),
    )


# ── helpers ─────────────────────────────────────────────────────────────────

def _parse_scalar(value: str) -> str:
    if (value.startswith("'") and value.endswith("'")) or (value.startswith('"') and value.endswith('"')):
        return ast.literal_eval(value)
    return value


def _parse_bool(value: object, field_name: str) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in {"true", "yes", "on"}:
            return True
        if lowered in {"false", "no", "off"}:
            return False
    raise ConfigError(f"{field_name} must be a boolean")


def _parse_int(value: object, field_name: str, fallback: int = 0) -> int:
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value)
    if isinstance(value, str):
        try:
            return int(value.strip())
        except (TypeError, ValueError) as exc:
            raise ConfigError(f"{field_name} must be an integer") from exc
    return fallback


def _find_line_starting_with(lines: list[str], start: int, prefix: str) -> int:
    for i in range(start, len(lines)):
        if lines[i].strip().startswith(prefix):
            return i
    return len(lines)
