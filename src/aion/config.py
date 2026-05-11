from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import Path


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
    """Auto-update configuration loaded from the flat .aion.yaml format."""
    pass


class ConfigError(RuntimeError):
    pass


SUPPORTED_CONFIG_FIELDS = {
    "provider",
    "model",
    "ignore_paths",
    "auto_repair_issue_types",
    "auto_repair_min_confidence",
    "sandbox_mode",
    "sandbox_verification_commands",
    "auto_approve_verified_fixes",
    "rollback_on_verification_failure",
    "schedule",
    "schedule_interval",
    "schedule_day",
    "schedule_time",
    "schedule_timezone",
    "open_pull_requests_limit",
    "labels",
    "reviewers",
    "assignees",
    "target_branch",
    "commit_message_prefix",
    "directory",
    "updates",
}


def load_app_config(root: Path) -> AppConfig:
    """Load configuration from .aion.yaml."""
    config_path = root / ".aion.yaml"
    if not config_path.exists():
        return AppConfig()

    return _parse_config(config_path)


def load_update_configs(root: Path) -> list[UpdateConfig]:
    """Load AION auto-update configuration from flat .aion.yaml.

    Supports two formats:

    1. **Flat format** – top-level key-value pairs (no ``updates`` wrapper)::

           provider: openai
           directory: "/"

       Returns a single ``UpdateConfig`` with those values.

    2. **Updates-wrapper format** – a top-level ``updates`` key containing
       a list of update config blocks::

           updates:
             - directory: "/"
               schedule:
                 interval: "weekly"
               ...
             - directory: "/subdir"
               ...

       Returns one ``UpdateConfig`` per list item.
    """
    config_path = root / ".aion.yaml"
    if not config_path.exists():
        return [UpdateConfig()]

    config = _parse_config(config_path)

    # Check if the config uses the "updates" wrapper format
    updates_raw = config.__dict__.get("__updates__")
    if updates_raw and isinstance(updates_raw, list):
        result: list[UpdateConfig] = []
        for item_data in updates_raw:
            if not isinstance(item_data, dict):
                continue
            app_config = _app_config_from_data(item_data)
            result.append(_update_config_from_app_config(app_config))
        return result if result else [UpdateConfig()]

    # Legacy flat format (no updates wrapper)
    flat = {
        k: v
        for k, v in config.__dict__.items()
        if not k.startswith("_")
    }
    return [UpdateConfig(**flat)]  # type: ignore[arg-type]


# Flat format parser

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

        if key not in SUPPORTED_CONFIG_FIELDS:
            raise ConfigError(f"unsupported config field: {key}")

        if not value:
            if key == "updates":
                nested_value, index = _parse_updates(lines, index, path)
                data["__updates__"] = nested_value
                continue
            nested_value, index = _parse_flat_nested_value(lines, index, path)
            data[key] = nested_value
            continue

        data[key] = _parse_scalar(value)

    config = _app_config_from_data(data)
    if "__updates__" in data:
        config.__dict__["__updates__"] = data["__updates__"]
    return config


def _parse_flat_nested_value(lines: list[str], start_index: int, path: Path) -> tuple[object, int]:
    """Parse a top-level nested list or mapping in flat .aion.yaml."""
    nested_lines: list[str] = []
    index = start_index
    while index < len(lines):
        nested_raw = lines[index]
        nested = nested_raw.strip()
        if not nested or nested.startswith("#"):
            index += 1
            continue
        if not nested_raw.startswith(("  ", "\t")):
            break
        nested_lines.append(nested_raw)
        index += 1

    if not nested_lines:
        return [], index

    first = nested_lines[0].strip()
    if first.startswith("- "):
        items: list[str] = []
        for nested_raw in nested_lines:
            nested = nested_raw.strip()
            if not nested.startswith("- "):
                raise ConfigError(f"invalid list item in {path}: {nested_raw}")
            items.append(_parse_scalar(nested[2:].strip()))
        return items, index

    data: dict[str, object] = {}
    for nested_raw in nested_lines:
        nested = nested_raw.strip()
        if ":" not in nested:
            raise ConfigError(f"invalid nested config line in {path}: {nested_raw}")
        key, value = nested.split(":", 1)
        key = key.strip()
        value = value.strip()
        if not key or not value:
            raise ConfigError(f"invalid nested config line in {path}: {nested_raw}")
        data[key] = _parse_scalar(value)
    return data, index


def _update_config_from_app_config(cfg: AppConfig) -> UpdateConfig:
    """Convert an AppConfig to an UpdateConfig."""
    return UpdateConfig(
        provider=cfg.provider,
        model=cfg.model,
        ignore_paths=list(cfg.ignore_paths),
        auto_repair_issue_types=list(cfg.auto_repair_issue_types),
        auto_repair_min_confidence=cfg.auto_repair_min_confidence,
        sandbox_mode=cfg.sandbox_mode,
        sandbox_verification_commands=list(cfg.sandbox_verification_commands),
        auto_approve_verified_fixes=cfg.auto_approve_verified_fixes,
        rollback_on_verification_failure=cfg.rollback_on_verification_failure,
        schedule_interval=cfg.schedule_interval,
        schedule_day=cfg.schedule_day,
        schedule_time=cfg.schedule_time,
        schedule_timezone=cfg.schedule_timezone,
        open_pull_requests_limit=cfg.open_pull_requests_limit,
        labels=list(cfg.labels),
        reviewers=list(cfg.reviewers),
        assignees=list(cfg.assignees),
        target_branch=cfg.target_branch,
        commit_message_prefix=cfg.commit_message_prefix,
        directory=cfg.directory,
    )


def _app_config_from_data(data: dict[str, object]) -> AppConfig:
    ignore_paths = data.get("ignore_paths", [])
    if not isinstance(ignore_paths, list):
        raise ConfigError("ignore_paths must be a list")

    provider = data.get("provider")
    model = data.get("model")
    auto_repair_issue_types = data.get(
        "auto_repair_issue_types",
        AppConfig().auto_repair_issue_types,
    )
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
    schedule = data.get("schedule")
    if schedule is not None and not isinstance(schedule, dict):
        raise ConfigError("schedule must be a mapping")
    schedule_data = schedule if isinstance(schedule, dict) else {}
    schedule_interval = str(
        data.get("schedule_interval", schedule_data.get("interval", AppConfig().schedule_interval))
    )
    schedule_day = str(
        data.get("schedule_day", schedule_data.get("day", AppConfig().schedule_day))
    )
    schedule_time = str(
        data.get("schedule_time", schedule_data.get("time", AppConfig().schedule_time))
    )
    schedule_timezone = str(
        data.get("schedule_timezone", schedule_data.get("timezone", AppConfig().schedule_timezone))
    )

    open_pull_requests_limit = _parse_int(
        data.get("open_pull_requests_limit", AppConfig().open_pull_requests_limit),
        "open_pull_requests_limit",
        AppConfig().open_pull_requests_limit,
    )
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
    commit_message_prefix = str(
        data.get("commit_message_prefix", AppConfig().commit_message_prefix)
    )
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


# Updates-wrapper parser

def _parse_updates(lines: list[str], start_index: int, path: Path) -> tuple[list[dict[str, object]], int]:
    """Parse the ``updates: [...]`` block, returning a list of config dicts.

    Each list item under ``updates`` is a flat mapping that may contain
    nested sub-mappings (e.g. ``schedule:``) and nested lists (e.g.
    ``ignore_paths:``).
    """
    # Collect all lines indented under ``updates:``
    nested_lines: list[str] = []
    index = start_index
    while index < len(lines):
        nested_raw = lines[index]
        nested = nested_raw.strip()
        if not nested or nested.startswith("#"):
            index += 1
            continue
        if not nested_raw.startswith((" ", "\t")):
            break
        nested_lines.append(nested_raw)
        index += 1

    if not nested_lines:
        return [], index

    # Determine the base indentation (where ``- `` items sit)
    base_indent = len(nested_lines[0]) - len(nested_lines[0].lstrip())

    # Group lines into list-item blocks.  Each block starts with ``- ``
    # at *base_indent*; continuation lines are indented deeper.
    item_blocks: list[list[str]] = []
    current: list[str] = []
    for raw in nested_lines:
        stripped = raw.lstrip()
        indent = len(raw) - len(stripped)
        if stripped.startswith("- ") and indent == base_indent:
            if current:
                item_blocks.append(current)
            # Strip the ``- `` prefix, keep the rest of the line
            current = [raw[:indent] + stripped[2:]]
        else:
            current.append(raw)
    if current:
        item_blocks.append(current)

    # Parse each item block as a flat key-value dict
    configs: list[dict[str, object]] = []
    for block in item_blocks:
        item_data = _parse_nested_block(block, path)
        configs.append(item_data)

    return configs, index


def _parse_nested_block(lines: list[str], path: Path) -> dict[str, object]:
    """Parse a recursively-nested key-value block at any indentation level.

    Handles:

    * Simple key-value pairs: ``key: value``
    * Nested mappings where the value is empty (indented children follow)
    * Inline lists: ``key:`` followed by ``- item`` lines
    """
    data: dict[str, object] = {}
    i = 0
    while i < len(lines):
        raw = lines[i]
        stripped = raw.strip()

        if not stripped or stripped.startswith("#"):
            i += 1
            continue

        if ":" not in stripped:
            raise ConfigError(f"invalid config line in {path}: {raw}")

        key, _, value = stripped.partition(":")
        key = key.strip()
        value = value.strip()

        if not value:
            # Collect continuation lines at strictly-greater indentation
            key_indent = len(raw) - len(raw.lstrip())
            i += 1
            nested_lines: list[str] = []
            while i < len(lines):
                next_raw = lines[i]
                next_stripped = next_raw.strip()
                if not next_stripped or next_stripped.startswith("#"):
                    i += 1
                    continue
                next_indent = len(next_raw) - len(next_stripped)
                if next_indent <= key_indent:
                    break
                nested_lines.append(next_raw)
                i += 1

            if nested_lines and nested_lines[0].strip().startswith("- "):
                # Inline list
                items: list[str] = []
                for list_raw in nested_lines:
                    list_stripped = list_raw.strip()
                    if list_stripped.startswith("- "):
                        items.append(_parse_scalar(list_stripped[2:].strip()))
                data[key] = items
            elif nested_lines:
                # Nested mapping
                data[key] = _parse_nested_block(nested_lines, path)
            else:
                data[key] = []
            continue

        data[key] = _parse_scalar(value)
        i += 1

    return data


# Helpers

def _parse_scalar(value: str) -> str:
    if (
        (value.startswith("'") and value.endswith("'"))
        or (value.startswith('"') and value.endswith('"'))
    ):
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
