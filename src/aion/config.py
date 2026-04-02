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


class ConfigError(RuntimeError):
    pass


def load_app_config(root: Path) -> AppConfig:
    config_path = root / ".aion.yaml"
    if not config_path.exists():
        return AppConfig()

    return _parse_config(config_path)


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
    )


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
