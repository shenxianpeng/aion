from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class AppConfig:
    provider: str | None = None
    model: str | None = None
    ignore_paths: list[str] = field(default_factory=list)


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
    return AppConfig(
        provider=str(provider) if provider is not None else None,
        model=str(model) if model is not None else None,
        ignore_paths=[str(item) for item in ignore_paths],
    )


def _parse_scalar(value: str) -> str:
    if (value.startswith("'") and value.endswith("'")) or (value.startswith('"') and value.endswith('"')):
        return ast.literal_eval(value)
    return value
