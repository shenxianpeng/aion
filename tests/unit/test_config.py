from pathlib import Path

from aion.config import load_app_config


def test_load_app_config_reads_yaml_values(tmp_path: Path) -> None:
    (tmp_path / ".aion.yaml").write_text(
        "\n".join(
            [
                "provider: openai",
                "model: gpt-4.1",
                "ignore_paths:",
                "  - tests/*",
                "  - scripts/generated_*.py",
            ]
        ),
        encoding="utf-8",
    )

    config = load_app_config(tmp_path)

    assert config.provider == "openai"
    assert config.model == "gpt-4.1"
    assert config.ignore_paths == ["tests/*", "scripts/generated_*.py"]
