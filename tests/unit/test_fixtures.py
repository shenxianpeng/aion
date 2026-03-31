import json
from pathlib import Path


def test_labels_match_fixture_files() -> None:
    fixtures_root = Path("tests/fixtures")
    labels = json.loads((fixtures_root / "labels.json").read_text(encoding="utf-8"))
    fixture_files = {
        path.relative_to(fixtures_root).as_posix()
        for path in fixtures_root.rglob("*.py")
    }

    assert set(labels) == fixture_files


def test_each_fixture_has_context_file() -> None:
    fixtures_root = Path("tests/fixtures")
    for source in fixtures_root.rglob("*.py"):
        fixture_id = source.name.split("_", 1)[0]
        context = source.with_name(f"{fixture_id}_context.json")
        assert context.exists(), f"missing context file for {source}"
