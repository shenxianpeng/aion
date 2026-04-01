import json
import subprocess
from pathlib import Path

import pytest

from aion.semgrep_runner import SemgrepError, SemgrepRunner


def test_run_parses_semgrep_json(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    target = tmp_path / "demo.py"
    target.write_text("print('hello')\n", encoding="utf-8")
    payload = {
        "results": [
            {
                "check_id": "python.lang.security.audit.eval-detected.eval-detected",
                "path": str(target),
                "start": {"line": 3},
                "end": {"line": 3},
                "extra": {
                    "severity": "ERROR",
                    "message": "Avoid eval",
                    "lines": "eval(user_input)",
                    "metadata": {"cwe": ["CWE-95"]},
                },
            }
        ]
    }

    def fake_run(*_args, **_kwargs):
        return subprocess.CompletedProcess(args=[], returncode=1, stdout=json.dumps(payload), stderr="")

    monkeypatch.setattr(subprocess, "run", fake_run)

    findings = SemgrepRunner().run(target)

    assert len(findings) == 1
    assert findings[0].check_id.endswith("eval-detected")
    assert findings[0].line == 3
    assert findings[0].message == "Avoid eval"


def test_run_raises_on_malformed_json(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    target = tmp_path / "demo.py"
    target.write_text("print('hello')\n", encoding="utf-8")

    def fake_run(*_args, **_kwargs):
        return subprocess.CompletedProcess(args=[], returncode=0, stdout="{bad json", stderr="")

    monkeypatch.setattr(subprocess, "run", fake_run)

    with pytest.raises(SemgrepError, match="malformed JSON"):
        SemgrepRunner().run(target)
