from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

from .models import SemgrepFinding, normalize_path


class SemgrepError(RuntimeError):
    pass


def semgrep_available() -> bool:
    return shutil.which("semgrep") is not None


class SemgrepRunner:
    def __init__(self, config: str = "p/python"):
        self.config = config

    def run(self, target: Path) -> list[SemgrepFinding]:
        command = ["semgrep", "--json", "--config", self.config, str(target)]
        result = subprocess.run(command, capture_output=True, text=True, check=False)
        if result.returncode not in (0, 1):
            raise SemgrepError(result.stderr.strip() or "semgrep failed")
        try:
            payload = json.loads(result.stdout or "{}")
        except json.JSONDecodeError as exc:
            raise SemgrepError("semgrep returned malformed JSON") from exc

        findings: list[SemgrepFinding] = []
        for item in payload.get("results", []):
            start = item.get("start", {})
            end = item.get("end", {})
            extra = item.get("extra", {})
            findings.append(
                SemgrepFinding(
                    check_id=item.get("check_id", "unknown"),
                    path=normalize_path(Path(item.get("path", str(target)))),
                    line=start.get("line", 1),
                    end_line=end.get("line"),
                    severity=extra.get("severity", "INFO"),
                    message=extra.get("message", "").strip() or item.get("check_id", "Semgrep finding"),
                    code=extra.get("lines"),
                    metadata=extra.get("metadata", {}),
                )
            )
        return findings
