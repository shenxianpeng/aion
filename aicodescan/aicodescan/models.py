from __future__ import annotations

from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field


Severity = Literal["critical", "high", "medium", "low"]


class ContextProfile(BaseModel):
    orm: str | None = None
    auth_decorators: list[str] = Field(default_factory=list)
    db_patterns: list[str] = Field(default_factory=list)
    low_level_db_imports: list[str] = Field(default_factory=list)
    http_client: str | None = None
    imports: list[str] = Field(default_factory=list)
    function_names: list[str] = Field(default_factory=list)
    scanned_files: int = 0
    sampled: bool = False
    skipped_files: list[str] = Field(default_factory=list)

    def summary_payload(self) -> dict[str, object]:
        return {
            "orm": self.orm,
            "auth_decorators": self.auth_decorators[:20],
            "db_patterns": self.db_patterns[:20],
            "low_level_db_imports": self.low_level_db_imports[:20],
            "http_client": self.http_client,
            "imports": self.imports[:50],
            "function_names": self.function_names[:30],
            "scanned_files": self.scanned_files,
            "sampled": self.sampled,
        }


class SemgrepFinding(BaseModel):
    check_id: str
    path: str
    line: int
    end_line: int | None = None
    severity: str = "INFO"
    message: str
    code: str | None = None
    metadata: dict[str, object] = Field(default_factory=dict)


class Finding(BaseModel):
    issue: str
    severity: Severity
    line: int
    context_gap: str
    fix: str
    semgrep_rule: str | None = None


class ScanReport(BaseModel):
    file: str
    findings: list[Finding] = Field(default_factory=list)
    semgrep_findings: list[SemgrepFinding] = Field(default_factory=list)
    ai_generated: bool = False
    mode: Literal["semgrep+llm", "llm-only", "semgrep-only", "skipped"] = "skipped"


class LLMScanResponse(BaseModel):
    findings: list[Finding] = Field(default_factory=list)


class ProjectScanSummary(BaseModel):
    target: str
    files_scanned: int = 0
    reports: list[ScanReport] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)

    @property
    def finding_count(self) -> int:
        return sum(len(report.findings) for report in self.reports)

    def sorted_reports(self) -> list[ScanReport]:
        return sorted(
            self.reports,
            key=lambda report: (
                min(
                    (
                        {"critical": 0, "high": 1, "medium": 2, "low": 3}[finding.severity]
                        for finding in report.findings
                    ),
                    default=4,
                ),
                report.file,
            ),
        )


def normalize_path(path: Path) -> str:
    try:
        return str(path.resolve())
    except OSError:
        return str(path)
