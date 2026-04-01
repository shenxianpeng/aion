from __future__ import annotations

from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field


Severity = Literal["critical", "high", "medium", "low"]
IncidentStatus = Literal["detected", "planned", "patched", "verified", "approved", "rejected"]
VerificationVerdict = Literal["verified_fix", "unsafe_patch", "needs_human_review"]


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


class Incident(BaseModel):
    id: str
    source: Literal["scan", "heuristic", "runtime_event"] = "heuristic"
    target_file: str
    issue_type: str
    issue: str
    severity: Severity
    line: int
    evidence: list[str] = Field(default_factory=list)
    confidence: float = 0.0
    attack_surface: str = "code"
    recommended_action: str = "review"
    remediation_strategy: str | None = None
    verification_strategy: list[str] = Field(default_factory=list)
    status: IncidentStatus = "detected"


class RemediationPlan(BaseModel):
    incident_id: str
    target_file: str
    strategy: str
    summary: str
    planned_changes: list[str] = Field(default_factory=list)
    verification_steps: list[str] = Field(default_factory=list)
    rollback_condition: str = "verification_failed"
    status: IncidentStatus = "planned"


class PatchArtifact(BaseModel):
    incident_ids: list[str] = Field(default_factory=list)
    target_file: str
    original_content: str
    patched_content: str
    diff: str
    generator: Literal["template", "llm"] = "template"
    plans: list[RemediationPlan] = Field(default_factory=list)
    static_validation_passed: bool = False
    status: IncidentStatus = "patched"


class VerificationCheck(BaseModel):
    name: str
    passed: bool
    details: str = ""


class VerificationResult(BaseModel):
    artifact: PatchArtifact
    verdict: VerificationVerdict
    syntax_ok: bool
    semgrep_ok: bool
    assertions_ok: bool
    semgrep_findings: list[SemgrepFinding] = Field(default_factory=list)
    checks: list[VerificationCheck] = Field(default_factory=list)
    failure_reasons: list[str] = Field(default_factory=list)
    status: IncidentStatus = "verified"


class RepairAttemptRecord(BaseModel):
    target: str
    created_at: str
    context_profile: ContextProfile
    incidents: list[Incident] = Field(default_factory=list)
    artifact: PatchArtifact | None = None
    verification: VerificationResult | None = None
    warnings: list[str] = Field(default_factory=list)


class ScanReport(BaseModel):
    file: str
    findings: list[Finding] = Field(default_factory=list)
    semgrep_findings: list[SemgrepFinding] = Field(default_factory=list)
    incidents: list[Incident] = Field(default_factory=list)
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

    @property
    def incident_count(self) -> int:
        return sum(len(report.incidents) for report in self.reports)

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


class RepairSession(BaseModel):
    target: str
    incidents: list[Incident] = Field(default_factory=list)
    artifact: PatchArtifact | None = None
    warnings: list[str] = Field(default_factory=list)


class RunIncidentResult(BaseModel):
    session: RepairSession
    verification: VerificationResult | None = None


def normalize_path(path: Path) -> str:
    try:
        return str(path.resolve())
    except OSError:
        return str(path)
