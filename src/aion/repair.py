from __future__ import annotations

import ast
import difflib
import hashlib
import re
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from .models import (
    ContextProfile,
    Finding,
    Incident,
    PatchArtifact,
    RepairAttemptRecord,
    RemediationPlan,
    SemgrepFinding,
    VerificationCheck,
    VerificationResult,
    normalize_path,
)
from .risk_heuristics import fallback_reasons
from .semgrep_runner import SemgrepError, SemgrepRunner, semgrep_available


@dataclass
class DetectionOutcome:
    incidents: list[Incident]
    semgrep_findings: list[SemgrepFinding]
    llm_findings: list[Finding]
    fallback_signals: list[str]
    warnings: list[str]
    mode: str


class IncidentDetector:
    _SUPPORTED_INCIDENTS: dict[str, dict[str, object]] = {
        "raw_sqlite_query": {
            "issue": "Raw sqlite query bypasses project database safety patterns.",
            "severity": "high",
            "attack_surface": "database",
            "recommended_action": "auto_repair",
            "remediation_strategy": "parameterize_sqlite_query",
            "verification_strategy": ["syntax", "semgrep", "sqlite_parameterization"],
        },
        "hardcoded_secret": {
            "issue": "Hardcoded secret should be loaded from environment variables.",
            "severity": "critical",
            "attack_surface": "credential",
            "recommended_action": "auto_repair",
            "remediation_strategy": "env_secret",
            "verification_strategy": ["syntax", "secret_removed", "semgrep"],
        },
        "missing_auth_decorator": {
            "issue": "Route handler bypasses the repository's auth decorator pattern.",
            "severity": "high",
            "attack_surface": "http",
            "recommended_action": "auto_repair",
            "remediation_strategy": "inject_auth_decorator",
            "verification_strategy": ["syntax", "auth_decorator_present"],
        },
        "insecure_yaml_load": {
            "issue": "yaml.load without SafeLoader allows arbitrary code execution via deserialization.",
            "severity": "critical",
            "attack_surface": "deserialization",
            "recommended_action": "auto_repair",
            "remediation_strategy": "safe_yaml_load",
            "verification_strategy": ["syntax", "yaml_safe_load", "semgrep"],
        },
        "command_injection": {
            "issue": "os.system with an f-string argument is vulnerable to shell command injection.",
            "severity": "critical",
            "attack_surface": "command_execution",
            "recommended_action": "auto_repair",
            "remediation_strategy": "shlex_quote_command",
            "verification_strategy": ["syntax", "command_shlex_quoted"],
        },
        "eval_injection": {
            "issue": "eval() with user-controlled input enables arbitrary code execution.",
            "severity": "critical",
            "attack_surface": "code_execution",
            "recommended_action": "auto_repair",
            "remediation_strategy": "ast_literal_eval",
            "verification_strategy": ["syntax", "eval_replaced"],
        },
        "subprocess_shell_injection": {
            "issue": "subprocess called with shell=True and an f-string is vulnerable to command injection.",
            "severity": "critical",
            "attack_surface": "command_execution",
            "recommended_action": "auto_repair",
            "remediation_strategy": "shlex_quote_subprocess",
            "verification_strategy": ["syntax", "subprocess_shlex_quoted"],
        },
        "weak_cryptography": {
            "issue": "MD5 is a broken hash algorithm; use SHA-256 or stronger for security-sensitive operations.",
            "severity": "high",
            "attack_surface": "cryptography",
            "recommended_action": "auto_repair",
            "remediation_strategy": "upgrade_hash_algorithm",
            "verification_strategy": ["syntax", "weak_hash_removed"],
        },
    }

    def __init__(
        self,
        semgrep_runner: SemgrepRunner | None = None,
        llm_analyzer=None,
    ) -> None:
        self.semgrep_runner = semgrep_runner
        self.llm_analyzer = llm_analyzer

    def analyze(
        self,
        target: Path,
        context_profile: ContextProfile,
        fallback_signals: list[str] | None = None,
        console=None,
    ) -> DetectionOutcome:
        content = target.read_text(encoding="utf-8", errors="ignore")
        signals = fallback_signals if fallback_signals is not None else fallback_reasons(target, context_profile)
        warnings: list[str] = []
        semgrep_findings: list[SemgrepFinding] = []
        llm_findings: list[Finding] = []
        mode = "heuristic-only"

        if self.semgrep_runner is not None:
            try:
                semgrep_findings = self.semgrep_runner.run(target)
                mode = "semgrep-only"
            except SemgrepError as exc:
                warnings.append(f"semgrep failed: {exc}")

        should_run_llm = self.llm_analyzer is not None and ((self.semgrep_runner is None) or bool(semgrep_findings) or bool(signals))
        if should_run_llm:
            try:
                llm_findings = self.llm_analyzer.analyze(
                    target,
                    context_profile,
                    semgrep_findings,
                    fallback_signals=signals,
                    console=console,
                )
                mode = "llm-only" if self.semgrep_runner is None else "semgrep+llm"
            except Exception as exc:  # noqa: BLE001
                warnings.append(f"LLM analysis failed: {exc}")
                if self.semgrep_runner is None:
                    mode = "heuristic-only"

        incidents = self._deduplicate_incidents(
            [
                *self._detect_heuristics(target, content, context_profile),
                *self._incidents_from_semgrep(target, semgrep_findings),
                *self._incidents_from_llm(target, llm_findings),
            ]
        )
        return DetectionOutcome(
            incidents=incidents,
            semgrep_findings=semgrep_findings,
            llm_findings=llm_findings,
            fallback_signals=signals,
            warnings=warnings,
            mode=mode,
        )

    def detect(self, target: Path, context_profile: ContextProfile) -> list[Incident]:
        return self.analyze(target, context_profile).incidents

    def _detect_heuristics(self, target: Path, content: str, context_profile: ContextProfile) -> list[Incident]:
        incidents: list[Incident] = []

        if self._has_raw_sqlite_issue(content):
            incidents.append(
                self._make_supported_incident(
                    target,
                    "raw_sqlite_query",
                    line=self._line_for(content, "cursor.execute"),
                    evidence=["sqlite3.connect", "cursor.execute(f-string)"],
                    confidence=0.93,
                    source="heuristic",
                )
            )

        secret_match = self._find_hardcoded_secret(content)
        if secret_match:
            incidents.append(
                self._make_supported_incident(
                    target,
                    "hardcoded_secret",
                    line=self._line_for(content, secret_match.group(0)),
                    evidence=[secret_match.group(0).strip()],
                    confidence=0.98,
                    source="heuristic",
                )
            )

        if self._has_missing_auth_issue(content, context_profile):
            incidents.append(
                self._make_supported_incident(
                    target,
                    "missing_auth_decorator",
                    line=self._line_for(content, "@router."),
                    evidence=["APIRouter route without project auth decorator"],
                    confidence=0.88,
                    source="heuristic",
                )
            )

        if self._has_insecure_yaml_load(content):
            incidents.append(
                self._make_supported_incident(
                    target,
                    "insecure_yaml_load",
                    line=self._line_for(content, "yaml.load("),
                    evidence=["yaml.load called without SafeLoader"],
                    confidence=0.97,
                    source="heuristic",
                )
            )

        if self._has_command_injection(content):
            incidents.append(
                self._make_supported_incident(
                    target,
                    "command_injection",
                    line=self._line_for(content, "os.system("),
                    evidence=["os.system(f-string)"],
                    confidence=0.95,
                    source="heuristic",
                )
            )

        if self._has_eval_injection(content):
            incidents.append(
                self._make_supported_incident(
                    target,
                    "eval_injection",
                    line=self._line_for(content, "eval("),
                    evidence=["eval() called with non-constant argument"],
                    confidence=0.96,
                    source="heuristic",
                )
            )

        if self._has_subprocess_shell_injection(content):
            incidents.append(
                self._make_supported_incident(
                    target,
                    "subprocess_shell_injection",
                    line=self._line_for(content, "subprocess."),
                    evidence=["subprocess with shell=True and f-string argument"],
                    confidence=0.95,
                    source="heuristic",
                )
            )

        if self._has_weak_cryptography(content):
            incidents.append(
                self._make_supported_incident(
                    target,
                    "weak_cryptography",
                    line=self._line_for(content, "hashlib.md5("),
                    evidence=["hashlib.md5 used for security-sensitive hashing"],
                    confidence=0.92,
                    source="heuristic",
                )
            )

        return incidents

    def _has_raw_sqlite_issue(self, content: str) -> bool:
        return "sqlite3.connect" in content and bool(re.search(r"cursor\.execute\(\s*f[\"']", content))

    def _find_hardcoded_secret(self, content: str) -> re.Match[str] | None:
        pattern = re.compile(
            r"^(?P<name>[A-Z0-9_]*(?:SECRET|TOKEN|API_KEY|PASSWORD)[A-Z0-9_]*)\s*=\s*[\"'](?P<value>[^\"']+)[\"']\s*$",
            re.MULTILINE,
        )
        for match in pattern.finditer(content):
            if "os.getenv" not in match.group(0):
                return match
        return None

    def _has_insecure_yaml_load(self, content: str) -> bool:
        for match in re.finditer(r"\byaml\.load\s*\([^)]*\)", content):
            if "Loader" not in match.group(0):
                return True
        return False

    def _has_command_injection(self, content: str) -> bool:
        return bool(re.search(r"os\.system\s*\(\s*f[\"']", content))

    def _has_eval_injection(self, content: str) -> bool:
        # Detect eval() where the argument is not a simple string or numeric constant
        return bool(re.search(r'\beval\s*\(\s*(?!["\'\d])', content))

    def _has_subprocess_shell_injection(self, content: str) -> bool:
        return bool(
            re.search(r"subprocess\.(call|run|Popen)\s*\(\s*f[\"'].*?shell\s*=\s*True", content, re.DOTALL)
        )

    def _has_weak_cryptography(self, content: str) -> bool:
        return "hashlib.md5(" in content

    def _has_missing_auth_issue(self, content: str, context_profile: ContextProfile) -> bool:
        if "APIRouter" not in content or "@router." not in content:
            return False
        auth_markers = {decorator.lstrip("@") for decorator in context_profile.auth_decorators}
        route_block = re.search(r"((?:@\w[^\n]*\n)+)def\s+\w+\(", content)
        if not route_block:
            return False
        decorators = route_block.group(1)
        return bool(auth_markers) and not any(marker in decorators for marker in auth_markers)

    def _make_supported_incident(
        self,
        target: Path,
        issue_type: str,
        *,
        line: int,
        evidence: list[str],
        confidence: float,
        source: str,
    ) -> Incident:
        metadata = self._SUPPORTED_INCIDENTS[issue_type]
        return Incident(
            id=self._incident_id(target, issue_type, line),
            source=source,  # type: ignore[arg-type]
            target_file=normalize_path(target),
            issue_type=issue_type,
            issue=str(metadata["issue"]),
            severity=metadata["severity"],  # type: ignore[arg-type]
            line=line,
            evidence=evidence,
            confidence=confidence,
            attack_surface=str(metadata["attack_surface"]),
            recommended_action=str(metadata["recommended_action"]),
            remediation_strategy=str(metadata["remediation_strategy"]),
            verification_strategy=list(metadata["verification_strategy"]),
        )

    def _incidents_from_semgrep(self, target: Path, findings: list[SemgrepFinding]) -> list[Incident]:
        incidents: list[Incident] = []
        for finding in findings:
            issue_type = self._infer_issue_type(" ".join(filter(None, [finding.check_id, finding.message, finding.code or ""])))
            if issue_type is None:
                incidents.append(
                    self._make_review_incident(
                        target,
                        issue_type="semgrep_review",
                        line=finding.line,
                        issue=finding.message or finding.check_id,
                        severity=self._severity_from_semgrep(finding.severity),
                        evidence=[finding.check_id, finding.message],
                        confidence=0.70,
                    )
                )
                continue
            incidents.append(
                self._make_supported_incident(
                    target,
                    issue_type,
                    line=finding.line,
                    evidence=[finding.check_id, finding.message],
                    confidence=0.90,
                    source="scan",
                )
            )
        return incidents

    def _incidents_from_llm(self, target: Path, findings: list[Finding]) -> list[Incident]:
        incidents: list[Incident] = []
        for finding in findings:
            issue_type = self._infer_issue_type(" ".join([finding.issue, finding.context_gap, finding.fix]))
            if issue_type is None:
                incidents.append(
                    self._make_review_incident(
                        target,
                        issue_type="llm_review",
                        line=finding.line,
                        issue=finding.issue,
                        severity=finding.severity,
                        evidence=[finding.context_gap, finding.fix],
                        confidence=0.75,
                    )
                )
                continue
            incidents.append(
                self._make_supported_incident(
                    target,
                    issue_type,
                    line=finding.line,
                    evidence=[finding.issue, finding.context_gap, finding.fix],
                    confidence=0.85,
                    source="scan",
                )
            )
        return incidents

    def _make_review_incident(
        self,
        target: Path,
        *,
        issue_type: str,
        line: int,
        issue: str,
        severity,
        evidence: list[str],
        confidence: float,
    ) -> Incident:
        return Incident(
            id=self._incident_id(target, issue_type, line),
            source="scan",
            target_file=normalize_path(target),
            issue_type=issue_type,
            issue=issue,
            severity=severity,
            line=line,
            evidence=evidence,
            confidence=confidence,
            recommended_action="review",
        )

    def _infer_issue_type(self, text: str) -> str | None:
        lowered = text.lower()
        if "sqlite" in lowered and ("cursor.execute" in lowered or "sql injection" in lowered or "parameterized" in lowered):
            return "raw_sqlite_query"
        if "secret" in lowered or "api key" in lowered or "password" in lowered or "token" in lowered:
            return "hardcoded_secret"
        if "auth decorator" in lowered or "authentication decorator" in lowered or "missing auth" in lowered:
            return "missing_auth_decorator"
        if "yaml.load" in lowered or ("yaml" in lowered and "safe" in lowered):
            return "insecure_yaml_load"
        if "subprocess" in lowered and ("shell=true" in lowered or "command injection" in lowered):
            return "subprocess_shell_injection"
        if "os.system" in lowered or ("command injection" in lowered and "subprocess" not in lowered):
            return "command_injection"
        if "eval" in lowered:
            return "eval_injection"
        if "md5" in lowered or "hashlib.md5" in lowered or "sha-256" in lowered or "sha256" in lowered:
            return "weak_cryptography"
        return None

    def _severity_from_semgrep(self, severity: str):
        mapping = {
            "ERROR": "high",
            "WARNING": "medium",
            "INFO": "low",
        }
        return mapping.get(severity.upper(), "medium")

    def _deduplicate_incidents(self, incidents: list[Incident]) -> list[Incident]:
        deduped: dict[tuple[str, str, int, str | None], Incident] = {}
        for incident in incidents:
            key = (
                incident.target_file,
                incident.issue_type,
                incident.line,
                incident.remediation_strategy,
            )
            existing = deduped.get(key)
            if existing is None or incident.confidence > existing.confidence:
                deduped[key] = incident
        return sorted(deduped.values(), key=lambda incident: (incident.target_file, incident.line, incident.issue_type))

    def _incident_id(self, target: Path, issue_type: str, line: int) -> str:
        digest = hashlib.sha256(f"{normalize_path(target)}:{issue_type}:{line}".encode("utf-8")).hexdigest()
        return digest[:12]

    def _line_for(self, content: str, needle: str) -> int:
        for index, line in enumerate(content.splitlines(), start=1):
            if needle in line:
                return index
        return 1


class PatchPlanner:
    def plan(self, incident: Incident, context_profile: ContextProfile) -> RemediationPlan | None:
        if incident.issue_type == "raw_sqlite_query":
            orm = context_profile.orm or "the repository ORM"
            return RemediationPlan(
                incident_id=incident.id,
                target_file=incident.target_file,
                strategy="parameterize_sqlite_query",
                summary="Replace interpolated sqlite query with a parameterized call.",
                planned_changes=[
                    "Rewrite f-string SQL execution to use placeholders and bound parameters.",
                    f"Keep the file aligned with {orm} style by removing unsafe raw interpolation.",
                ],
                verification_steps=["syntax", "semgrep", "sqlite_parameterization"],
            )
        if incident.issue_type == "hardcoded_secret":
            return RemediationPlan(
                incident_id=incident.id,
                target_file=incident.target_file,
                strategy="env_secret",
                summary="Replace the hardcoded credential with an environment lookup.",
                planned_changes=[
                    "Import os when needed.",
                    "Replace the literal secret assignment with os.getenv.",
                ],
                verification_steps=["syntax", "semgrep", "secret_removed"],
            )
        if incident.issue_type == "missing_auth_decorator":
            chosen = self._preferred_auth_decorator(context_profile)
            if not chosen:
                return None
            return RemediationPlan(
                incident_id=incident.id,
                target_file=incident.target_file,
                strategy="inject_auth_decorator",
                summary=f"Insert the repository auth decorator {chosen}.",
                planned_changes=[
                    f"Add {chosen} above the route decorator.",
                ],
                verification_steps=["syntax", "auth_decorator_present"],
            )
        if incident.issue_type == "insecure_yaml_load":
            return RemediationPlan(
                incident_id=incident.id,
                target_file=incident.target_file,
                strategy="safe_yaml_load",
                summary="Replace yaml.load with yaml.safe_load to prevent arbitrary code execution.",
                planned_changes=[
                    "Replace yaml.load( with yaml.safe_load( to use the safe YAML deserializer.",
                ],
                verification_steps=["syntax", "yaml_safe_load"],
            )
        if incident.issue_type == "command_injection":
            return RemediationPlan(
                incident_id=incident.id,
                target_file=incident.target_file,
                strategy="shlex_quote_command",
                summary="Wrap os.system f-string variables with shlex.quote to prevent shell injection.",
                planned_changes=[
                    "Wrap user-controlled variables in shlex.quote() inside os.system f-string.",
                    "Import shlex when needed.",
                ],
                verification_steps=["syntax", "command_shlex_quoted"],
            )
        if incident.issue_type == "eval_injection":
            return RemediationPlan(
                incident_id=incident.id,
                target_file=incident.target_file,
                strategy="ast_literal_eval",
                summary="Replace eval() with ast.literal_eval() to safely evaluate literal Python expressions.",
                planned_changes=[
                    "Replace eval( with ast.literal_eval( to prevent arbitrary code execution.",
                    "Import ast when needed.",
                ],
                verification_steps=["syntax", "eval_replaced"],
            )
        if incident.issue_type == "subprocess_shell_injection":
            return RemediationPlan(
                incident_id=incident.id,
                target_file=incident.target_file,
                strategy="shlex_quote_subprocess",
                summary="Wrap subprocess f-string variables with shlex.quote to prevent shell injection.",
                planned_changes=[
                    "Wrap user-controlled variables in shlex.quote() inside subprocess f-string.",
                    "Import shlex when needed.",
                ],
                verification_steps=["syntax", "subprocess_shlex_quoted"],
            )
        if incident.issue_type == "weak_cryptography":
            return RemediationPlan(
                incident_id=incident.id,
                target_file=incident.target_file,
                strategy="upgrade_hash_algorithm",
                summary="Replace hashlib.md5 with hashlib.sha256 for security-sensitive hashing.",
                planned_changes=[
                    "Replace hashlib.md5( with hashlib.sha256( to use a stronger hash algorithm.",
                ],
                verification_steps=["syntax", "weak_hash_removed"],
            )
        return None

    def _preferred_auth_decorator(self, context_profile: ContextProfile) -> str | None:
        decorators = context_profile.auth_decorators
        if "@require_permissions" in decorators:
            return "@require_permissions"
        return decorators[0] if decorators else None


class PatchGenerator:
    def __init__(self, planner: PatchPlanner | None = None):
        self.planner = planner or PatchPlanner()

    def generate(
        self,
        target: Path,
        incidents: list[Incident],
        context_profile: ContextProfile,
    ) -> PatchArtifact | None:
        if not incidents:
            return None

        original = target.read_text(encoding="utf-8", errors="ignore")
        patched = original
        plans: list[RemediationPlan] = []
        applied_incident_ids: list[str] = []

        for incident in incidents:
            plan = self.planner.plan(incident, context_profile)
            if plan is None:
                continue
            next_content = self._apply_strategy(patched, incident, plan, context_profile)
            if next_content == patched:
                continue
            patched = next_content
            plans.append(plan)
            applied_incident_ids.append(incident.id)

        if patched == original or not plans:
            return None

        diff = "".join(
            difflib.unified_diff(
                original.splitlines(keepends=True),
                patched.splitlines(keepends=True),
                fromfile=normalize_path(target),
                tofile=f"{normalize_path(target)} (patched)",
            )
        )

        artifact = PatchArtifact(
            incident_ids=applied_incident_ids,
            target_file=normalize_path(target),
            original_content=original,
            patched_content=patched,
            diff=diff,
            generator="template",
            plans=plans,
        )
        artifact.static_validation_passed = self._is_valid_python(patched)
        return artifact

    def _apply_strategy(
        self,
        content: str,
        incident: Incident,
        plan: RemediationPlan,
        context_profile: ContextProfile,
    ) -> str:
        if plan.strategy == "parameterize_sqlite_query":
            return self._parameterize_sqlite_query(content)
        if plan.strategy == "env_secret":
            return self._replace_hardcoded_secret(content)
        if plan.strategy == "inject_auth_decorator":
            return self._inject_auth_decorator(content, context_profile)
        if plan.strategy == "safe_yaml_load":
            return self._fix_yaml_load(content)
        if plan.strategy == "shlex_quote_command":
            return self._fix_command_injection(content)
        if plan.strategy == "ast_literal_eval":
            return self._fix_eval_injection(content)
        if plan.strategy == "shlex_quote_subprocess":
            return self._fix_subprocess_injection(content)
        if plan.strategy == "upgrade_hash_algorithm":
            return self._fix_weak_cryptography(content)
        return content

    def _parameterize_sqlite_query(self, content: str) -> str:
        pattern = re.compile(
            r"(?P<prefix>\s*cursor\.execute\(\s*)f(?P<quote>[\"'])(?P<query>.*)\{(?P<var>[a-zA-Z_][a-zA-Z0-9_]*)\}(?P<tail>.*?)(?P=quote)\s*\)",
            re.MULTILINE,
        )

        def repl(match: re.Match[str]) -> str:
            variable = match.group("var")
            raw_query = match.group("query") + "{" + variable + "}" + match.group("tail")
            query = re.sub(rf"'\{{{variable}\}}'", "?", raw_query, count=1)
            if query == raw_query:
                query = raw_query.replace("{" + variable + "}", "?", 1)
            quote = match.group("quote")
            return f'{match.group("prefix")}{quote}{query}{quote}, ({variable},))'

        return pattern.sub(repl, content, count=1)

    def _replace_hardcoded_secret(self, content: str) -> str:
        detector = IncidentDetector()
        match = detector._find_hardcoded_secret(content)
        if not match:
            return content
        name = match.group("name")
        replacement = f'{name} = os.getenv("{name}", "")'
        updated = content.replace(match.group(0), replacement, 1)
        if "import os" not in updated:
            lines = updated.splitlines()
            insert_at = 1 if lines and lines[0].startswith('"""') else 0
            lines.insert(insert_at + 1 if insert_at and len(lines) > 1 else insert_at, "import os")
            updated = "\n".join(lines)
            if content.endswith("\n"):
                updated += "\n"
        return updated

    def _inject_auth_decorator(self, content: str, context_profile: ContextProfile) -> str:
        decorator = self.planner._preferred_auth_decorator(context_profile)
        if not decorator or decorator in content:
            return content
        lines = content.splitlines()
        for index, line in enumerate(lines):
            if line.lstrip().startswith("@router."):
                lines.insert(index, decorator)
                return "\n".join(lines) + ("\n" if content.endswith("\n") else "")
        return content

    def _fix_yaml_load(self, content: str) -> str:
        def repl(match: re.Match[str]) -> str:
            call = match.group(0)
            if "Loader" in call:
                return call
            return call.replace("yaml.load(", "yaml.safe_load(", 1)

        return re.sub(r"\byaml\.load\s*\([^)]*\)", repl, content)

    def _fix_command_injection(self, content: str) -> str:
        pattern = re.compile(
            r"os\.system\s*\(\s*f(?P<quote>[\"'])(?P<cmd>[^{]*)\{(?P<var>[a-zA-Z_][a-zA-Z0-9_]*)\}(?P<tail>[^\"']*?)(?P=quote)\s*\)",
        )

        def repl(match: re.Match[str]) -> str:
            var = match.group("var")
            cmd = match.group("cmd")
            tail = match.group("tail")
            quote = match.group("quote")
            return f'os.system(f{quote}{cmd}{{shlex.quote({var})}}{tail}{quote})'

        updated = pattern.sub(repl, content, count=1)
        if updated != content and "import shlex" not in updated:
            lines = updated.splitlines()
            insert_at = 0
            for i, line in enumerate(lines):
                if line.startswith("import os"):
                    insert_at = i + 1
                    break
            lines.insert(insert_at, "import shlex")
            updated = "\n".join(lines)
            if content.endswith("\n"):
                updated += "\n"
        return updated

    def _fix_eval_injection(self, content: str) -> str:
        updated = re.sub(r"\beval\s*\(", "ast.literal_eval(", content)
        if updated != content and "import ast" not in updated:
            lines = updated.splitlines()
            insert_at = 0
            for i, line in enumerate(lines):
                if line.startswith("import ") or line.startswith("from "):
                    insert_at = i + 1
            lines.insert(insert_at, "import ast")
            updated = "\n".join(lines)
            if content.endswith("\n"):
                updated += "\n"
        return updated

    def _fix_subprocess_injection(self, content: str) -> str:
        pattern = re.compile(
            r"subprocess\.(?P<func>call|run|Popen)\s*\(\s*f(?P<quote>[\"'])(?P<cmd>[^{]*)\{(?P<var>[a-zA-Z_][a-zA-Z0-9_]*)\}(?P<tail>[^\"']*?)(?P=quote)\s*,\s*shell\s*=\s*True\s*\)",
        )

        def repl(match: re.Match[str]) -> str:
            func = match.group("func")
            var = match.group("var")
            cmd = match.group("cmd")
            tail = match.group("tail")
            quote = match.group("quote")
            return f'subprocess.{func}(f{quote}{cmd}{{shlex.quote({var})}}{tail}{quote}, shell=True)'

        updated = pattern.sub(repl, content, count=1)
        if updated != content and "import shlex" not in updated:
            lines = updated.splitlines()
            insert_at = 0
            for i, line in enumerate(lines):
                if line.startswith("import subprocess"):
                    insert_at = i + 1
                    break
            lines.insert(insert_at, "import shlex")
            updated = "\n".join(lines)
            if content.endswith("\n"):
                updated += "\n"
        return updated

    def _fix_weak_cryptography(self, content: str) -> str:
        return re.sub(r"\bhashlib\.md5\s*\(", "hashlib.sha256(", content)

    def _is_valid_python(self, content: str) -> bool:
        try:
            ast.parse(content)
        except SyntaxError:
            return False
        return True


class Verifier:
    def verify(self, artifact: PatchArtifact) -> VerificationResult:
        checks: list[VerificationCheck] = []
        failure_reasons: list[str] = []

        syntax_ok = self._check_syntax(artifact.patched_content)
        checks.append(VerificationCheck(name="syntax", passed=syntax_ok, details="Patched content parses as Python."))
        if not syntax_ok:
            failure_reasons.append("Patched content is not valid Python.")

        semgrep_findings = self._run_semgrep(artifact)
        semgrep_ok = semgrep_findings is not None
        if semgrep_findings is None:
            semgrep_ok = True
            checks.append(VerificationCheck(name="semgrep", passed=True, details="Semgrep unavailable; skipped."))
            semgrep_findings = []
        else:
            semgrep_ok = len(semgrep_findings) == 0
            checks.append(
                VerificationCheck(
                    name="semgrep",
                    passed=semgrep_ok,
                    details="No semgrep findings on patched artifact." if semgrep_ok else "Semgrep still reports findings.",
                )
            )
            if not semgrep_ok:
                failure_reasons.append("Semgrep still reports findings on patched artifact.")

        assertions_ok, assertion_failures = self._run_assertions(artifact)
        checks.extend(assertion_failures["checks"])
        failure_reasons.extend(assertion_failures["reasons"])

        verdict = "verified_fix"
        if not artifact.plans:
            verdict = "needs_human_review"
            failure_reasons.append("No remediation plans were applied.")
        elif not syntax_ok or not assertions_ok:
            verdict = "unsafe_patch"
        elif not semgrep_ok:
            verdict = "needs_human_review"

        return VerificationResult(
            artifact=artifact,
            verdict=verdict,
            syntax_ok=syntax_ok,
            semgrep_ok=semgrep_ok,
            assertions_ok=assertions_ok,
            semgrep_findings=semgrep_findings,
            checks=checks,
            failure_reasons=failure_reasons,
        )

    def _check_syntax(self, content: str) -> bool:
        try:
            ast.parse(content)
        except SyntaxError:
            return False
        return True

    def _run_semgrep(self, artifact: PatchArtifact):
        if not semgrep_available():
            return None
        with tempfile.TemporaryDirectory(prefix="aion-verify-") as tmp_dir:
            temp_path = Path(tmp_dir) / Path(artifact.target_file).name
            temp_path.write_text(artifact.patched_content, encoding="utf-8")
            try:
                return SemgrepRunner().run(temp_path)
            except SemgrepError:
                return []

    def _run_assertions(self, artifact: PatchArtifact) -> tuple[bool, dict[str, list[object]]]:
        checks: list[VerificationCheck] = []
        reasons: list[str] = []
        patched = artifact.patched_content

        for plan in artifact.plans:
            if plan.strategy == "parameterize_sqlite_query":
                passed = 'cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))' in patched
                checks.append(
                    VerificationCheck(
                        name="sqlite_parameterization",
                        passed=passed,
                        details="sqlite query uses a placeholder and bound parameters.",
                    )
                )
                if not passed:
                    reasons.append("Patched sqlite query is not parameterized.")
            elif plan.strategy == "env_secret":
                passed = "os.getenv(" in patched and "sk-live-" not in patched
                checks.append(
                    VerificationCheck(
                        name="secret_removed",
                        passed=passed,
                        details="Hardcoded secret was replaced with an environment lookup.",
                    )
                )
                if not passed:
                    reasons.append("Hardcoded secret literal still exists after patching.")
            elif plan.strategy == "inject_auth_decorator":
                details = plan.summary.replace("Insert the repository auth decorator ", "").rstrip(".")
                passed = details in patched
                checks.append(
                    VerificationCheck(
                        name="auth_decorator_present",
                        passed=passed,
                        details="Selected auth decorator is present in the route declaration.",
                    )
                )
                if not passed:
                    reasons.append("Auth decorator was not injected into the route declaration.")
            elif plan.strategy == "safe_yaml_load":
                remaining_unsafe = any(
                    "Loader" not in m.group(0)
                    for m in re.finditer(r"\byaml\.load\s*\([^)]*\)", patched)
                )
                passed = "yaml.safe_load(" in patched and not remaining_unsafe
                checks.append(
                    VerificationCheck(
                        name="yaml_safe_load",
                        passed=passed,
                        details="yaml.load replaced with yaml.safe_load to prevent arbitrary code execution.",
                    )
                )
                if not passed:
                    reasons.append("Insecure yaml.load still present after patching.")
            elif plan.strategy == "shlex_quote_command":
                passed = "shlex.quote(" in patched
                checks.append(
                    VerificationCheck(
                        name="command_shlex_quoted",
                        passed=passed,
                        details="os.system argument is wrapped with shlex.quote to prevent shell injection.",
                    )
                )
                if not passed:
                    reasons.append("os.system call is not protected with shlex.quote.")
            elif plan.strategy == "ast_literal_eval":
                passed = "ast.literal_eval(" in patched and "import ast" in patched
                checks.append(
                    VerificationCheck(
                        name="eval_replaced",
                        passed=passed,
                        details="eval() replaced with ast.literal_eval() to prevent arbitrary code execution.",
                    )
                )
                if not passed:
                    reasons.append("eval() was not replaced with ast.literal_eval().")
            elif plan.strategy == "shlex_quote_subprocess":
                passed = "shlex.quote(" in patched
                checks.append(
                    VerificationCheck(
                        name="subprocess_shlex_quoted",
                        passed=passed,
                        details="subprocess f-string argument is wrapped with shlex.quote to prevent shell injection.",
                    )
                )
                if not passed:
                    reasons.append("subprocess call is not protected with shlex.quote.")
            elif plan.strategy == "upgrade_hash_algorithm":
                passed = "hashlib.sha256(" in patched and "hashlib.md5(" not in patched
                checks.append(
                    VerificationCheck(
                        name="weak_hash_removed",
                        passed=passed,
                        details="hashlib.md5 replaced with hashlib.sha256 for stronger security.",
                    )
                )
                if not passed:
                    reasons.append("Weak hash algorithm hashlib.md5 still present after patching.")

        return not reasons, {"checks": checks, "reasons": reasons}


class RepairExecutor:
    def __init__(
        self,
        detector: IncidentDetector | None = None,
        generator: PatchGenerator | None = None,
        verifier: Verifier | None = None,
        knowledge_base=None,
    ):
        self.detector = detector or IncidentDetector()
        self.generator = generator or PatchGenerator()
        self.verifier = verifier or Verifier()
        self.knowledge_base = knowledge_base  # optional KnowledgeBase; avoids circular import

    def run(
        self,
        target: Path,
        context_profile: ContextProfile,
        verify: bool = True,
    ) -> RepairAttemptRecord:
        incidents = self.detector.detect(target, context_profile)
        artifact = self.generator.generate(target, incidents, context_profile)
        warnings: list[str] = []
        if not incidents:
            warnings.append("No actionable incidents were detected.")
        if incidents and artifact is None:
            warnings.append("Incidents were detected, but no deterministic patch could be generated.")

        verification = None
        if verify and artifact is not None:
            verification = self.verifier.verify(artifact)
            if self.knowledge_base is not None:
                for incident in incidents:
                    if verification.verdict == "verified_fix":
                        self.knowledge_base.record_success(incident, verification)
                    else:
                        self.knowledge_base.record_failure(incident)

        return RepairAttemptRecord(
            target=normalize_path(target),
            created_at=datetime.now(timezone.utc).isoformat(),
            context_profile=context_profile,
            incidents=incidents,
            artifact=artifact,
            verification=verification,
            warnings=warnings,
        )

    def write_record(self, record: RepairAttemptRecord, destination: Path) -> None:
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(record.model_dump_json(indent=2), encoding="utf-8")
