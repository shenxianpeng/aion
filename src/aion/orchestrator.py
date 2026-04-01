from __future__ import annotations

import hashlib
import shlex
import shutil
import subprocess
import tempfile
from pathlib import Path

from .config import AppConfig
from .defense import RuntimeDefensePlanner
from .models import (
    CommandExecutionResult,
    ContextProfile,
    EventQueueSummary,
    Incident,
    OrchestrationEvent,
    OrchestrationResult,
    PatchArtifact,
    PolicyDecision,
    RepairSession,
    RolloutDecision,
    RunIncidentResult,
    SandboxMode,
    SandboxExecutionResult,
)
from .repair import IncidentDetector, PatchGenerator, Verifier


class PolicyEngine:
    def __init__(
        self,
        auto_repair_issue_types: set[str] | None = None,
        min_confidence: float = 0.85,
    ):
        self.auto_repair_issue_types = auto_repair_issue_types or {
            "raw_sqlite_query",
            "hardcoded_secret",
            "missing_auth_decorator",
        }
        self.min_confidence = min_confidence

    def decide(self, event: OrchestrationEvent, incidents: list[Incident]) -> PolicyDecision:
        if not incidents:
            return PolicyDecision(
                action="needs_human_review",
                reasons=["No actionable incidents were detected for the event."],
                sandbox_required=True,
            )

        blocked = [
            incident
            for incident in incidents
            if incident.issue_type not in self.auto_repair_issue_types or incident.confidence < self.min_confidence
        ]
        if blocked:
            reasons = []
            for incident in blocked:
                if incident.issue_type not in self.auto_repair_issue_types:
                    reasons.append(f"{incident.issue_type} is not approved for automatic remediation.")
                if incident.confidence < self.min_confidence:
                    reasons.append(
                        f"{incident.issue_type} confidence {incident.confidence:.2f} is below the auto-repair threshold."
                    )
            return PolicyDecision(
                action="needs_human_review",
                reasons=reasons,
                sandbox_required=True,
            )

        reasons = [f"{event.event_type} event approved for sandbox remediation."]
        if event.event_type == "runtime_alert":
            reasons.append("Runtime alerts remain sandbox-only and require staged verification before rollout.")
        return PolicyDecision(
            action="auto_repair_sandbox",
            reasons=reasons,
            approved_incident_ids=[incident.id for incident in incidents],
            sandbox_required=True,
        )


class SandboxExecutor:
    def __init__(
        self,
        verifier: Verifier | None = None,
        mode: SandboxMode = "file",
        verification_commands: list[str] | None = None,
        auto_approve_verified_fixes: bool = False,
        rollback_on_verification_failure: bool = True,
    ):
        self.verifier = verifier or Verifier()
        self.mode = mode
        self.verification_commands = verification_commands or []
        self.auto_approve_verified_fixes = auto_approve_verified_fixes
        self.rollback_on_verification_failure = rollback_on_verification_failure

    def execute(self, artifact: PatchArtifact, repo_root: Path | None = None) -> SandboxExecutionResult:
        workspace = Path(tempfile.mkdtemp(prefix="aion-sandbox-"))
        target_path, staged_repo_root = self._stage_target(workspace, artifact, repo_root)
        staged_artifact = artifact.model_copy(update={"target_file": str(target_path)})
        verification = self.verifier.verify(staged_artifact)
        command_results = self._run_verification_commands(staged_repo_root)
        rollout = self._decide_rollout(verification, command_results)
        return SandboxExecutionResult(
            mode=self.mode,
            workspace_root=str(workspace),
            staged_repo_root=str(staged_repo_root),
            staged_target_file=str(target_path),
            patch_applied=True,
            command_results=command_results,
            verification=verification,
            rollout=rollout,
        )

    def _stage_target(self, workspace: Path, artifact: PatchArtifact, repo_root: Path | None) -> tuple[Path, Path]:
        if self.mode == "repository" and repo_root is not None and repo_root.exists() and repo_root.is_dir():
            staged_repo = workspace / repo_root.name
            shutil.copytree(repo_root, staged_repo, dirs_exist_ok=True)
            artifact_path = Path(artifact.target_file)
            try:
                relative_target = artifact_path.relative_to(repo_root)
            except ValueError as exc:
                raise ValueError(
                    f"In 'repository' sandbox mode, artifact.target_file must be within repo_root "
                    f"({repo_root}); got {artifact_path}"
                ) from exc
            target_path = staged_repo / relative_target
        else:
            staged_repo = workspace
            target_path = workspace / Path(artifact.target_file).name
        target_path.parent.mkdir(parents=True, exist_ok=True)
        target_path.write_text(artifact.patched_content, encoding="utf-8")
        return target_path, staged_repo

    def _run_verification_commands(self, staged_repo_root: Path) -> list[CommandExecutionResult]:
        results: list[CommandExecutionResult] = []
        for command in self.verification_commands:
            try:
                completed = subprocess.run(
                    shlex.split(command),
                    cwd=staged_repo_root,
                    capture_output=True,
                    text=True,
                    check=False,
                )
                results.append(
                    CommandExecutionResult(
                        command=command,
                        cwd=str(staged_repo_root),
                        passed=completed.returncode == 0,
                        exit_code=completed.returncode,
                        stdout=completed.stdout.strip(),
                        stderr=completed.stderr.strip(),
                    )
                )
            except OSError as exc:
                results.append(
                    CommandExecutionResult(
                        command=command,
                        cwd=str(staged_repo_root),
                        passed=False,
                        exit_code=-1,
                        stderr=str(exc),
                    )
                )
        return results

    def _decide_rollout(
        self,
        verification,
        command_results: list[CommandExecutionResult],
    ) -> RolloutDecision:
        reasons: list[str] = []
        verification_ok = verification is not None and verification.verdict == "verified_fix"
        commands_ok = all(result.passed for result in command_results)

        if not verification_ok:
            reasons.append("Sandbox verification did not produce a verified fix.")
        failed_commands = [result.command for result in command_results if not result.passed]
        if failed_commands:
            reasons.append(f"Sandbox verification commands failed: {', '.join(failed_commands)}")

        if not verification_ok or not commands_ok:
            recommendation = "rollback" if self.rollback_on_verification_failure else "needs_human_review"
            if not reasons:
                reasons.append("Sandbox checks did not reach an approvable state.")
            return RolloutDecision(recommendation=recommendation, reasons=reasons)

        if self.auto_approve_verified_fixes:
            reasons.append("Sandbox verification and configured commands passed.")
            return RolloutDecision(recommendation="approved_for_rollout", reasons=reasons)

        reasons.append("Sandbox checks passed, but rollout still requires human approval.")
        return RolloutDecision(recommendation="needs_human_review", reasons=reasons)


class Orchestrator:
    def __init__(
        self,
        detector: IncidentDetector | None = None,
        generator: PatchGenerator | None = None,
        verifier: Verifier | None = None,
        policy_engine: PolicyEngine | None = None,
        sandbox_executor: SandboxExecutor | None = None,
        defense_planner: RuntimeDefensePlanner | None = None,
    ):
        self.detector = detector or IncidentDetector()
        self.generator = generator or PatchGenerator()
        self.verifier = verifier or Verifier()
        self.policy_engine = policy_engine or PolicyEngine()
        self.sandbox_executor = sandbox_executor or SandboxExecutor(self.verifier)
        self.defense_planner = defense_planner or RuntimeDefensePlanner()

    @classmethod
    def from_config(
        cls,
        config: AppConfig,
        detector: IncidentDetector | None = None,
        generator: PatchGenerator | None = None,
        verifier: Verifier | None = None,
    ) -> "Orchestrator":
        policy_engine = PolicyEngine(
            auto_repair_issue_types=set(config.auto_repair_issue_types),
            min_confidence=config.auto_repair_min_confidence,
        )
        sandbox_executor = SandboxExecutor(
            verifier=verifier,
            mode=config.sandbox_mode,  # type: ignore[arg-type]
            verification_commands=config.sandbox_verification_commands,
            auto_approve_verified_fixes=config.auto_approve_verified_fixes,
            rollback_on_verification_failure=config.rollback_on_verification_failure,
        )
        return cls(
            detector=detector,
            generator=generator,
            verifier=verifier,
            policy_engine=policy_engine,
            sandbox_executor=sandbox_executor,
        )

    def ingest_event(self, event: dict[str, object]) -> OrchestrationEvent:
        target_file = str(event["target_file"])
        event_type = str(event.get("event_type", "code_scan"))
        event_id = str(event.get("event_id", self._event_id(event_type, target_file)))
        return OrchestrationEvent(
            event_id=event_id,
            event_type=event_type,  # type: ignore[arg-type]
            target_file=target_file,
            metadata=dict(event.get("metadata", {})),
        )

    def plan_remediation(self, incident: Incident) -> dict[str, object]:
        return {
            "incident_id": incident.id,
            "target_file": incident.target_file,
            "strategy": incident.remediation_strategy,
            "verification_strategy": incident.verification_strategy,
        }

    def verify_patch(self, artifact: PatchArtifact):
        return self.verifier.verify(artifact)

    def run_incident(self, target: Path, context_profile: ContextProfile) -> RunIncidentResult:
        incidents = self.detector.detect(target, context_profile)
        session = RepairSession(target=str(target), incidents=incidents)
        artifact = self.generator.generate(target, incidents, context_profile)
        session.artifact = artifact
        if artifact is None:
            session.warnings.append("No deterministic remediation plan could be applied.")
            return RunIncidentResult(session=session, verification=None)
        verification = self.verifier.verify(artifact)
        return RunIncidentResult(session=session, verification=verification)

    def process_event(
        self,
        event: OrchestrationEvent,
        context_profile: ContextProfile,
        repo_root: Path | None = None,
    ) -> OrchestrationResult:
        target = Path(event.target_file)
        incidents = self.detector.detect(target, context_profile)
        policy = self.policy_engine.decide(event, incidents)
        result = OrchestrationResult(event=event, policy=policy, incidents=incidents)

        if policy.action != "auto_repair_sandbox":
            result.defense_plan = self.defense_planner.plan(event, incidents, rollout=None)
            return result

        artifact = self.generator.generate(target, incidents, context_profile)
        result.artifact = artifact
        if artifact is None:
            result.warnings.append("Policy approved sandbox remediation, but no patch artifact was generated.")
            result.defense_plan = self.defense_planner.plan(event, incidents, rollout=None)
            return result

        sandbox = self.sandbox_executor.execute(artifact, repo_root=repo_root)
        result.sandbox = sandbox
        result.defense_plan = self.defense_planner.plan(event, incidents, rollout=sandbox.rollout)
        if sandbox.verification is not None and sandbox.verification.verdict != "verified_fix":
            result.warnings.append("Sandbox verification did not produce a verified fix.")
        return result

    def process_event_queue(
        self,
        events: list[OrchestrationEvent],
        context_loader,
        repo_root_loader,
    ) -> tuple[list[OrchestrationResult], EventQueueSummary]:
        results: list[OrchestrationResult] = []
        summary = EventQueueSummary(total_events=len(events))
        for event in events:
            context_profile = context_loader(event)
            repo_root = repo_root_loader(event)
            result = self.process_event(event, context_profile, repo_root=repo_root)
            results.append(result)
            if result.policy.action == "auto_repair_sandbox":
                summary.auto_repair_count += 1
            elif result.policy.action == "needs_human_review":
                summary.human_review_count += 1
            elif result.policy.action == "blocked":
                summary.blocked_count += 1
            if result.sandbox is not None and result.sandbox.verification is not None and result.sandbox.verification.verdict == "verified_fix":
                summary.verified_count += 1
            if result.sandbox is not None and result.sandbox.rollout is not None:
                if result.sandbox.rollout.recommendation == "approved_for_rollout":
                    summary.approved_count += 1
                elif result.sandbox.rollout.recommendation == "rollback":
                    summary.rollback_count += 1
        return results, summary

    def cleanup_sandbox(self, result: OrchestrationResult) -> None:
        if result.sandbox is None:
            return
        shutil.rmtree(result.sandbox.workspace_root, ignore_errors=True)

    def _event_id(self, event_type: str, target_file: str) -> str:
        digest = hashlib.sha256(f"{event_type}:{target_file}".encode("utf-8")).hexdigest()
        return digest[:12]
