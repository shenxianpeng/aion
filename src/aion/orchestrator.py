from __future__ import annotations

import hashlib
import shutil
import tempfile
from pathlib import Path

from .models import (
    ContextProfile,
    Incident,
    OrchestrationEvent,
    OrchestrationResult,
    PatchArtifact,
    PolicyDecision,
    RepairSession,
    RunIncidentResult,
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
    def __init__(self, verifier: Verifier | None = None):
        self.verifier = verifier or Verifier()

    def execute(self, artifact: PatchArtifact) -> SandboxExecutionResult:
        workspace = Path(tempfile.mkdtemp(prefix="aion-sandbox-"))
        target_path = workspace / Path(artifact.target_file).name
        target_path.write_text(artifact.patched_content, encoding="utf-8")
        staged_artifact = artifact.model_copy(update={"target_file": str(target_path)})
        verification = self.verifier.verify(staged_artifact)
        return SandboxExecutionResult(
            workspace_root=str(workspace),
            staged_target_file=str(target_path),
            patch_applied=True,
            verification=verification,
        )


class Orchestrator:
    def __init__(
        self,
        detector: IncidentDetector | None = None,
        generator: PatchGenerator | None = None,
        verifier: Verifier | None = None,
        policy_engine: PolicyEngine | None = None,
        sandbox_executor: SandboxExecutor | None = None,
    ):
        self.detector = detector or IncidentDetector()
        self.generator = generator or PatchGenerator()
        self.verifier = verifier or Verifier()
        self.policy_engine = policy_engine or PolicyEngine()
        self.sandbox_executor = sandbox_executor or SandboxExecutor(self.verifier)

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
    ) -> OrchestrationResult:
        target = Path(event.target_file)
        incidents = self.detector.detect(target, context_profile)
        policy = self.policy_engine.decide(event, incidents)
        result = OrchestrationResult(event=event, policy=policy, incidents=incidents)

        if policy.action != "auto_repair_sandbox":
            return result

        artifact = self.generator.generate(target, incidents, context_profile)
        result.artifact = artifact
        if artifact is None:
            result.warnings.append("Policy approved sandbox remediation, but no patch artifact was generated.")
            return result

        sandbox = self.sandbox_executor.execute(artifact)
        result.sandbox = sandbox
        if sandbox.verification is not None and sandbox.verification.verdict != "verified_fix":
            result.warnings.append("Sandbox verification did not produce a verified fix.")
        return result

    def cleanup_sandbox(self, result: OrchestrationResult) -> None:
        if result.sandbox is None:
            return
        shutil.rmtree(result.sandbox.workspace_root, ignore_errors=True)

    def _event_id(self, event_type: str, target_file: str) -> str:
        digest = hashlib.sha256(f"{event_type}:{target_file}".encode("utf-8")).hexdigest()
        return digest[:12]
