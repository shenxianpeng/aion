# Roadmap

This roadmap reflects the current shipped state of AION and the remaining work
required to move from a local control-plane prototype toward production-grade
self-healing.

## Current status

The repository now ships:

- context-aware Python scanning with repository profiling and Semgrep triage
- deterministic repair artifacts plus standalone verification
- repair evaluation with persisted repair records and metrics
- sandbox orchestration for single events, event queues, inbox items, and webhooks
- release candidates with approval, staged advancement, rejection, and rollback
- runtime-first defense planning for containment before rollout

## Phases completed in the current implementation

### Phase 0: Trusted foundation

- Findings are upgraded into structured incidents.
- Repair, verification, orchestration, and release flows share JSON models.
- Fixtures cover the incident lifecycle end to end.

### Phase 1: Automatic repair closed loop

- Deterministic repair is implemented for the first supported issue classes.
- Verification runs syntax checks, Semgrep re-scan, assertions, and optional sandbox commands.
- `repair`, `verify`, and `run-incident` provide a local closed loop.

### Phase 2: Self-verification and learning

- Repair attempts can be persisted as audit records.
- `repair-eval` computes repair success, verification pass, false-fix, and rollback rates.
- Failure outcomes are captured for later template and policy refinement.

### Phase 3: Pre-production autonomy prototype

- The orchestrator accepts JSON events, queue payloads, inbox items, and webhooks.
- Policy gating decides whether an incident can enter automatic sandbox remediation.
- Repository-level sandbox execution supports project-specific verification commands.
- Release candidate management now covers approval and staged rollout decisions.

## Next steps

### Phase 4: Production adapters

The next major work is no longer core modeling. It is integration:

- authenticated webhook and queue adapters for real event sources
- deployment adapters for promotion, rollback, and rollout telemetry
- provider adapters for WAF, gateway, and feature flag execution
- approval and audit integration with external systems
- richer repository test selection instead of only configured command lists

## Guiding principle

AION is intentionally conservative. Every step favors deterministic artifacts,
auditable state, and reversible rollout decisions over opaque automation.
