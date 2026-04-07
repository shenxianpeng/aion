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
- drift detection, knowledge base, and a continuous watch loop for self-evolution
- knowledge-base confidence boosts wired into the policy engine

## Completed phases

### Phase 0: Trusted foundation — shipped in v1.0.0

- Findings are upgraded into structured incidents.
- Repair, verification, orchestration, and release flows share JSON models.
- Fixtures cover the incident lifecycle end to end.

### Phase 1: Automatic repair closed loop — shipped in v1.0.0

- Deterministic repair is implemented for the first supported issue classes.
- Verification runs syntax checks, Semgrep re-scan, assertions, and optional sandbox commands.
- `repair`, `verify`, and `run-incident` provide a local closed loop.

### Phase 2: Self-verification and learning — shipped in v1.0.0

- Repair attempts can be persisted as audit records.
- `repair-eval` computes repair success, verification pass, false-fix, and rollback rates.
- Failure outcomes are captured for later template and policy refinement.

### Phase 3: Pre-production autonomy prototype — shipped in v1.0.0

- The orchestrator accepts JSON events, queue payloads, inbox items, and webhooks.
- Policy gating decides whether an incident can enter automatic sandbox remediation.
- Repository-level sandbox execution supports project-specific verification commands.
- Release candidate management now covers approval and staged rollout decisions.

### Phase 4: Self-evolving engine — shipped in v1.1.0

- **Drift detection**: `snapshot` saves a point-in-time security state; `drift` compares the
  current codebase against any saved snapshot and reports new incidents, resolved incidents,
  regressed files, and a numeric health delta.
- **Knowledge base**: every successful repair is persisted as a `RepairPattern` in
  `.aion/knowledge/patterns.json`; confidence boosts derived from historical success rates are
  applied by the `PolicyEngine` before the auto-repair threshold check, closing the
  self-evolving feedback loop.
- **Continuous watch loop**: `watch` polls a target directory on a configurable interval,
  auto-repairs newly detected incidents, and refreshes the baseline after each successful fix.
- **Engine status dashboard**: `status` shows all saved snapshots and the full knowledge-base
  summary in a single view.
- **Expanded LLM provider support**: Gemini and Azure OpenAI are now supported alongside
  Anthropic and OpenAI, with automatic provider auto-detection from available environment
  variables.

## Next steps

### Phase 5: Production adapters

The next major work is no longer core modeling. It is integration:

- authenticated webhook and queue adapters for real event sources
- deployment adapters for promotion, rollback, and rollout telemetry
- provider adapters for WAF, gateway, and feature flag execution
- approval and audit integration with external systems
- richer repository test selection instead of only configured command lists

## Guiding principle

AION is intentionally conservative. Every step favors deterministic artifacts,
auditable state, and reversible rollout decisions over opaque automation.
