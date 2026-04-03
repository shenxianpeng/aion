# How It Works

AION is a staged control plane. The same repository can move from static
analysis into repair, verification, orchestration, rollout control, and runtime
containment without changing the core data model.

## 1. Normalize the signal

AION can start from:

- `scan` over a repository or file
- a single event JSON payload
- an event queue JSON payload
- a file-backed inbox item
- a webhook `POST /events`

All of these become structured orchestration events.

## 2. Build repository context

Before deciding whether something is risky, AION extracts a lightweight
repository profile:

- imports and dominant framework usage
- authentication decorators
- database access patterns
- function names
- probable ORM and HTTP client conventions

That context lets AION detect project-specific drift instead of only generic
rule hits.

## 3. Upgrade findings into incidents

Detection combines:

- `semgrep --config p/python`
- repository-specific fallback heuristics
- optional LLM explanation for context-sensitive findings

Actionable results are promoted into incidents with severity, confidence,
evidence, remediation strategy, and verification strategy.

## 4. Turn incidents into patch artifacts

For supported issue types, AION generates deterministic patch artifacts instead
of mutating the live repository:

- interpolated `sqlite3` queries become parameterized calls
- hardcoded secrets become environment lookups
- missing auth decorators are aligned to the repository pattern

The artifact includes the original content, patched content, diff, plans, and
validation status.

## 5. Verify inside a sandbox

Artifacts are staged in one of two modes:

- `file`: copy only the target file into a temporary workspace
- `repository`: copy the repository and rewrite the target path inside it

Verification combines:

- Python syntax validation
- Semgrep re-scan when available
- built-in remediation assertions
- project-specific commands from `sandbox_verification_commands`

The result becomes a rollout recommendation:

- `approved_for_rollout`
- `rollback`
- `needs_human_review`

## 6. Persist control-plane state

The implementation keeps state as local JSON artifacts.

| State | Default location |
|---|---|
| Inbox events | `.aion/inbox/events/` |
| Inbox results | `.aion/inbox/results/` |
| Release candidates | `.aion/releases/` |
| Repair records | user-specified `--record-path` or evaluation directory |

This keeps the system auditable and easy to script around.

## 7. Manage staged rollout

Successful sandbox runs can be promoted into release candidates. The release
state machine supports:

- candidate creation
- approval
- phased advancement through canary, staged, broad, and full rollout
- rejection
- rollback

## 8. Plan runtime-first containment

In parallel with code remediation, AION can produce a runtime defense plan with
actions such as:

- gateway blocks
- WAF rules
- feature flag changes
- dependency pins
- code-patch follow-up actions

This keeps the system biased toward containment first and code rollout second.

## 9. Self-evolving loop: drift detection and learning

AION implements a continuous self-improvement cycle:

### Drift detection

`aion snapshot` captures a security fingerprint (file hashes + incidents + health
score) at a point in time. `aion drift` compares the live state against that
baseline to identify regressions and compute a health delta.

| State | Default location |
|---|---|
| Snapshots | `.aion/snapshots/` |

The health score is a 0.0–1.0 metric: 1.0 means no known vulnerabilities;
lower values reflect incident severity and count relative to repository size.

### Knowledge base

Every successful repair is recorded as a pattern in the knowledge base. Over
time the engine accumulates historical success rates per issue type and
remediation strategy. These rates are used to compute a **confidence boost** at
repair time so that well-understood issue types are handled with higher certainty.

| State | Default location |
|---|---|
| Repair patterns | `.aion/knowledge/patterns.json` |

### Watch mode

`aion watch` implements the outer loop: poll → detect drift → auto-repair →
record → refresh baseline. Each iteration uses the knowledge base to improve
patch confidence. Use `aion status` to inspect the accumulated state.

## 10. Current boundary

The current implementation stops at local control-plane decisions and persisted
artifacts. Real production queues, deploy systems, WAF APIs, feature flag
providers, and rollout automation remain integration work on top of these
interfaces.
