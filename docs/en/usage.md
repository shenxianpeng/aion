# Usage

## Prerequisites

- Set `OPENAI_API_KEY` or `ANTHROPIC_API_KEY` before running `scan`
- Place `.aion.yaml` in the target repository root if you want policy or sandbox defaults
- Use `--output json` when you want machine-readable artifacts

## 1. Scan a repository

```bash
uv run aion scan ./path/to/project
```

Scan only files you already know are AI-generated:

```bash
uv run aion scan ./path/to/project \
  --ai-generated ./path/to/project/generated_file.py
```

Switch provider or emit JSON:

```bash
uv run aion scan ./path/to/project --provider openai --output json
```

Print extracted context, fallback reasons, and Semgrep detail:

```bash
uv run aion scan ./path/to/project --verbose
```

## 2. Generate and verify a repair artifact

Create a deterministic patch artifact and persist the audit trail:

```bash
uv run aion repair ./path/to/file.py \
  --context-file ./context.json \
  --artifact-path ./artifact.json \
  --record-path ./repair-record.json
```

Verify an existing artifact:

```bash
uv run aion verify --artifact-path ./artifact.json
```

Run the full incident flow against a single file:

```bash
uv run aion run-incident ./path/to/file.py \
  --context-file ./context.json \
  --record-path ./incident-record.json \
  --output json
```

Evaluate deterministic repair quality across fixtures:

```bash
uv run aion repair-eval ./tests/fixtures \
  --records-dir ./repair-records \
  --output json
```

## 3. Orchestrate events in a sandbox

Process one event:

```bash
uv run aion process-event ./event.json \
  --result-path ./orchestration.json \
  --output json
```

Process a JSON array of events:

```bash
uv run aion process-event-queue ./events.json \
  --results-dir ./queue-results \
  --output json
```

Typical event payload:

```json
{
  "event_id": "runtime-001",
  "event_type": "runtime_alert",
  "target_file": "/absolute/path/to/service.py",
  "metadata": {
    "repo_root": "/absolute/path/to/repo",
    "context_file": "/absolute/path/to/context.json"
  }
}
```

Supported event types in the current release:

- `code_scan`
- `runtime_alert`
- `dependency_alert`

## 4. Use the persistent inbox and webhook

Enqueue an event into the file-backed inbox:

```bash
uv run aion enqueue-event ./event.json \
  --inbox-root ./.aion/inbox
```

Inspect pending or processed items:

```bash
uv run aion list-inbox \
  --inbox-root ./.aion/inbox \
  --status pending
```

Process everything currently pending:

```bash
uv run aion process-inbox \
  --inbox-root ./.aion/inbox \
  --output json
```

Start the webhook receiver:

```bash
uv run aion serve-webhook \
  --inbox-root ./.aion/inbox \
  --host 127.0.0.1 \
  --port 8080
```

The webhook accepts `POST /events` and writes accepted payloads into the inbox.

## 5. Manage staged rollout

Create a release candidate from a successful orchestration result:

```bash
uv run aion create-release-candidate ./.aion/inbox/results/<event>.json \
  --releases-root ./.aion/releases
```

Inspect current candidates:

```bash
uv run aion list-releases --releases-root ./.aion/releases
```

Approve and advance through phases:

```bash
uv run aion approve-release <candidate-id> \
  --approver alice \
  --releases-root ./.aion/releases

uv run aion advance-release <candidate-id> \
  --releases-root ./.aion/releases
```

Reject or roll back:

```bash
uv run aion reject-release <candidate-id> \
  --approver alice \
  --reason "review failed" \
  --releases-root ./.aion/releases

uv run aion rollback-release <candidate-id> \
  --reason "failed canary metrics" \
  --releases-root ./.aion/releases
```

## 6. Plan runtime defense actions

Generate containment recommendations from an orchestration result:

```bash
uv run aion plan-defense ./.aion/inbox/results/<event>.json --output json
```

The current defense planner can emit:

- gateway blocks
- WAF rules
- feature flag actions
- dependency pin recommendations
- code-patch follow-up actions

## 7. Track security drift and evolution

### Save a security baseline

Capture the current security state of your repository:

```bash
uv run aion snapshot ./src --name baseline
```

This creates `.aion/snapshots/baseline.json` containing a health score, incident
list, and file hashes — a reproducible fingerprint of the repository's security
posture.

### Check for drift

Compare the current state against a saved snapshot to detect regressions:

```bash
uv run aion drift ./src --name baseline
```

Exit code `0` means no regression. Exit code `1` means new incidents were found.
Use `--output json` to get a machine-readable drift report for CI integration.

### Continuous watch mode

Monitor a directory for security drift and auto-repair new incidents as they appear:

```bash
uv run aion watch ./src --interval 30 --auto-repair
```

AION polls every `--interval` seconds, compares against the last known-good
baseline, and automatically generates and verifies patches for any new incidents.
Each successful repair is recorded in the knowledge base so future runs improve.

### Inspect engine health and learned patterns

Show accumulated snapshots and knowledge-base repair patterns:

```bash
uv run aion status
# or specify a custom .aion directory
uv run aion status --aion-dir ./.aion --output json
```

## Operational notes

- The current release emits patch artifacts; it does not rewrite live production files in place.
- `sandbox_verification_commands` run inside the staged workspace, not inside your working tree.
- `process-event` and inbox processing automatically load `.aion.yaml` from the event repository root.
- `repair-eval` reports repair success rate, verification pass rate, false-fix rate, and rollback rate.
- Drift snapshots and knowledge-base patterns are persisted in `.aion/` and survive restarts.
