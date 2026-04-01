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

## Operational notes

- The current release emits patch artifacts; it does not rewrite live production files in place.
- `sandbox_verification_commands` run inside the staged workspace, not inside your working tree.
- `process-event` and inbox processing automatically load `.aion.yaml` from the event repository root.
- `repair-eval` reports repair success rate, verification pass rate, false-fix rate, and rollback rate.
