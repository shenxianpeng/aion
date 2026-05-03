# Configuration

Place `.aion.yaml` in the target repository root. AION reads it for repository
scan defaults, orchestration commands, and the auto-update workflow.

AION uses a flat config format. Auto-update fields such as `schedule`,
`open_pull_requests_limit`, and `labels` are configured at the top level.

## Flat Format

```yaml
directory: "/"
schedule:
  interval: "weekly"
  day: "monday"
  time: "09:00"
  timezone: "Asia/Shanghai"
provider: openai
model: gpt-4.1
ignore_paths:
  - tests/*
  - scripts/generated_*.py
auto_repair_issue_types:
  - raw_sqlite_query
  - hardcoded_secret
  - missing_auth_decorator
auto_repair_min_confidence: 0.90
sandbox_mode: repository
sandbox_verification_commands:
  - python -m pytest tests/unit
auto_approve_verified_fixes: false
rollback_on_verification_failure: true
open_pull_requests_limit: 5
labels:
  - "aion"
  - "security"
reviewers:
  - "team:security"
assignees:
  - "username"
target_branch: "main"
commit_message_prefix: "[AION]"
```

## Fields

### Core fields

| Field | Type | Default | Description |
|---|---|---|---|
| `provider` | string | `null` | Scan-time LLM provider, `anthropic` or `openai` |
| `model` | string | provider default | Explicit model override for `scan` |
| `ignore_paths` | list | `[]` | Glob patterns skipped during repository scanning |
| `auto_repair_issue_types` | list | built-in set | Incident types allowed into automatic sandbox remediation |
| `auto_repair_min_confidence` | float | `0.85` | Minimum incident confidence required before automatic remediation |
| `sandbox_mode` | string | `repository` | `file` for single-file staging or `repository` for full repository staging |
| `sandbox_verification_commands` | list | `[]` | Commands executed in the staged sandbox after built-in verification |
| `auto_approve_verified_fixes` | boolean | `false` | Emit `approved_for_rollout` when staged verification passes |
| `rollback_on_verification_failure` | boolean | `true` | Emit `rollback` instead of `needs_human_review` when staged verification fails |

### Auto-update fields

| Field | Type | Default | Description |
|---|---|---|---|
| `directory` | string | `/` | Relative directory to operate on |
| `schedule.interval` | string | `weekly` | `daily`, `weekly`, or `monthly` (for reference; AION itself runs on-demand) |
| `schedule.day` | string | `monday` | Day of the week for `weekly` interval |
| `schedule.time` | string | `09:00` | Time of day (24h format) |
| `schedule.timezone` | string | `UTC` | Timezone for the schedule |
| `open_pull_requests_limit` | integer | `5` | Maximum concurrent open AION PRs |
| `labels` | list | `[]` | Labels applied to auto-created PRs |
| `reviewers` | list | `[]` | Reviewers requested on auto-created PRs |
| `assignees` | list | `[]` | Assignees for auto-created PRs |
| `target_branch` | string | `main` | Base branch for auto-created PRs |
| `commit_message_prefix` | string | `[AION]` | Prefix for commit messages |

## Resolution rules

- CLI flags override matching `.aion.yaml` settings.
- `scan` reads configuration from the target repository root.
- `process-event`, `process-event-queue`, and inbox processing read configuration from the event `repo_root`.

## Recommended profiles

Conservative staging:

```yaml
auto_repair_min_confidence: 0.95
auto_approve_verified_fixes: false
rollback_on_verification_failure: false
```

Fast local experimentation:

```yaml
sandbox_mode: file
auto_approve_verified_fixes: true
rollback_on_verification_failure: true
```

## Operational notes

- `provider` and `model` affect `scan`; deterministic repair and orchestration do not require an LLM.
- `sandbox_verification_commands` execute inside the staged workspace and each command result is stored in the orchestration record.
- Context extraction results are cached at `~/.aion-context.json`.
