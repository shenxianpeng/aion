# Configuration

Place `.aion.yaml` in the target repository root. AION reads it for scan defaults
and the `auto-update` pull-request workflow. It uses a flat config format.

## Example

```yaml
provider: openai
model: gpt-4.1
ignore_paths:
  - tests/*
  - scripts/generated_*.py
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

CLI flags override the matching `.aion.yaml` settings.

## Fields

### Scan

| Field | Type | Default | Description |
|---|---|---|---|
| `provider` | string | `null` | Scan-time LLM provider: `anthropic`, `openai`, `gemini`, `azure`, `deepseek`, or `qwen` |
| `model` | string | provider default | Explicit model override for `scan` |
| `ignore_paths` | list | `[]` | Glob patterns skipped during scanning |

### Auto-update pull requests

| Field | Type | Default | Description |
|---|---|---|---|
| `directory` | string | `/` | Relative directory to operate on |
| `open_pull_requests_limit` | integer | `5` | Maximum concurrent open AION PRs |
| `labels` | list | `[]` | Labels applied to auto-created PRs |
| `reviewers` | list | `[]` | Reviewers requested on auto-created PRs |
| `assignees` | list | `[]` | Assignees for auto-created PRs |
| `target_branch` | string | `main` | Base branch for auto-created PRs |
| `commit_message_prefix` | string | `[AION]` | Prefix for commit messages and PR titles |

## Supported LLM providers

| Provider | Env Variable | Default Model |
|---|---|---|
| Anthropic | `ANTHROPIC_API_KEY` | `claude-3-5-sonnet-latest` |
| OpenAI | `OPENAI_API_KEY` | `gpt-4.1` |
| DeepSeek | `DEEPSEEK_API_KEY` | `deepseek-chat` |
| Qwen (Tongyi) | `QWEN_API_KEY` | `qwen-plus` |
| Gemini | `GEMINI_API_KEY` | `gemini-2.0-flash` |
| Azure OpenAI | `AZURE_OPENAI_API_KEY` | `gpt-4` |

## Resolution rules

- CLI flags override matching `.aion.yaml` settings.
- `scan` and `auto-update` read configuration from the target repository root.

## Operational notes

- `provider` and `model` affect `scan` only; deterministic `repair`, `verify`,
  and `auto-update` do not require an LLM.
- Context extraction results are cached at `~/.aion-context.json`.
- A `schedule:` block is accepted for documentation purposes (AION itself runs
  on demand or on the cron in your workflow), as are unrecognized legacy keys
  from earlier releases — they are parsed but have no effect.
