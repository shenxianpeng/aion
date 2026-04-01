# Configuration

Place a `.aion.yaml` file in the target repository root.

## Example

```yaml
provider: openai
model: gpt-4.1
ignore_paths:
  - tests/*
  - scripts/generated_*.py
```

## Fields

| Field | Type | Description |
|-------|------|-------------|
| `provider` | string | `anthropic` or `openai` |
| `model` | string | Explicit model name |
| `ignore_paths` | list | Glob patterns to skip during scanning |

## Override order

CLI flags take precedence over `.aion.yaml`.

## Cache

Context extraction results are cached at:

```text
~/.aion-context.json
```
