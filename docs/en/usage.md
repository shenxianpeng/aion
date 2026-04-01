# Usage

## Scan a repository

```bash
uv run aion scan ./path/to/project
```

## Scan known AI-generated files only

```bash
uv run aion scan ./path/to/project \
  --ai-generated ./path/to/project/generated_file.py
```

## Use OpenAI instead of Anthropic

```bash
uv run aion scan ./path/to/project --provider openai
```

## Emit JSON

```bash
uv run aion scan ./path/to/project --output json
```

## Verbose mode

```bash
uv run aion scan ./path/to/project --verbose
```

Verbose mode prints the extracted context profile, Semgrep findings, fallback reasons,
and token estimates to stderr.

## Typical workflow

1. Point the tool at a repository or a generated file.
2. Let it identify candidate Python files.
3. Review warnings about AI-generated detection or missing `semgrep`.
4. Inspect context-aware findings and suggested fixes.
