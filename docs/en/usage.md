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

Repair and verification flow:

```bash
uv run aion repair ./path/to/file.py \
  --context-file ./context.json \
  --artifact-path ./artifact.json \
  --record-path ./repair-record.json

uv run aion verify --artifact-path ./artifact.json

uv run aion run-incident ./path/to/file.py \
  --context-file ./context.json \
  --record-path ./incident-record.json \
  --output json

uv run aion repair-eval ./tests/fixtures \
  --records-dir ./repair-records \
  --output json
```

The current autonomy release generates patch artifacts and verifies them locally. It does not rewrite production files in place.
`repair-eval` runs the deterministic repair pipeline across fixture cases and reports repair success rate, verification pass rate, false-fix rate, and rollback rate.

Verbose mode prints the extracted context profile, Semgrep findings, fallback reasons,
and token estimates to stderr.

## Typical workflow

1. Point the tool at a repository or a generated file.
2. Let it identify candidate Python files.
3. Review warnings about AI-generated detection or missing `semgrep`.
4. Inspect context-aware findings and suggested fixes.
