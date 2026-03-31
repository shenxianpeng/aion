# aicodescan

`aicodescan` is a context-aware CLI security scanner for AI-generated Python code.

It builds a lightweight security profile from the existing repository, runs `semgrep` as a fast first pass, and only asks the LLM to explain concrete issues when there is something to investigate. The main differentiator is context-gap reporting, for example: "this file uses `sqlite3`, but the rest of the project uses `sqlalchemy` sessions."

## Current MVP

- Python-only scanning
- Project context extraction via `ast`
- `semgrep --config p/python` integration
- Anthropic-backed structured findings
- Anthropic and OpenAI providers
- AI-generated file detection via file markers, git history, or explicit `--ai-generated`
- Rich terminal output and JSON output

## Install

```bash
uv sync
```

## Usage

```bash
export ANTHROPIC_API_KEY=your_key
uv run aicodescan scan ./path/to/project
uv run aicodescan scan ./path/to/project --ai-generated ./path/to/project/generated_file.py
uv run aicodescan scan ./path/to/project --output json
export OPENAI_API_KEY=your_key
uv run aicodescan scan ./path/to/project --provider openai
```

## Config File

Create `.aicodescan.yaml` in the project root:

```yaml
provider: openai
model: gpt-4.1
ignore_paths:
  - tests/*
  - scripts/generated_*.py
```

CLI flags still override config values.

## Notes

- If `semgrep` is unavailable, the tool degrades to LLM-only mode and prints a warning.
- If no AI-generated markers are found, the tool scans all Python files and prints a warning.
- Context extraction cache is stored at `~/.aicodescan-context.json`.
- Provider-specific defaults: Anthropic uses `claude-3-5-sonnet-latest`; OpenAI uses `gpt-4.1` unless `--model` is set.

## Tests

```bash
uv run pytest tests/unit
uv run pytest -m eval tests/eval
```
