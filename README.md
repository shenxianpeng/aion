# AION

[![Docs](https://img.shields.io/badge/docs-github%20pages-blue)](https://shenxianpeng.github.io/aion/)

> **Code Once, Live Forever.**

`AION` is The Self-Evolving Code Engine — designed to end technical debt and keep your codebase in a perpetual state of health.

AI scans your code continuously, automatically rewrites outdated syntax and risky logic, and delivers an evolved codebase every day. Instead of treating every file in isolation, it builds a lightweight profile of the existing repository, runs `semgrep` as a fast first pass, and only asks the LLM to investigate files that have concrete risk signals or meaningful context gaps. The main differentiator is context-gap reporting, for example: "this file uses `sqlite3`, but the rest of the project uses `sqlalchemy` sessions."

## Current MVP

- Python-only scanning
- Project context extraction via `ast`
- `semgrep --config p/python` integration
- Anthropic-backed structured findings
- Anthropic and OpenAI providers
- AI-generated file detection via file markers, git history, or explicit `--ai-generated`
- Rich terminal output and JSON output
- Deterministic remediation planning for high-confidence Python issues
- Patch artifact generation and standalone verification
- Local orchestrator skeleton for `scan -> repair -> verify` incident handling

## Install

```bash
uv sync
```

## Usage

```bash
export ANTHROPIC_API_KEY=your_key
uv run aion scan ./path/to/project
uv run aion scan ./path/to/project --ai-generated ./path/to/project/generated_file.py
uv run aion scan ./path/to/project --output json
export OPENAI_API_KEY=your_key
uv run aion scan ./path/to/project --provider openai
uv run aion repair ./path/to/file.py --context-file ./context.json --artifact-path ./artifact.json
uv run aion verify --artifact-path ./artifact.json
uv run aion run-incident ./path/to/file.py --context-file ./context.json --output json
uv run aion repair-eval ./tests/fixtures --records-dir ./repair-records --output json
```

## Config File

Create `.aion.yaml` in the project root:

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
- Context extraction cache is stored at `~/.aion-context.json`.
- Provider-specific defaults: Anthropic uses `claude-3-5-sonnet-latest`; OpenAI uses `gpt-4.1` unless `--model` is set.
- The first autonomy release does not modify production code or apply patches in place; it emits patch artifacts and verifies them locally.
- Deterministic auto-repair currently covers raw sqlite f-string queries, hardcoded secrets, and missing auth decorators.
- `repair` and `run-incident` can persist full repair attempt records for auditability, and `repair-eval` reports repair success, verification pass, false-fix, and rollback rates.

## Tests

```bash
uv run pytest tests/unit
uv run pytest -m eval tests/eval
```

## Documentation

Full documentation is published with GitHub Pages:

- English: `docs/en/`
- 中文: `docs/zh/`
- Site URL: `https://shenxianpeng.github.io/aion/`
