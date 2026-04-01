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
uv run aion process-event ./event.json --result-path ./orchestration.json --output json
uv run aion process-event-queue ./events.json --results-dir ./queue-results --output json
uv run aion enqueue-event ./event.json --inbox-root ./.aion/inbox
uv run aion process-inbox --inbox-root ./.aion/inbox --output json
uv run aion create-release-candidate ./.aion/inbox/results/<event>.json --releases-root ./.aion/releases
uv run aion approve-release <candidate-id> --approver alice --releases-root ./.aion/releases
uv run aion advance-release <candidate-id> --releases-root ./.aion/releases
uv run aion plan-defense ./.aion/inbox/results/<event>.json --output json
uv run aion serve-webhook --inbox-root ./.aion/inbox --host 127.0.0.1 --port 8080
```

## Config File

Create `.aion.yaml` in the project root:

```yaml
provider: openai
model: gpt-4.1
ignore_paths:
  - tests/*
  - scripts/generated_*.py
auto_repair_issue_types:
  - raw_sqlite_query
  - hardcoded_secret
auto_repair_min_confidence: 0.90
sandbox_mode: repository
sandbox_verification_commands:
  - python -m pytest tests/unit
auto_approve_verified_fixes: false
rollback_on_verification_failure: true
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
- `process-event` is the current control-plane prototype: it ingests an event payload, applies policy gating, and runs approved remediations in a sandbox workspace.
- `.aion.yaml` now controls auto-repair issue allowlists, minimum confidence, and sandbox mode (`file` or `repository`) for orchestration commands.
- `process-event-queue` processes a JSON array of events, persists per-event results, and reports aggregate queue metrics.
- `enqueue-event`, `list-inbox`, and `process-inbox` provide a persistent file-backed inbox so orchestration can consume events incrementally instead of only from ad hoc JSON arrays.
- `serve-webhook` exposes `POST /events` and writes accepted payloads straight into the inbox for near-real-time orchestration.
- Sandbox orchestration can now run project-specific verification commands and emit a rollout recommendation: `approved_for_rollout`, `rollback`, or `needs_human_review`.
- `create-release-candidate`, `approve-release`, `advance-release`, `reject-release`, and `rollback-release` implement a staged rollout state machine with canary/broad/full phases.
- `plan-defense` emits runtime-first containment actions such as gateway blocks, WAF rules, feature flags, dependency pins, and code patch follow-ups.

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
