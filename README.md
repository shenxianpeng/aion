# AION

[![PyPI version](https://img.shields.io/pypi/v/aion-evolve)](https://pypi.org/project/aion-evolve/)
[![CI](https://github.com/shenxianpeng/aion/actions/workflows/ci.yml/badge.svg)](https://github.com/shenxianpeng/aion/actions/workflows/ci.yml)
[![Coverage](https://codecov.io/gh/shenxianpeng/aion/graph/badge.svg?branch=main)](https://codecov.io/gh/shenxianpeng/aion)
[![Docs](https://img.shields.io/badge/docs-github%20pages-blue)](https://shenxianpeng.github.io/aion/)
[![AION Auto-Update](https://img.shields.io/badge/AION-Auto--Update-blue)](https://github.com/marketplace/actions/aion-auto-update)

> **Code Once, Live Forever.**

AION is an autonomous code-immunity control plane for Python services. It turns
repository scanning into a staged remediation workflow: detect incidents,
generate deterministic patches, verify them in isolated sandboxes, orchestrate
events through queues and webhooks, and produce rollout plus runtime-defense
decisions.

## What Ships Today

- Context-aware Python scanning with repository profiling, Semgrep triage, and optional LLM explanation
- Deterministic remediation for `raw_sqlite_query`, `hardcoded_secret`, and `missing_auth_decorator`
- Verification with syntax checks, Semgrep re-scan, built-in assertions, and staged project commands
- Event-driven control-plane primitives: inbox, webhook ingress, queue processing, sandbox orchestration
- Release candidate management with approval, phased rollout, rejection, and rollback
- Runtime containment planning covering gateway blocks, WAF rules, feature flags, dependency pins, and code-patch follow-up

## Architecture

| Layer | Implemented capabilities |
|---|---|
| Sensor | Repository scan, JSON event ingestion, persistent inbox, webhook `POST /events` |
| Decision | Incident detection, remediation planning, policy gating, rollout recommendation |
| Execution | Patch artifact generation, file or repository sandbox staging, verification command execution |
| Assurance | Repair records, queue metrics, release candidates, rollback decisions, runtime defense plans |

## Installation

Install from PyPI:

```bash
pip install aion-evolve
```

Or install as a `uv` tool:

```bash
uv tool install aion-evolve
```

For local development:

```bash
git clone https://github.com/shenxianpeng/aion.git
cd aion
uv sync --group dev --group docs
uv run aion --help
```

## Quick Start

Choose at least one LLM provider for `scan`:

```bash
export OPENAI_API_KEY=your_key
# or
export ANTHROPIC_API_KEY=your_key
# or
export DEEPSEEK_API_KEY=your_key
# or
export QWEN_API_KEY=your_key
# or
export GEMINI_API_KEY=your_key
```

Scan a repository:

```bash
aion scan ./path/to/repo --output json
```

If you are running from the cloned repository instead of an installed package,
use `uv run aion ...`.

Plan and verify a deterministic repair:

```bash
aion repair ./path/to/file.py \
  --context-file ./context.json \
  --artifact-path ./artifact.json \
  --record-path ./repair-record.json

aion verify --artifact-path ./artifact.json
```

Process an orchestration event inside a sandbox:

```bash
aion process-event ./event.json \
  --result-path ./orchestration.json \
  --output json
```

Promote a verified result into staged rollout control:

```bash
aion create-release-candidate ./.aion/inbox/results/<event>.json
aion approve-release <candidate-id> --approver alice
aion advance-release <candidate-id>
```

## Configuration

AION supports two config formats in `.aion.yaml`:

### Supported Providers

| Provider | Env Variable | Default Model |
|---|---|---|
| Anthropic | `ANTHROPIC_API_KEY` | `claude-3-5-sonnet-latest` |
| OpenAI | `OPENAI_API_KEY` | `gpt-4.1` |
| DeepSeek | `DEEPSEEK_API_KEY` | `deepseek-chat` |
| Qwen (Tongyi) | `QWEN_API_KEY` | `qwen-plus` |
| Gemini | `GEMINI_API_KEY` | `gemini-2.0-flash` |
| Azure OpenAI | `AZURE_OPENAI_API_KEY` | `gpt-4` |

### Updates block (recommended, Dependabot-like)

```yaml
updates:
  - directory: "/"
    schedule:
      interval: "weekly"
      day: "monday"
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
```

### Legacy flat format (still supported)

```yaml
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
```

CLI flags override equivalent settings from `.aion.yaml`.

## GitHub Action

AION ships as a reusable GitHub Action. Add it to any workflow:

```yaml
# .github/workflows/aion.yml
name: AION Auto-Update
on:
  schedule:
    - cron: '0 9 * * 1'  # Weekly on Monday at 09:00 UTC
  workflow_dispatch:

permissions:
  contents: write
  pull-requests: write

jobs:
  auto-update:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v6
        with:
          fetch-depth: 0
      - uses: shenxianpeng/aion@main
        with:
          openai_api_key: ${{ secrets.OPENAI_API_KEY }}
          # or use deepseek, qwen, anthropic, gemini:
          # deepseek_api_key: ${{ secrets.DEEPSEEK_API_KEY }}
          # qwen_api_key: ${{ secrets.QWEN_API_KEY }}
```

Or run it locally:

```bash
aion auto-update --target ./ --dry-run   # Preview
aion auto-update --target ./              # Live
```

CLI flags override equivalent settings from `.aion.yaml`.

## Command Surface

Core analysis:

- `aion scan`
- `aion repair`
- `aion verify`
- `aion run-incident`
- `aion repair-eval`
- `aion auto-update` ← **Dependabot-style: scan → fix → PR**

Control plane:

- `aion process-event`
- `aion process-event-queue`
- `aion enqueue-event`
- `aion list-inbox`
- `aion process-inbox`
- `aion serve-webhook`

Release and defense:

- `aion create-release-candidate`
- `aion list-releases`
- `aion approve-release`
- `aion reject-release`
- `aion advance-release`
- `aion rollback-release`
- `aion plan-defense`

Drift and monitoring:

- `aion snapshot`
- `aion drift`
- `aion watch`
- `aion status`

## Documentation

Documentation is published at [shenxianpeng.github.io/aion](https://shenxianpeng.github.io/aion/).
The docs site uses native Material for MkDocs language switching backed by the
`mkdocs-static-i18n` plugin, so the language selector and sidebar navigation are
generated per locale instead of being patched in with custom JavaScript.

- [English docs](https://shenxianpeng.github.io/aion/)
- [中文文档](https://shenxianpeng.github.io/aion/zh/)

## Current Scope

- AION produces patch artifacts and staged decisions. It does not hot-patch live production code in place.
- External integrations for production queues, gateways, WAF providers, feature flags, and deployment systems remain adapter work on top of the shipped interfaces.
- The current implementation is Python-only by design.
