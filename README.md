# AION

[![PyPI version](https://img.shields.io/pypi/v/aion-evolve)](https://pypi.org/project/aion-evolve/)
[![CI](https://github.com/shenxianpeng/aion/actions/workflows/ci.yml/badge.svg)](https://github.com/shenxianpeng/aion/actions/workflows/ci.yml)
[![Coverage](https://codecov.io/gh/shenxianpeng/aion/graph/badge.svg?branch=main)](https://codecov.io/gh/shenxianpeng/aion)
[![Docs](https://img.shields.io/badge/docs-github%20pages-blue)](https://shenxianpeng.github.io/aion/)
[![AION Auto-Update](https://img.shields.io/badge/AION-Auto--Update-blue)](https://github.com/marketplace/actions/aion-auto-update)

> **Scan Python repos. Open verified security fixes. Nothing you didn't ask for.**

AION scans a Python repository for a focused set of high-confidence security
issues, generates a **deterministic** patch for each one, **verifies** the patch
in isolation (syntax + an AST assertion that the fix actually holds + an optional
Semgrep re-scan), and opens a pull request only for fixes that pass. If a fix
can't be proven safe, AION reports it for human review instead of touching your
code.

It is intentionally small. The goal is a tool you can trust to run unattended on
your repository, not a platform you have to operate.

## What it actually does

- **Context-aware scanning** — profiles the repository (ORM, HTTP client, auth
  decorators, DB patterns) so findings are grounded in how *your* code is
  written, with optional LLM explanation.
- **Deterministic, verified auto-fixes** for these issue types:
  | Issue | Fix |
  |---|---|
  | `hardcoded_secret` | move the literal to `os.getenv(...)` |
  | `raw_sqlite_query` | parameterize the `cursor.execute` call |
  | `insecure_yaml_load` | `yaml.load` → `yaml.safe_load` |
  | `command_injection` | wrap `os.system` f-string vars in `shlex.quote` |
  | `subprocess_shell_injection` | wrap `subprocess(... shell=True)` vars in `shlex.quote` |
  | `eval_injection` | `eval(...)` → `ast.literal_eval(...)` |
  | `weak_cryptography` | `hashlib.md5` → `hashlib.sha256` |
- **Verification gate** — every patch must parse, satisfy an AST assertion proving
  the specific fix is present, and (when Semgrep is installed) survive a re-scan.
  Anything short of a `verified_fix` is *not* turned into a PR.
- **`missing_auth_decorator` is report-only** — a missing auth gate is surfaced for
  a human, but never auto-injected (auto-injecting an auth decorator cannot know
  which decorator is correct or whether a route is intentionally public).
- **Drift detection** — snapshot a repo's security state and detect regressions
  over time.

## Installation

```bash
pip install aion-evolve
# or
uv tool install aion-evolve
```

For local development:

```bash
git clone https://github.com/shenxianpeng/aion.git
cd aion
uv sync --group dev --group docs
uv run aion --help
```

## Quick start

### Scan and explain (LLM)

`scan` uses an LLM provider for explanations. Set at least one key:

```bash
export OPENAI_API_KEY=your_key      # or ANTHROPIC_API_KEY / DEEPSEEK_API_KEY /
                                    #    QWEN_API_KEY / GEMINI_API_KEY
aion scan ./path/to/repo --output json
```

### Plan and verify a single deterministic repair (no LLM needed)

```bash
aion repair ./path/to/file.py \
  --context-file ./context.json \
  --artifact-path ./artifact.json

aion verify --artifact-path ./artifact.json
```

### Auto-update: scan → verify → open PRs

```bash
aion auto-update --target ./ --dry-run   # preview, no PRs
aion auto-update --target ./             # live: opens PRs for verified fixes
```

## GitHub Action

AION ships as a reusable GitHub Action:

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
          # or: deepseek_api_key / qwen_api_key / anthropic_api_key / gemini_api_key
```

## Configuration

AION reads a flat `.aion.yaml` (CLI flags override it):

```yaml
provider: openai
model: gpt-4.1
ignore_paths:
  - tests/*
  - scripts/generated_*.py
auto_repair_issue_types:
  - raw_sqlite_query
  - hardcoded_secret
  - insecure_yaml_load
  - command_injection
auto_repair_min_confidence: 0.90
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

### Supported LLM providers

| Provider | Env Variable | Default Model |
|---|---|---|
| Anthropic | `ANTHROPIC_API_KEY` | `claude-3-5-sonnet-latest` |
| OpenAI | `OPENAI_API_KEY` | `gpt-4.1` |
| DeepSeek | `DEEPSEEK_API_KEY` | `deepseek-chat` |
| Qwen (Tongyi) | `QWEN_API_KEY` | `qwen-plus` |
| Gemini | `GEMINI_API_KEY` | `gemini-2.0-flash` |
| Azure OpenAI | `AZURE_OPENAI_API_KEY` | `gpt-4` |

## Command surface

| Command | Purpose |
|---|---|
| `aion scan` | Scan a repo and explain findings (LLM) |
| `aion repair` | Plan a deterministic patch for one file |
| `aion verify` | Verify a patch artifact (syntax + assertions + Semgrep) |
| `aion auto-update` | Scan → verify → open PRs for verified fixes |
| `aion snapshot` | Save a point-in-time security snapshot |
| `aion drift` | Compare current state against a snapshot |
| `aion watch` | Continuously watch for drift and auto-repair regressions |
| `aion status` | Show snapshot and repair-knowledge-base health |

## Scope (what AION does *not* do)

- It produces patch artifacts and pull requests. It does **not** hot-patch live
  production code, and it is **not** a runtime control plane.
- It is **Python-only** by design.
- It fixes a deliberately small set of high-confidence issue types. Breadth is a
  non-goal; trustworthiness is the goal.

## Documentation

Published at [shenxianpeng.github.io/aion](https://shenxianpeng.github.io/aion/)
([中文](https://shenxianpeng.github.io/aion/zh/)).
