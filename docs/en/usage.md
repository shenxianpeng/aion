# Usage

AION has eight commands: `scan`, `repair`, `verify`, `auto-update`, `snapshot`,
`drift`, `watch`, and `status`.

## Prerequisites

- Set at least one LLM provider key (`OPENAI_API_KEY`, `ANTHROPIC_API_KEY`,
  `GEMINI_API_KEY`, `DEEPSEEK_API_KEY`, or `QWEN_API_KEY`) before running `scan`.
  Deterministic `repair` / `verify` / `auto-update` do **not** require an LLM.
- Place `.aion.yaml` in the target repository root for auto-update defaults.
- Use `--output json` when you want machine-readable output.

## 1. Scan a repository

```bash
uv run aion scan ./path/to/project
```

Scan only files you already know are AI-generated:

```bash
uv run aion scan ./path/to/project \
  --ai-generated ./path/to/project/generated_file.py
```

Switch provider or emit JSON:

```bash
uv run aion scan ./path/to/project --provider openai --output json
```

Print extracted context, fallback reasons, and Semgrep detail:

```bash
uv run aion scan ./path/to/project --verbose
```

## 2. Generate and verify a repair artifact

Create a deterministic patch artifact (no LLM required):

```bash
uv run aion repair ./path/to/file.py \
  --context-file ./context.json \
  --artifact-path ./artifact.json \
  --record-path ./repair-record.json
```

Verify an existing artifact — syntax check, an AST assertion that the specific
fix is present, and a Semgrep re-scan when Semgrep is installed:

```bash
uv run aion verify --artifact-path ./artifact.json
```

A patch is only considered a fix when the verdict is `verified_fix`.

## 3. Auto-update: scan → verify → open PRs

Run the full pipeline:

```bash
uv run aion auto-update --target ./
```

Dry-run to inspect what would happen without creating PRs:

```bash
uv run aion auto-update --target ./ --dry-run
```

The `auto-update` command:

1. Reads `.aion.yaml` for provider and PR configuration.
2. Scans all Python files for security incidents.
3. Generates deterministic patches for supported issue types.
4. Verifies each patch in an isolated workspace.
5. Opens a pull request for each **verified** fix.
6. Respects `open_pull_requests_limit` to avoid PR floods.

### GitHub Action

AION ships with a reusable GitHub Action (`action.yml`). Add it to a workflow:

```yaml
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
```

## 4. Supported issue types

`scan` can surface many findings, but only these are turned into deterministic,
verified auto-fixes:

| Issue type | Fix |
|---|---|
| `hardcoded_secret` | move the literal to `os.getenv(...)` |
| `raw_sqlite_query` | parameterize the `cursor.execute` call |
| `insecure_yaml_load` | `yaml.load` → `yaml.safe_load` |
| `command_injection` | wrap `os.system` f-string vars in `shlex.quote` |
| `subprocess_shell_injection` | wrap `subprocess(... shell=True)` vars in `shlex.quote` |
| `eval_injection` | `eval(...)` → `ast.literal_eval(...)` |
| `weak_cryptography` | `hashlib.md5` → `hashlib.sha256` |

`missing_auth_decorator` is **report-only**: a missing auth gate is surfaced for
a human, but never auto-injected, because AION cannot know which decorator is
correct or whether a route is intentionally public.

## 5. Track security drift

### Save a security baseline

```bash
uv run aion snapshot ./src --name baseline
```

This creates `.aion/snapshots/baseline.json` containing a health score, incident
list, and file hashes — a reproducible fingerprint of the repository's security
posture.

### Check for drift

```bash
uv run aion drift ./src --name baseline
```

Exit code `0` means no regression; exit code `1` means new incidents were found.
Use `--output json` for a machine-readable drift report in CI.

### Continuous watch mode

```bash
uv run aion watch ./src --interval 30 --auto-repair
```

AION polls every `--interval` seconds, compares against the last known-good
baseline, and generates and verifies patches for new incidents. When a repair
reaches `verified_fix`, `watch` writes the patched content back to the watched
local file and refreshes the baseline.

### Inspect engine health

```bash
uv run aion status
# or specify a custom .aion directory
uv run aion status --aion-dir ./.aion --output json
```

`status` shows accumulated snapshots and the repair knowledge base (per
issue-type success/failure history recorded by repairs).

## 6. Operational notes

- AION emits patch artifacts and pull requests; `watch` can rewrite watched local
  files after verification. It does not rewrite live production files in place.
- Deterministic `repair`, `verify`, and `auto-update` do not require an LLM; only
  `scan`'s explanations do.
- Drift snapshots and knowledge-base history are persisted under `.aion/` and
  survive restarts.
- Context extraction results are cached at `~/.aion-context.json`.
