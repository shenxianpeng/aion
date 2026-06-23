# How It Works

AION runs one pipeline: **scan → detect → repair → verify → ship**. Everything
else (drift detection, the watch loop) reuses the same detection and repair core.

## 1. Build repository context

Before deciding whether something is risky, AION extracts a lightweight
repository profile:

- imports and dominant framework usage
- authentication decorators (only genuinely auth-like ones)
- database access patterns
- function names
- probable ORM and HTTP client conventions

That context lets AION ground findings in how *your* code is written instead of
only generic rule hits.

## 2. Detect incidents

Detection combines:

- `semgrep --config p/python` when Semgrep is installed
- repository-specific fallback heuristics
- optional LLM explanation for context-sensitive findings

Actionable results are promoted into incidents with severity, confidence,
evidence, a remediation strategy, and a verification strategy.

## 3. Generate deterministic patch artifacts

For supported issue types, AION generates a deterministic patch instead of
mutating the repository in place. Each artifact carries the original content,
patched content, a unified diff, the applied plans, and a static-validation flag.

Supported deterministic fixes:

| Issue type | Fix |
|---|---|
| `hardcoded_secret` | move the literal to `os.getenv(...)` |
| `raw_sqlite_query` | parameterize the `cursor.execute` call |
| `insecure_yaml_load` | `yaml.load` → `yaml.safe_load` |
| `command_injection` | wrap `os.system` f-string vars in `shlex.quote` |
| `subprocess_shell_injection` | wrap `subprocess(... shell=True)` vars in `shlex.quote` |
| `eval_injection` | `eval(...)` → `ast.literal_eval(...)` |
| `weak_cryptography` | `hashlib.md5` → `hashlib.sha256` |

`missing_auth_decorator` is detected but **report-only** — it is surfaced for a
human and never auto-patched.

## 4. Verify

Every patch must clear an independent verification gate before it is allowed to
become a pull request:

- **Syntax** — the patched content must parse as Python.
- **Assertion** — an AST check confirms the *specific* fix is actually present
  (e.g. the `cursor.execute` call is now parameterized, the secret is now an
  `os.getenv` lookup). This is independent of the regex that produced the patch.
- **Semgrep re-scan** — when Semgrep is installed, the patched file must come
  back clean.

The verdict is one of `verified_fix`, `unsafe_patch`, or `needs_human_review`.
Only `verified_fix` proceeds to a pull request.

## 5. Ship

`auto-update` opens a pull request for each verified fix, applying the labels,
reviewers, assignees, and target branch from `.aion.yaml`, and respects
`open_pull_requests_limit`. Anything that is not a verified fix is left for human
review rather than committed.

Each PR body includes a **plain-language explanation** — the risk the code
carried, what the fix changes, and whether it affects runtime behavior — so a
reviewer can merge with confidence quickly. The same explanation is printed by
`aion repair` for local runs.

## 6. Drift detection and the watch loop

The same detection/repair core powers continuous monitoring.

### Drift detection

`aion snapshot` captures a security fingerprint (file hashes + incidents + health
score) at a point in time. `aion drift` compares the live state against that
baseline to identify regressions and compute a health delta.

| State | Default location |
|---|---|
| Snapshots | `.aion/snapshots/` |

The health score is a 0.0–1.0 metric: 1.0 means no known incidents; lower values
reflect incident severity and count relative to repository size.

### Knowledge base

Every repair records its outcome (success/failure per issue type and strategy) in
`.aion/knowledge/patterns.json`. `aion status` surfaces this history. It is an
audit trail of how repairs have performed over time.

### Watch mode

`aion watch` runs the outer loop: poll → detect drift → auto-repair verified
fixes → record → refresh baseline.

## 7. Boundaries

AION produces patch artifacts and pull requests. It does not hot-patch live
production code, integrate with WAF/gateway/feature-flag/deploy systems, or
process runtime event streams. It is Python-only by design.
