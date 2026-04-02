# GitHub Copilot Instructions for AION

## Mission

**AION is The Self-Evolving Code Engine. Code Once, Live Forever.**

Every change you make should push the project closer to this goal: autonomous, self-healing Python
services that detect drift, synthesize deterministic repairs, verify them in isolation, and prepare
staged rollout and runtime-containment decisions — with minimal human toil.

---

## Standing Rules

### 1. Keep Documentation in Sync

If a code change affects observable behavior — CLI flags, configuration keys, command output,
module APIs, workflow steps, or architectural decisions — update the relevant documentation in
the same commit or PR.

- English docs live in `docs/en/`.
- Chinese docs live in `docs/zh/`.
- Both language variants must be kept in sync.
- The top-level `README.md` is a quick-reference entry point; update it when command surfaces,
  configuration schemas, or installation steps change.

Do **not** merge a code change that makes existing documentation inaccurate.

### 2. Keep Tests in Sync

Every code change that adds, removes, or alters behavior must be accompanied by a corresponding
test change.

- Unit tests live in `tests/unit/`.
- Eval fixtures live in `tests/fixtures/`.
- Eval tests live in `tests/eval/`.
- Follow the existing test conventions in each directory — use `pytest`, and mirror the module
  structure under `src/aion/` in the test files.
- New public functions and new CLI commands require at least one test.
- Bug fixes require a regression test.

Do **not** leave tests that assert the old behavior when the behavior has intentionally changed.

### 3. Evolve Toward the AION Mission

When suggesting or implementing changes, prefer approaches that:

- Increase autonomy and reduce the need for human intervention.
- Keep the repair/verify/rollout loop deterministic and auditable.
- Make the system more self-explanatory (structured output, clear repair records, explicit
  policy gates).
- Lower the barrier for future extension to additional languages or runtimes.

---

## Project Layout

```
src/aion/          # Main package
tests/unit/        # Unit tests (mirrors src/aion/ structure)
tests/eval/        # Evaluation / integration tests
tests/fixtures/    # Shared fixtures used by tests
docs/en/           # English documentation (MkDocs)
docs/zh/           # Chinese documentation (MkDocs)
.aion.yaml         # Example AION configuration file
```

## Development Commands

```bash
uv sync --group dev --group docs   # install all dependencies
uv run pytest tests/unit           # run unit tests
uv run pytest tests/                # run all tests
uv run aion --help                  # explore the CLI
uv run mkdocs serve                 # preview documentation locally
```
