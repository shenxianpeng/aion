# Roadmap

This roadmap reflects the current shipped functionality in `main` and the next logical steps for AION.

## Current status

AION already supports:

- Python-focused repository and file scanning
- Repository context extraction via static analysis
- `semgrep --config p/python` as the fast first pass
- Anthropic and OpenAI providers for contextual analysis
- AI-generated file targeting via markers, Git history, or explicit `--ai-generated`
- Rich terminal output and JSON output
- Deterministic remediation planning for selected high-confidence Python issues
- Patch artifact generation through `aion repair`
- Standalone artifact verification through `aion verify`
- A local `scan -> repair -> verify` incident loop through `aion run-incident`

## First autonomy release boundary

The current autonomy release is intentionally conservative.

What it does now:

- detects incidents
- plans deterministic remediation
- generates patch artifacts
- verifies artifacts locally

What it does **not** do yet:

- modify production files in place
- auto-commit or auto-open pull requests
- perform repository-wide autonomous remediation workflows
- support non-Python remediation

## Deterministic repair coverage today

Current built-in deterministic repair paths cover:

- raw sqlite f-string queries
- hardcoded secrets
- missing auth decorators

## Next steps

Planned next milestones:

1. Expand deterministic repair coverage to more Python security and code-quality patterns.
2. Improve artifact verification with stronger policy checks and richer assertions.
3. Add safe review-oriented workflows for exporting or handing off verified patches.
4. Introduce repository-level orchestration beyond single-file incident handling.
5. Explore controlled write-back and automation only after verification and approval boundaries are mature.

## Guiding principle

AION is moving toward self-evolving code, but the current phase prioritizes safety, determinism, and reviewability over aggressive automation.
