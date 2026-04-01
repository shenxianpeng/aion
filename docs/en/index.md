# AION Overview

AION is an autonomous code-immunity system for Python services. It starts with
context-aware security scanning and extends into deterministic remediation,
sandbox verification, event orchestration, staged release control, and
runtime-first containment planning.

## Current release

| Area | What is implemented |
|---|---|
| Detection | Repository context extraction, Semgrep triage, fallback heuristics, optional LLM explanation |
| Repair | Deterministic patch artifacts for raw SQLite interpolation, hardcoded secrets, and missing auth decorators |
| Verification | Syntax checks, Semgrep re-scan, built-in assertions, staged project commands |
| Control plane | JSON event ingestion, persistent inbox, queue processing, webhook ingress |
| Rollout | Release candidate creation, approval, phased advancement, rejection, rollback |
| Defense | Runtime containment planning for gateway, WAF, feature flags, dependency actions, and code follow-up |

## Operating model

1. Scan a repository or ingest an event.
2. Convert findings into structured incidents.
3. Generate a patch artifact instead of mutating the live repository.
4. Stage the patch inside a sandbox and verify it.
5. Persist the result as an inbox item, orchestration record, or release candidate.
6. Produce rollout and runtime-defense recommendations.

## What AION is for

- Reviewing AI-generated or newly introduced Python changes against repository conventions
- Building a local control plane for autonomous repair experiments
- Testing policy-gated remediation before integrating real production adapters
- Capturing auditable repair, verification, and rollout state as JSON artifacts

## What AION does not do yet

- Hot-patch production code in place
- Push directly to deployment systems, WAF providers, or feature flag services
- Support non-Python languages in the current release

## Continue reading

- [Installation](installation.md)
- [Usage](usage.md)
- [Configuration](configuration.md)
- [How It Works](how-it-works.md)
