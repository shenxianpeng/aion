# Roadmap

AION is intentionally small and focused: scan a Python repository, generate
deterministic patches for a set of high-confidence security issues, verify them,
and open pull requests only for fixes that pass.

## Current status

The project ships:

- context-aware Python scanning with repository profiling and Semgrep triage
- deterministic repair for seven security issue types, each with an AST-level
  verification assertion
- a verification gate (syntax + assertion + optional Semgrep re-scan) that gates
  every pull request
- `auto-update` to scan, verify, and open pull requests for verified fixes
- a reusable GitHub Action
- drift detection (`snapshot` / `drift`), a continuous `watch` loop, and a
  `status` view over snapshots and repair history

## Design principles

- **Trustworthy over broad.** A small set of fixes that are always verified beats
  a large set that sometimes corrupts code.
- **Report, don't guess.** When a fix cannot be proven safe (for example, a
  missing auth decorator), AION reports it for review instead of editing the code.
- **Deterministic and auditable.** Patches are template-based and every one is
  re-checked by an independent AST assertion.

## Possible next steps

These are directions, not commitments. Each should be weighed against the
"trustworthy over broad" principle before being taken on.

- **Reliability transparency** — surface deterministic repair and verification
  pass rates per issue type, and ship golden-path examples that run end-to-end in CI.
- **A few more high-confidence fixes** — additional issue types only where a
  deterministic patch can be verified with the same rigor as the existing seven.
- **Better repository test selection** for verification, beyond a single file's
  AST assertion.
- **Quality signal** — bring back a lightweight repair-quality report
  (success / verification-pass / false-fix rates) over a fixture corpus.

## What is explicitly out of scope

To keep the project controllable, these are non-goals:

- runtime control-plane features (event queues, webhooks, inbox processing)
- staged-rollout / release-candidate management
- runtime containment (WAF, gateway, feature-flag, deploy integrations)
- in-place hot patching of live production code
- non-Python languages
