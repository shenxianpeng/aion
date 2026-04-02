# Goal-Driven Autonomous Remediation System (Master Agent + Subagent)

This prompt defines a **goal-driven multi-agent system** that drives AION's
full scan → repair → verify → release lifecycle autonomously until the
repository reaches a clean security posture.

---

## Goal

> Achieve a **zero critical-incident posture** for the target Python repository
> by using AION to detect all security issues, generate and verify deterministic
> patches for every auto-repairable finding, and produce an approved release
> candidate that is ready to roll out — without any human intervention in the
> remediation loop.

**Target repository:** `{{TARGET_REPO_PATH}}`  
**AION config:** `{{TARGET_REPO_PATH}}/.aion.yaml` (must exist before starting)  
**Artifact directory:** `.aion/` (inbox, patches, repair records, releases)

---

## Criteria for Success

All of the following must be true before the process ends:

| # | Criterion | How to verify |
|---|-----------|---------------|
| 1 | `aion scan` produces **zero `critical` or `high` severity incidents** | Exit code 0 and no `severity: critical/high` entries in the JSON output |
| 2 | Every auto-repairable incident has a **verified patch artifact** | `aion verify --artifact-path <artifact>` exits 0 for every artifact under `.aion/` |
| 3 | A **release candidate exists** at `approved` or `active` status | `aion list-releases` shows at least one entry with `status: approved` or `status: active` |
| 4 | No subagent is in a **failed** or **stalled** state | Master agent heartbeat check passes with all subagents reporting `done` or `idle` |

---

## System Design

```
┌─────────────────────────────────────────┐
│           MASTER AGENT (you)            │
│  - Spawns the Remediation Subagent      │
│  - Evaluates criteria every 5 minutes   │
│  - Restarts stalled subagent if needed  │
│  - Stops only when all criteria are met │
└──────────────────┬──────────────────────┘
                   │ assigns goal
                   ▼
┌─────────────────────────────────────────┐
│       REMEDIATION SUBAGENT              │
│  Phase 1 › Scan                         │
│  Phase 2 › Repair (per incident)        │
│  Phase 3 › Verify (per patch artifact)  │
│  Phase 4 › Release candidate lifecycle  │
│  Reports status back to master agent    │
└─────────────────────────────────────────┘
```

---

## Master Agent Instructions

You are the **master agent**. Your three responsibilities are:

### 1. Spawn the Remediation Subagent

On start, launch one subagent named **`remediation-agent`** and hand it the
goal and all context below. The subagent must work autonomously through all
four phases.

### 2. Evaluate Criteria on Every Status Report

Whenever the subagent reports a phase completion or declares it has finished,
check all four success criteria in the table above. If **all four pass**, stop
the subagent and end the process with a final summary. If any criterion fails,
instruct the subagent to continue from the failed criterion.

### 3. Heartbeat Check Every 5 Minutes

If the subagent has not reported progress for 5 minutes:
1. Re-run the criteria check yourself.
2. If criteria are not met → restart a new `remediation-agent` subagent, pass
   it the current state (latest scan JSON + existing artifacts), and instruct
   it to resume from the last incomplete phase.
3. If criteria are met → stop and emit final summary.

> **Do not stop the agents until the user explicitly requests it OR all
> four success criteria are simultaneously satisfied.**

---

## Remediation Subagent Instructions

You are the **remediation subagent** (`remediation-agent`). Execute the
following phases in order. After each phase, report your status to the master
agent with: phase name, outcome, artifact paths produced, and remaining work.

---

### Phase 1 — Scan

```bash
aion scan {{TARGET_REPO_PATH}} --output json > .aion/scan-result.json
```

- Parse `.aion/scan-result.json`.
- Classify each finding by severity (`critical`, `high`, `medium`, `low`).
- Produce a **phase report** listing total counts per severity and the list of
  auto-repairable issue types (check against `.aion.yaml:auto_repair_issue_types`).
- If zero `critical`/`high` findings → skip to Phase 4 (check existing
  release candidates).
- Otherwise → continue to Phase 2.

---

### Phase 2 — Repair (iterate over each incident)

For every auto-repairable incident in `.aion/scan-result.json`:

```bash
aion repair {{TARGET_REPO_PATH}}/<file> \
  --context-file .aion/scan-result.json \
  --artifact-path .aion/patches/<incident-id>.artifact.json \
  --record-path   .aion/records/<incident-id>.record.json
```

Sub-tasks:
- Process incidents in descending severity order (`critical` first).
- If `aion repair` exits non-zero for an incident, log it as `repair-failed`
  and continue with the remaining incidents. Report all failures to the master
  agent after the loop.
- After all incidents are processed, report: repaired count, failed count, and
  list of artifact paths.

---

### Phase 3 — Verify (iterate over each patch artifact)

For every `.artifact.json` produced in Phase 2:

```bash
aion verify --artifact-path .aion/patches/<incident-id>.artifact.json
```

Sub-tasks:
- If `aion verify` exits non-zero → run `aion repair` again for that incident
  (one retry). If the retry also fails, mark as `verify-failed` and report to
  master agent.
- Only artifacts with exit code 0 are considered **verified**.
- After all artifacts are processed, report: verified count, failed count.
- Proceed to Phase 4 only when zero `critical`/`high` artifacts remain
  unverified.

---

### Phase 4 — Release Candidate Lifecycle

```bash
# Create a release candidate from verified inbox results
aion create-release-candidate .aion/inbox/results/latest.json

# Approve and advance
aion approve-release <candidate-id> --approver aion-agent
aion advance-release <candidate-id>
```

Sub-tasks:
- Run `aion list-releases` to check for any existing candidate that is already
  `approved` or `active` — skip creation if one exists.
- After advancing, run `aion list-releases` and capture the status.
- Report the candidate ID and status to the master agent.

---

### Status Report Format

After each phase, emit a structured status block:

```
[AION-AGENT STATUS]
phase:        <scan|repair|verify|release>
outcome:      <success|partial|failed>
timestamp:    <ISO-8601>
details:
  - <key findings or artifact paths>
  - <counts of resolved / pending / failed incidents>
remaining:    <next phase or "none" if all criteria are met>
```

---

## Pseudocode Reference

```
spawn subagent("remediation-agent", goal, context)

while (success_criteria not all met) {
  wait(5 minutes)

  if (subagent.inactive OR subagent.reports_done) {
    check_all_criteria()

    if (all criteria met) {
      stop_all_subagents()
      emit_final_summary()
      break
    } else {
      restart_subagent("remediation-agent", last_known_state)
    }
  }
}
```

---

## AION Command Quick Reference

| Task | Command |
|------|---------|
| Full scan | `aion scan <repo> --output json` |
| Repair a file | `aion repair <file> --context-file <ctx> --artifact-path <out> --record-path <rec>` |
| Verify a patch | `aion verify --artifact-path <artifact>` |
| Run full incident | `aion run-incident <file> --output json` |
| List inbox | `aion list-inbox` |
| Create release | `aion create-release-candidate <result.json>` |
| List releases | `aion list-releases` |
| Approve release | `aion approve-release <id> --approver <name>` |
| Advance release | `aion advance-release <id>` |
| Rollback release | `aion rollback-release <id>` |
| Plan runtime defense | `aion plan-defense <incident.json>` |

---

## Notes for GitHub Copilot Agent Mode

- This prompt is designed to be used with **GitHub Copilot agent mode** (Workspace or `@workspace` in VS Code).
- Replace `{{TARGET_REPO_PATH}}` with the absolute or relative path to the repository you want AION to harden.
- Copilot will act as the **master agent** and spawn a sequential subagent workflow using the AION CLI.
- All intermediate artifacts are written under `.aion/` — commit this directory if you want audit history.
- To abort at any time: close the Copilot chat session or run `aion rollback-release <id>` to revert.
