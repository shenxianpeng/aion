# AION

**Code Once, Live Forever.**

AION is The Self-Evolving Code Engine — designed to end technical debt and keep your codebase in a perpetual state of health.

Instead of treating every file in isolation, it builds a lightweight profile of the
existing repository, uses `semgrep` as a fast first pass, and only asks the LLM to
investigate files that have concrete risk signals or meaningful context gaps.

## Why this exists

AI-generated code often looks locally reasonable while drifting away from project
conventions in ways that increase security risk:

- Raw `sqlite3` usage in a codebase that otherwise standardizes on ORM sessions
- Missing auth decorators in handlers that should follow an established access pattern
- Hardcoded secrets where the rest of the repository loads credentials from the environment

AION is designed to catch that mismatch between a generated file and the
rest of the repository.

## Core capabilities

- Scans Python files and repositories from the command line
- Detects AI-generated files via markers, Git history, or explicit targeting
- Extracts repository context using static analysis
- Runs `semgrep --config p/python` as a fast rule-based pass
- Uses an LLM to explain security findings in repository context
- Reports context gaps, fixes, and JSON output for automation

## Read next

- [Installation](installation.md)
- [Usage](usage.md)
- [Configuration](configuration.md)
- [How It Works](how-it-works.md)
