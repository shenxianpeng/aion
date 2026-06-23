"""Plain-language risk and fix explanations for each supported issue type.

A developer who receives an AION pull request should be able to decide whether
to merge it in well under a minute. The diff alone rarely answers the two
questions they actually have:

1. *Why is my current code a risk?*
2. *Why is this specific change safe — does it alter what my program does?*

This module answers both in plain language, keyed by ``issue_type``. The text is
deterministic (no LLM), so it costs nothing to render and never drifts from the
fix that was actually applied.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Explanation:
    """A plain-language explanation of one issue type and its fix."""

    risk: str
    """What an attacker can do, or what goes wrong, if the code is left as-is."""

    fix: str
    """What the patch changes and why it resolves the risk."""

    behavior_note: str
    """Whether/how the fix changes runtime behavior, so reviewers can merge with confidence."""


# Keyed by ``Incident.issue_type``. Every auto-repairable issue type produced by
# ``IncidentDetector`` should have an entry here.
EXPLANATIONS: dict[str, Explanation] = {
    "hardcoded_secret": Explanation(
        risk=(
            "A secret (API key, token, or password) is committed directly in the "
            "source. Anyone with read access to the repository — or to its git "
            "history, forks, or CI logs — can read and reuse it. Rotating a leaked "
            "secret is far more expensive than never committing it."
        ),
        fix=(
            "The literal value is replaced with an `os.getenv(...)` lookup so the "
            "secret is supplied from the environment at runtime instead of living "
            "in the code."
        ),
        behavior_note=(
            "Set the same value as an environment variable before running. Once the "
            "variable is set, behavior is identical to before."
        ),
    ),
    "raw_sqlite_query": Explanation(
        risk=(
            "An SQL statement is built with an f-string, so user-controlled input "
            "is concatenated straight into the query. This is the classic SQL "
            "injection vector — a crafted value can read, modify, or delete data "
            "the query was never meant to touch."
        ),
        fix=(
            "The interpolated value is replaced with a `?` placeholder and passed "
            "as a bound parameter to `cursor.execute(...)`. SQLite then treats it "
            "strictly as data, never as SQL."
        ),
        behavior_note=(
            "Behavior-preserving for well-formed input: the same query runs with the "
            "same value, now passed safely as a parameter."
        ),
    ),
    "insecure_yaml_load": Explanation(
        risk=(
            "`yaml.load()` without a safe loader can construct arbitrary Python "
            "objects during deserialization. Loading an untrusted YAML document can "
            "therefore execute arbitrary code on the host."
        ),
        fix=(
            "`yaml.load(...)` is replaced with `yaml.safe_load(...)`, which only "
            "constructs basic Python types (dicts, lists, strings, numbers) and "
            "cannot instantiate arbitrary objects."
        ),
        behavior_note=(
            "Behavior-preserving for ordinary config/data YAML. Only affects code "
            "that relied on deserializing custom Python object tags — rare, and "
            "unsafe by design."
        ),
    ),
    "command_injection": Explanation(
        risk=(
            "`os.system()` is called with an f-string, so a user-controlled value "
            "is interpolated into a shell command. A value like `; rm -rf /` is "
            "interpreted by the shell, allowing arbitrary command execution."
        ),
        fix=(
            "The interpolated variables are wrapped in `shlex.quote(...)`, which "
            "escapes them so the shell treats each one as a single literal argument "
            "rather than as command syntax."
        ),
        behavior_note=(
            "Behavior-preserving for legitimate input: normal values run the same "
            "command. Only shell-metacharacter payloads are neutralized."
        ),
    ),
    "subprocess_shell_injection": Explanation(
        risk=(
            "A `subprocess` call uses `shell=True` with an f-string, so "
            "user-controlled input is parsed by the shell. As with `os.system`, a "
            "crafted value can inject and execute additional commands."
        ),
        fix=(
            "The interpolated variables are wrapped in `shlex.quote(...)` so they "
            "are passed to the shell as single literal arguments instead of as "
            "command syntax."
        ),
        behavior_note=(
            "Behavior-preserving for legitimate input. Consider dropping "
            "`shell=True` and passing an argument list for an even stronger "
            "guarantee."
        ),
    ),
    "eval_injection": Explanation(
        risk=(
            "`eval()` executes its argument as live Python. If any part of that "
            "argument is user-controlled, an attacker can run arbitrary code inside "
            "your process."
        ),
        fix=(
            "`eval(...)` is replaced with `ast.literal_eval(...)`, which safely "
            "parses only Python literals (numbers, strings, tuples, lists, dicts, "
            "booleans, `None`) and refuses to execute anything else."
        ),
        behavior_note=(
            "Behavior-preserving when the input is a literal data structure. If the "
            "code genuinely needed to evaluate expressions, this will raise instead "
            "— which is the safe outcome and worth a human look."
        ),
    ),
    "weak_cryptography": Explanation(
        risk=(
            "MD5 is cryptographically broken: collisions can be produced cheaply, "
            "so it must not be used for signatures, integrity checks, or anything "
            "security-sensitive."
        ),
        fix=(
            "`hashlib.md5(...)` is replaced with `hashlib.sha256(...)`, a hash "
            "function with no known practical collision attacks."
        ),
        behavior_note=(
            "Changes the produced digest. If MD5 hashes are persisted or compared "
            "against stored values, those will need to be recomputed — review where "
            "the hash is consumed before merging."
        ),
    ),
    "missing_auth_decorator": Explanation(
        risk=(
            "A route handler appears to be missing the repository's usual "
            "authentication decorator, so it may be reachable without auth. This is "
            "surfaced for review only."
        ),
        fix=(
            "AION does not auto-inject auth decorators: it cannot know which "
            "decorator is correct or whether the route is intentionally public. "
            "Add the appropriate decorator yourself, or confirm the route is meant "
            "to be unauthenticated."
        ),
        behavior_note=(
            "No automatic change is made for this issue type."
        ),
    ),
}


def explanation_for(issue_type: str) -> Explanation | None:
    """Return the :class:`Explanation` for ``issue_type``, or ``None`` if unknown."""
    return EXPLANATIONS.get(issue_type)
