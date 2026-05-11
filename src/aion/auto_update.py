"""Auto-update engine: scans a repository, generates verified fixes, and creates PRs.

Implements the AION auto-update workflow:

1. Load flat configuration from ``.aion.yaml``.
2. Scan the repository for security incidents.
3. Generate deterministic patch artifacts for supported issue types.
4. Verify patches in sandboxes.
5. Create pull requests for verified fixes.
6. Respect ``open_pull_requests_limit`` and label / reviewer / assignee settings.
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from fnmatch import fnmatch

from .config import UpdateConfig, load_update_configs
from .context_extractor import ContextExtractor
from .knowledge_base import KnowledgeBase
from .models import ContextProfile, Incident, PatchArtifact, RepairAttemptRecord
from .repair import IncidentDetector, PatchGenerator, RepairExecutor, Verifier
from .semgrep_runner import SemgrepRunner, semgrep_available


class AutoUpdateResult:
    """Summary of one auto-update run."""

    def __init__(self) -> None:
        self.files_scanned: int = 0
        self.incidents_found: int = 0
        self.patches_generated: int = 0
        self.patches_verified: int = 0
        self.prs_created: int = 0
        self.errors: list[str] = []


class AutoUpdateEngine:
    """Core engine for the auto-update workflow.

    Scans a repository tree, generates verified patches, and creates pull requests.
    """

    def __init__(self, root: Path, update_config: UpdateConfig | None = None) -> None:
        self.root = root.resolve()
        self.config = update_config or (load_update_configs(root)[0] if load_update_configs(root) else UpdateConfig())
        self.kb = KnowledgeBase(base_dir=root / ".aion" / "knowledge")

    def run(self, dry_run: bool = False) -> AutoUpdateResult:
        """Execute the full auto-update pipeline."""
        result = AutoUpdateResult()

        # 1. Extract context
        context = ContextExtractor(root=self.root, extra_ignore_patterns=self.config.ignore_paths).extract()
        result.files_scanned = context.scanned_files

        # 2. Find candidate files
        candidate_files = self._find_python_files()
        if not candidate_files:
            return result

        # 3. Build detector and generator
        semgrep_runner = SemgrepRunner() if semgrep_available() else None
        detector = IncidentDetector(semgrep_runner=semgrep_runner)
        generator = PatchGenerator()
        verifier = Verifier()
        executor = RepairExecutor(detector=detector, generator=generator, verifier=verifier, knowledge_base=self.kb)

        # 4. Process each file: detect → repair → verify
        repair_records: list[RepairAttemptRecord] = []
        for file_path in candidate_files:
            record = executor.run(file_path, context, verify=True)
            if record.incidents:
                result.incidents_found += len(record.incidents)
            if record.artifact is not None:
                result.patches_generated += 1
            if record.verification is not None and record.verification.verdict == "verified_fix":
                result.patches_verified += 1
                repair_records.append(record)

        if not repair_records:
            return result

        # 5. Create PRs for verified fixes
        result.prs_created = self._create_pull_requests(repair_records, context, result, dry_run=dry_run)

        return result

    def _find_python_files(self) -> list[Path]:
        """Find Python files to scan, respecting ignore_paths."""
        excluded_dirs = {
            ".git", ".venv", "venv", "node_modules", "__pycache__",
            ".nox", ".tox", "site-packages", "dist-packages",
        }
        candidates = []
        for path in sorted(self.root.rglob("*.py")):
            if any(part in excluded_dirs for part in path.parts):
                continue
            if self._matches_ignore_pattern(path):
                continue
            candidates.append(path)
        return candidates

    def _matches_ignore_pattern(self, path: Path) -> bool:
        """Check if a path matches any ignore pattern."""
        try:
            relative = path.relative_to(self.root).as_posix()
        except ValueError:
            relative = path.as_posix()
        for pattern in self.config.ignore_paths:
            if fnmatch(relative, pattern) or fnmatch(path.name, pattern):
                return True
        return False

    def _create_pull_requests(
        self,
        records: list[RepairAttemptRecord],
        context: ContextProfile,
        result: AutoUpdateResult,
        dry_run: bool = False,
    ) -> int:
        """Create pull requests for verified repair records.

        Each record becomes a separate branch and PR.
        Respects ``open_pull_requests_limit``.
        """
        limit = max(1, self.config.open_pull_requests_limit)

        # Check existing AION PRs to avoid exceeding the limit
        existing_count = self._count_existing_aion_prs()
        available_slots = max(0, limit - existing_count)
        if available_slots <= 0:
            result.errors.append(
                f"PR limit reached: {existing_count} open AION PRs already exist (limit: {limit})"
            )
            return 0

        created = 0
        for record in records[:available_slots]:
            ok, err = self._create_single_pr(record, context, dry_run=dry_run)
            if ok:
                created += 1
            elif err:
                result.errors.append(err)

        return created

    def _count_existing_aion_prs(self) -> int:
        """Count open PRs created by AION."""
        try:
            result = subprocess.run(
                ["gh", "pr", "list", "--head", "aion/", "--state", "open", "--json", "number"],
                capture_output=True,
                text=True,
                check=False,
            )
            if result.returncode != 0:
                return 0
            data = json.loads(result.stdout)
            return len(data)
        except (OSError, json.JSONDecodeError):
            return 0

    def _create_single_pr(
        self,
        record: RepairAttemptRecord,
        context: ContextProfile,
        dry_run: bool = False,
    ) -> tuple[bool, str | None]:
        """Create a single PR for one repair record.

        Returns (True, None) if the PR was created successfully,
        or (False, error_message) on failure.
        """
        if record.artifact is None:
            return False, "No patch artifact available for this record"

        artifact = record.artifact
        target_path = Path(record.target)

        # Generate a branch name
        branch_name = self._branch_name(artifact)

        # Build PR title and body
        title = self._pr_title(record)
        body = self._pr_body(record, context)

        if dry_run:
            return True, None

        try:
            # Stash any local changes first
            subprocess.run(
                ["git", "-C", str(self.root), "stash", "--include-untracked"],
                capture_output=True, check=False,
            )

            # Create and switch to new branch
            base_branch = self._current_branch() or self.config.target_branch
            checkout_result = subprocess.run(
                ["git", "-C", str(self.root), "checkout", "-b", branch_name, f"origin/{base_branch}"],
                capture_output=True, text=True, check=False,
            )
            if checkout_result.returncode != 0:
                err = checkout_result.stderr.strip() or f"Failed to create branch {branch_name}"
                return False, f"Git checkout failed: {err}"

            # Apply the patch
            target_path.write_text(artifact.patched_content, encoding="utf-8")

            # Stage, commit
            relative_target = self._relative_path(target_path)
            add_result = subprocess.run(
                ["git", "-C", str(self.root), "add", relative_target],
                capture_output=True, text=True, check=False,
            )
            if add_result.returncode != 0:
                return False, f"Git add failed: {add_result.stderr.strip()}"

            commit_message = f"{self.config.commit_message_prefix} fix: {self._commit_summary(record)}"
            commit_result = subprocess.run(
                ["git", "-C", str(self.root), "commit", "-m", commit_message],
                capture_output=True, text=True, check=False,
            )
            if commit_result.returncode != 0:
                err = commit_result.stderr.strip() or "commit failed"
                return False, f"Git commit failed: {err}"

            # Push
            push_result = subprocess.run(
                ["git", "-C", str(self.root), "push", "origin", branch_name, "--force"],
                capture_output=True, text=True, check=False,
            )
            if push_result.returncode != 0:
                # Fallback: try without force
                push_result = subprocess.run(
                    ["git", "-C", str(self.root), "push", "origin", branch_name],
                    capture_output=True, text=True, check=False,
                )
            if push_result.returncode != 0:
                err = push_result.stderr.strip() or "push failed"
                return False, f"Git push failed: {err}"

            # Create PR via gh CLI
            pr_args = [
                "gh", "pr", "create",
                "--repo", self._github_repo(),
                "--head", branch_name,
                "--base", base_branch,
                "--title", title,
                "--body", body,
            ]
            for label in self.config.labels:
                pr_args.extend(["--label", label])
            for reviewer in self.config.reviewers:
                pr_args.extend(["--reviewer", reviewer])
            for assignee in self.config.assignees:
                pr_args.extend(["--assignee", assignee])

            pr_result = subprocess.run(pr_args, capture_output=True, text=True, check=False)

            # Switch back to original branch
            subprocess.run(
                ["git", "-C", str(self.root), "checkout", base_branch],
                capture_output=True, check=False,
            )

            if pr_result.returncode != 0:
                err = pr_result.stderr.strip() or "gh pr create failed"
                return False, f"PR creation failed: {err}"

            return True, None

        except OSError as exc:
            return False, f"OS error during PR creation: {exc}"

    def _branch_name(self, artifact: PatchArtifact) -> str:
        """Generate a unique branch name for the patch."""
        short_hash = hashlib.sha256(
            f"{artifact.target_file}:{artifact.incident_ids}".encode("utf-8")
        ).hexdigest()[:8]
        target_stem = Path(artifact.target_file).stem.replace(" ", "-").lower()
        return f"aion/fix-{target_stem}-{short_hash}"

    def _pr_title(self, record: RepairAttemptRecord) -> str:
        """Generate a PR title."""
        types = sorted({i.issue_type for i in record.incidents})
        type_str = ", ".join(types[:3])
        if len(types) > 3:
            type_str += f" +{len(types) - 3} more"
        return f"{self.config.commit_message_prefix} fix: {type_str} in {Path(record.target).name}"

    def _pr_body(self, record: RepairAttemptRecord, context: ContextProfile) -> str:
        """Generate a PR body with details."""
        artifact = record.artifact
        verification = record.verification

        lines = [
            "## AION Auto-Fix",
            "",
            f"**Target:** `{record.target}`",
            f"**Created:** {record.created_at}",
            "",
            "### Incidents Detected",
            "",
        ]

        for incident in record.incidents:
            lines.append(f"- **{incident.issue_type}** ({incident.severity}) — {incident.issue}")
            lines.append(f"  - Line: {incident.line}, Confidence: {incident.confidence:.0%}")
            lines.append(f"  - Strategy: {incident.remediation_strategy or 'N/A'}")

        if artifact is not None:
            lines.append("")
            lines.append("### Patch Details")
            lines.append("")
            lines.append(f"```diff\n{artifact.diff}\n```")

        if verification is not None:
            lines.append("")
            lines.append("### Verification")
            lines.append(f"- **Verdict:** {verification.verdict}")
            lines.append(f"- **Syntax OK:** {verification.syntax_ok}")
            lines.append(f"- **Semgrep OK:** {verification.semgrep_ok}")
            lines.append(f"- **Assertions OK:** {verification.assertions_ok}")
            if verification.checks:
                for check in verification.checks:
                    lines.append(f"  - {check.name}: {'✓' if check.passed else '✗'} {check.details}")

        lines.append("")
        lines.append("---")
        lines.append("*This PR was automatically created by [AION](https://github.com/shenxianpeng/aion).*")

        return "\n".join(lines)

    def _commit_summary(self, record: RepairAttemptRecord) -> str:
        """Generate a concise commit message summary."""
        types = sorted({i.issue_type for i in record.incidents})
        type_str = ", ".join(types[:3])
        return f"{type_str} in {Path(record.target).name}"

    def _current_branch(self) -> str | None:
        """Get the current git branch."""
        try:
            result = subprocess.run(
                ["git", "-C", str(self.root), "rev-parse", "--abbrev-ref", "HEAD"],
                capture_output=True,
                text=True,
                check=False,
            )
            if result.returncode == 0:
                return result.stdout.strip()
        except OSError:
            pass
        return None

    def _github_repo(self) -> str:
        """Detect the GitHub repository from git remote or GITHUB_REPOSITORY env."""
        repo = os.getenv("GITHUB_REPOSITORY", "")
        if repo:
            return repo
        try:
            result = subprocess.run(
                ["git", "-C", str(self.root), "remote", "get-url", "origin"],
                capture_output=True,
                text=True,
                check=False,
            )
            if result.returncode == 0:
                url = result.stdout.strip()
                # Extract owner/repo from git URL
                if "github.com" in url:
                    parts = url.rstrip(".git").split("github.com")[-1].strip("/:").split("/")
                    if len(parts) >= 2:
                        return f"{parts[-2]}/{parts[-1]}"
        except OSError:
            pass
        return "unknown/unknown"

    def _relative_path(self, path: Path) -> str:
        """Get path relative to repo root."""
        try:
            return path.relative_to(self.root).as_posix()
        except ValueError:
            return path.as_posix()
