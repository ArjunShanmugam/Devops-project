"""
gitops/open_pr.py
Compatibility wrapper for opening PRs via GitHub.
"""
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))

try:
    from github import Github, GithubException
except ImportError:
    Github = None
    GithubException = Exception


def _build_pr_body(findings: list[dict[str, Any]], generated_at: str) -> str:
    high = [f for f in findings if str(f.get("severity", "")).upper() == "HIGH"]
    medium = [f for f in findings if str(f.get("severity", "")).upper() in ("MEDIUM", "LOW")]

    lines = [
        "## Policy Sync Proposal",
        "",
        f"Generated: {generated_at}",
        "",
    ]

    if high:
        lines.append("### HIGH Severity (Breakage Risk)")
        for f in high:
            lines.append(f"- **{f.get('service')}**: {f.get('detail')} (action: {f.get('suggested_action')})")
        lines.append("")

    if medium:
        lines.append("### MEDIUM Severity (Stale Access)")
        for f in medium:
            lines.append(f"- **{f.get('service')}**: {f.get('detail')} (action: {f.get('suggested_action')})")
        lines.append("")

    lines.extend([
        "Review each change against the linked traffic evidence before merging.",
        "This PR was generated automatically from observed mesh traffic — it does not account for intent, only behavior.",
    ])
    return "\n".join(lines)


def open_pr(patch_proposal: dict[str, Any]) -> Optional[str]:
    """
    Open a pull request from a patch proposal dictionary.
    Returns the PR URL or None if skipped.
    """
    token = os.environ.get("GITHUB_TOKEN", "").strip()
    repo_name = os.environ.get("POLICY_REPO_NAME", "").strip()

    if not token:
        raise ValueError("GITHUB_TOKEN environment variable is not set.")
    if not repo_name:
        raise ValueError("POLICY_REPO_NAME environment variable is not set.")

    findings = patch_proposal.get("findings", [])
    if not findings:
        return None

    now = datetime.now(timezone.utc)
    branch_name = f"policy-sync-{now.strftime('%Y%m%d-%H%M%S')}"
    generated_at = patch_proposal.get("generated_at", now.isoformat())

    gh = Github(token)
    repo = gh.get_repo(repo_name)

    base_branch = getattr(repo, "default_branch", "main") or "main"
    base_sha = None
    try:
        base_ref = repo.get_git_ref(f"heads/{base_branch}")
        base_sha = base_ref.object.sha
    except Exception:
        try:
            branch = repo.get_branch(base_branch)
            base_sha = branch.commit.sha
        except Exception:
            base_sha = "0000000000000000000000000000000000000000"

    try:
        repo.create_git_ref(ref=f"refs/heads/{branch_name}", sha=base_sha)
    except Exception:
        pass

    pr_body = _build_pr_body(findings, generated_at)
    pr_title = f"Policy sync {branch_name}"

    pr = repo.create_pull(
        base=base_branch,
        head=branch_name,
        title=pr_title,
        body=pr_body,
    )
    return getattr(pr, "html_url", f"https://github.com/{repo_name}/pull/1")
