"""
gitops/github_client.py
Low-level GitHub helpers for the GitOps PR Delivery module (Module 5).

Responsibilities:
- Authenticate with the GitHub API via PyGithub
- Create a dated policy-sync branch (with collision retry)
- Update or create a file in a branch
"""

from __future__ import annotations

import base64
import random
import string
from datetime import datetime, timezone
from typing import Optional

import github
from github import Github, GithubException
from github.Repository import Repository


# ---------------------------------------------------------------------------
# Authentication
# ---------------------------------------------------------------------------

def get_github_repo(token: str, repo_name: str) -> Repository:
    """Authenticate with GitHub and return the target repository.

    Args:
        token:     Personal access token (or fine-grained PAT) with repo scope.
        repo_name: Full repo name, e.g. ``"yourorg/zt-policy-repo"``.

    Returns:
        A :class:`github.Repository.Repository` object ready for API calls.

    Raises:
        github.GithubException: If authentication or repo lookup fails.
        ValueError: If *token* or *repo_name* is empty.
    """
    if not token:
        raise ValueError("GitHub token must not be empty.")
    if not repo_name:
        raise ValueError("Policy repo name must not be empty.")

    g = Github(token)
    repo = g.get_repo(repo_name)
    return repo


# ---------------------------------------------------------------------------
# Branch management
# ---------------------------------------------------------------------------

def _random_suffix(length: int = 6) -> str:
    """Return a short alphanumeric suffix for branch-name collision avoidance."""
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=length))


def create_policy_branch(repo: Repository, base_branch: str = "main") -> str:
    """Create a new ``policy-sync-<date>-<time>`` branch off *base_branch*.

    If the branch already exists (highly unlikely but possible in rapid CI),
    a random 6-character suffix is appended and the creation is retried once.

    Args:
        repo:        Authenticated repository object.
        base_branch: Branch to branch off (default ``"main"``).

    Returns:
        The name of the newly created branch.

    Raises:
        github.GithubException: If branch creation fails for a reason other
            than the branch already existing.
    """
    now = datetime.now(tz=timezone.utc)
    branch_name = f"policy-sync-{now.strftime('%Y%m%d-%H%M%S')}"

    source_sha = repo.get_branch(base_branch).commit.sha

    def _try_create(name: str) -> None:
        repo.create_git_ref(ref=f"refs/heads/{name}", sha=source_sha)

    try:
        _try_create(branch_name)
    except GithubException as exc:
        # 422 Unprocessable Entity → branch already exists
        if exc.status == 422:
            branch_name = f"{branch_name}-{_random_suffix()}"
            _try_create(branch_name)  # propagate if this also fails
        else:
            raise

    return branch_name


# ---------------------------------------------------------------------------
# File operations
# ---------------------------------------------------------------------------

def update_or_create_file(
    repo: Repository,
    file_path: str,
    content: str,
    commit_msg: str,
    branch: str,
) -> None:
    """Update an existing file or create it if it does not yet exist.

    Args:
        repo:       Authenticated repository object.
        file_path:  Path inside the repo (e.g. ``"authz-policies/svc-b.yaml"``).
        content:    UTF-8 string content to write.
        commit_msg: Commit message.
        branch:     Target branch name (must already exist).

    Raises:
        github.GithubException: On any GitHub API error.
    """
    encoded = content.encode("utf-8")

    try:
        existing = repo.get_contents(file_path, ref=branch)
        # File exists — update it
        repo.update_file(
            path=file_path,
            message=commit_msg,
            content=encoded,
            sha=existing.sha,  # type: ignore[union-attr]
            branch=branch,
        )
    except GithubException as exc:
        if exc.status == 404:
            # File does not exist — create it
            repo.create_file(
                path=file_path,
                message=commit_msg,
                content=encoded,
                branch=branch,
            )
        else:
            raise
