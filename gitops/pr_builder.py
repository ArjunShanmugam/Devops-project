"""
gitops/pr_builder.py
Module 5 — GitOps PR Delivery for the Zero-Trust Policy Synthesis Engine.

Workflow
--------
1. Load patch_proposal.json produced by Module 4 (Diff Engine).
2. If there are no findings → log "no drift detected" and exit 0 without
   creating a PR.
3. Create a new dated branch off ``main`` in the GitHub repository named by
   the POLICY_REPO_NAME environment variable.
4. For every finding:
   - ``add_rule``    → commit the full inferred_policy/<service>.yaml to
                        authz-policies/<service>.yaml in the branch.
   - ``remove_rule`` → read the existing authz-policies/<service>.yaml from
                        the repo, strip the matching rule, commit the result.
5. Build a PR description grouped by severity (High first, then Medium).
6. Open the PR. The system **never** auto-merges; a human must review and merge.

Standalone usage
----------------
    python gitops/pr_builder.py

Environment variables
---------------------
GITHUB_TOKEN      GitHub personal-access token (repo scope required).
POLICY_REPO_NAME  Full repository name, e.g. ``yourorg/zt-policy-repo``.
"""

from __future__ import annotations

import json
import logging
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Ensure the project root is on sys.path so sibling packages are importable
# when running this file directly.
# ---------------------------------------------------------------------------
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))

import yaml  # PyYAML
from github import GithubException, RateLimitExceededException

from gitops.github_client import (
    create_policy_branch,
    get_github_repo,
    update_or_create_file,
)

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%SZ",
)
log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# File-system paths (relative to project root)
# ---------------------------------------------------------------------------
PATCH_PROPOSAL_PATH = _PROJECT_ROOT / "patch_proposal.json"
INFERRED_POLICY_DIR = _PROJECT_ROOT / "inferred_policy"

# Path template inside the GitHub repo
AUTHZ_POLICY_REPO_PATH = "authz-policies/{service}.yaml"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _load_patch_proposal(path: Path) -> dict[str, Any]:
    """Read and parse patch_proposal.json."""
    if not path.exists():
        log.error("patch_proposal.json not found at %s", path)
        sys.exit(1)
    with path.open() as fh:
        return json.load(fh)


def _load_inferred_policy(service: str) -> str | None:
    """Return the raw YAML text for *service*, or None if the file is absent."""
    candidate = INFERRED_POLICY_DIR / f"{service}.yaml"
    if not candidate.exists():
        log.warning("Inferred policy file not found: %s", candidate)
        return None
    return candidate.read_text(encoding="utf-8")


def _remove_rule_from_yaml(existing_yaml: str, source_principal: str, methods: list[str]) -> str:
    """Return *existing_yaml* with the matching rule removed.

    The matching rule is identified by its ``source.principals`` list
    containing *source_principal* **and** ``when``/``to.operation.methods``
    overlapping *methods*.  If no rule matches, the YAML is returned
    unchanged (idempotent).
    """
    doc = yaml.safe_load(existing_yaml)
    rules: list[dict] = (
        doc.get("spec", {}).get("rules", [])
    )
    methods_set = set(m.upper() for m in methods)

    def _matches(rule: dict) -> bool:
        # Check source principals
        for src in rule.get("from", []):
            principals = src.get("source", {}).get("principals", [])
            if any(source_principal in p for p in principals):
                # Check methods
                for to in rule.get("to", []):
                    ops_methods = set(
                        m.upper()
                        for m in to.get("operation", {}).get("methods", [])
                    )
                    if ops_methods & methods_set:
                        return True
        return False

    filtered = [r for r in rules if not _matches(r)]
    if len(filtered) == len(rules):
        log.warning(
            "No matching rule found for removal: principal=%s methods=%s",
            source_principal,
            methods,
        )
    if doc.get("spec") is not None:
        doc["spec"]["rules"] = filtered
    return yaml.dump(doc, default_flow_style=False, allow_unicode=True)


def _build_pr_description(findings: list[dict], generated_at: str) -> str:
    """Compose the PR body from *findings* grouped by severity."""
    high = [f for f in findings if f.get("severity", "").lower() == "high"]
    medium = [f for f in findings if f.get("severity", "").lower() == "medium"]

    lines: list[str] = [
        "## Policy Sync Proposal",
        "",
        f"Generated: {generated_at}",
        "",
    ]

    def _bullet(finding: dict) -> str:
        svc = finding.get("service", "unknown")
        detail = finding.get("detail", "")
        return f"- **{svc}**: {detail}"

    if high:
        lines.append("### High severity (breakage risk)")
        lines.extend(_bullet(f) for f in high)
        lines.append("")

    if medium:
        lines.append("### Medium severity (stale access)")
        lines.extend(_bullet(f) for f in medium)
        lines.append("")

    lines.append(
        "Review each change against the linked traffic evidence before merging. "
        "This PR was generated automatically from observed mesh traffic — it does "
        "not account for intent, only behavior."
    )
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def run_gitops_pr(
    patch_proposal_path: Path = PATCH_PROPOSAL_PATH,
    inferred_policy_dir: Path = INFERRED_POLICY_DIR,
    base_branch: str = "main",
) -> None:
    """End-to-end GitOps PR delivery.

    Raises:
        SystemExit: On unrecoverable errors (missing env vars, no patch file,
            GitHub rate-limit exceeded).
    """
    # ------------------------------------------------------------------
    # 1. Validate required environment variables
    # ------------------------------------------------------------------
    token = os.environ.get("GITHUB_TOKEN", "")
    repo_name = os.environ.get("POLICY_REPO_NAME", "")

    if not token:
        print(
            "ERROR: GITHUB_TOKEN environment variable is not set.\n"
            "       Export your GitHub personal access token before running:\n"
            "         export GITHUB_TOKEN=ghp_...",
            file=sys.stderr,
        )
        sys.exit(1)

    if not repo_name:
        print(
            "ERROR: POLICY_REPO_NAME environment variable is not set.\n"
            "       Set it to the full repo name, e.g.:\n"
            "         export POLICY_REPO_NAME=yourorg/zt-policy-repo",
            file=sys.stderr,
        )
        sys.exit(1)

    # ------------------------------------------------------------------
    # 2. Load patch proposal
    # ------------------------------------------------------------------
    proposal = _load_patch_proposal(patch_proposal_path)
    findings: list[dict] = proposal.get("findings", [])
    generated_at: str = proposal.get("generated_at", datetime.now(tz=timezone.utc).isoformat())

    # ------------------------------------------------------------------
    # 3. Early exit when there is nothing to do
    # ------------------------------------------------------------------
    if not findings:
        log.info("No drift detected — no PR will be created.")
        sys.exit(0)

    log.info("Loaded %d finding(s) from patch_proposal.json", len(findings))

    # ------------------------------------------------------------------
    # 4. Authenticate and obtain the target repository
    # ------------------------------------------------------------------
    try:
        log.info("Authenticating with GitHub for repo '%s' ...", repo_name)
        repo = get_github_repo(token, repo_name)
    except GithubException as exc:
        log.error("GitHub authentication / repo lookup failed: %s", exc)
        sys.exit(1)

    # ------------------------------------------------------------------
    # 5. Create the policy-sync branch
    # ------------------------------------------------------------------
    try:
        print(f"Creating branch off '{base_branch}' ...")
        branch_name = create_policy_branch(repo, base_branch=base_branch)
        log.info("Branch created: %s", branch_name)
    except RateLimitExceededException:
        log.error("GitHub rate limit exceeded. Try again later.")
        sys.exit(1)
    except GithubException as exc:
        log.error("Failed to create branch: %s", exc)
        sys.exit(1)

    # ------------------------------------------------------------------
    # 6. Commit policy files for each finding
    # ------------------------------------------------------------------
    committed_services: set[str] = set()

    for finding in findings:
        service: str = finding.get("service", "")
        action: str = finding.get("suggested_action", "")
        source_principal: str = finding.get("source_principal", "")
        methods: list[str] = finding.get("methods", [])
        repo_file_path = AUTHZ_POLICY_REPO_PATH.format(service=service)

        if service in committed_services:
            # We already committed the latest state for this service;
            # skip to avoid overwriting a compound update.
            continue

        try:
            if action == "add_rule":
                yaml_content = _load_inferred_policy(service)
                if yaml_content is None:
                    log.warning(
                        "Skipping add_rule for '%s': inferred policy file missing.",
                        service,
                    )
                    continue
                print(f"Committing {service}.yaml (add_rule) ...")
                update_or_create_file(
                    repo=repo,
                    file_path=repo_file_path,
                    content=yaml_content,
                    commit_msg=f"policy-sync: add rules for {service}",
                    branch=branch_name,
                )

            elif action == "remove_rule":
                # Fetch the current file from the repo and surgically remove
                # the stale rule before committing the patched version.
                try:
                    existing_content_obj = repo.get_contents(repo_file_path, ref=branch_name)
                    import base64 as _b64
                    existing_yaml = _b64.b64decode(
                        existing_content_obj.content  # type: ignore[union-attr]
                    ).decode("utf-8")
                except GithubException as exc:
                    if exc.status == 404:
                        log.warning(
                            "Cannot remove rule from '%s': file not in repo. Skipping.",
                            repo_file_path,
                        )
                        continue
                    raise

                updated_yaml = _remove_rule_from_yaml(existing_yaml, source_principal, methods)
                print(f"Committing {service}.yaml (remove_rule) ...")
                update_or_create_file(
                    repo=repo,
                    file_path=repo_file_path,
                    content=updated_yaml,
                    commit_msg=f"policy-sync: remove stale rule for {service}",
                    branch=branch_name,
                )

            else:
                log.warning(
                    "Unknown suggested_action '%s' for service '%s' — skipping.",
                    action,
                    service,
                )
                continue

            committed_services.add(service)

        except RateLimitExceededException:
            log.error("GitHub rate limit exceeded while committing '%s'. Stopping.", service)
            sys.exit(1)
        except GithubException as exc:
            log.error("Failed to commit '%s': %s", service, exc)
            # Continue so other services are not blocked by one failure.

    if not committed_services:
        log.error("No files were committed — aborting PR creation.")
        sys.exit(1)

    # ------------------------------------------------------------------
    # 7. Build PR description
    # ------------------------------------------------------------------
    pr_body = _build_pr_description(findings, generated_at)
    pr_title = f"Policy sync {branch_name}"

    # ------------------------------------------------------------------
    # 8. Open the Pull Request
    # ------------------------------------------------------------------
    try:
        print(f"Opening PR: '{pr_title}' ...")
        pr = repo.create_pull(
            title=pr_title,
            body=pr_body,
            head=branch_name,
            base=base_branch,
        )
        log.info("PR opened: %s", pr.html_url)
        print(f"\nPR created successfully: {pr.html_url}")
        print("⚠️  Human review required — this PR will NOT be auto-merged.")
    except RateLimitExceededException:
        log.error("GitHub rate limit exceeded while opening PR.")
        sys.exit(1)
    except GithubException as exc:
        log.error("Failed to open PR: %s", exc)
        sys.exit(1)


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    run_gitops_pr()
