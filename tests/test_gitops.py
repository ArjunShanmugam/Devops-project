"""
tests/test_gitops.py
Unit tests for Module 5 – GitOps PR (gitops/open_pr.py)
"""
import os
import re
import sys
import unittest
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


def _empty_patch_proposal():
    return {"generated_at": "2024-01-01T00:00:00Z", "findings": []}


def _patch_proposal_with_findings(*findings):
    return {"generated_at": "2024-01-01T00:00:00Z", "findings": list(findings)}


def _finding(ftype, severity, service, detail="test detail",
             source_principal="sa/test", methods=None):
    return {
        "type": ftype,
        "severity": severity,
        "service": service,
        "detail": detail,
        "source_principal": source_principal,
        "methods": methods or ["GET"],
        "suggested_action": "add_rule" if ftype == "under_permissive" else "remove_rule",
    }


class TestGitOps(unittest.TestCase):

    # ------------------------------------------------------------------
    # test_no_findings_skips_pr
    # ------------------------------------------------------------------
    @patch.dict(os.environ, {"GITHUB_TOKEN": "fake-token",
                              "POLICY_REPO_NAME": "org/repo"})
    def test_no_findings_skips_pr(self):
        """Empty patch_proposal → no PR created, function returns None."""
        with patch("github.Github") as mock_gh:
            from gitops.open_pr import open_pr  # noqa: PLC0415

            result = open_pr(_empty_patch_proposal())

        self.assertIsNone(result, "open_pr should return None when there are no findings")
        mock_gh.return_value.get_repo.return_value.create_pull.assert_not_called()

    # ------------------------------------------------------------------
    # test_branch_name_format
    # ------------------------------------------------------------------
    @patch.dict(os.environ, {"GITHUB_TOKEN": "fake-token",
                              "POLICY_REPO_NAME": "org/repo"})
    def test_branch_name_format(self):
        """Branch name must match pattern policy-sync-YYYYMMDD-HHMMSS."""
        branch_names_seen = []

        def capture_branch(base, head, title, body):
            branch_names_seen.append(head)
            pr_mock = MagicMock()
            pr_mock.html_url = "https://github.com/org/repo/pull/1"
            return pr_mock

        mock_repo = MagicMock()
        mock_repo.create_pull.side_effect = capture_branch
        mock_repo.get_branch.side_effect = Exception("branch not found")
        mock_repo.default_branch = "main"
        mock_repo.get_git_ref.side_effect = Exception("not found")

        with patch("github.Github") as mock_gh:
            mock_gh.return_value.get_repo.return_value = mock_repo
            mock_repo.create_git_ref = MagicMock()

            from gitops import open_pr as op_module  # noqa: PLC0415
            import importlib
            importlib.reload(op_module)

            proposal = _patch_proposal_with_findings(
                _finding("under_permissive", "HIGH", "svc-b")
            )
            try:
                op_module.open_pr(proposal)
            except Exception:
                pass  # We only care about what branch name was attempted

        pattern = re.compile(r"^policy-sync-\d{8}-\d{6}$")
        self.assertTrue(
            len(branch_names_seen) > 0,
            "No branch name captured; open_pr may not have attempted to create a PR",
        )
        for name in branch_names_seen:
            self.assertRegex(
                name, pattern,
                f"Branch name '{name}' does not match policy-sync-YYYYMMDD-HHMMSS",
            )

    # ------------------------------------------------------------------
    # test_pr_description_format
    # ------------------------------------------------------------------
    @patch.dict(os.environ, {"GITHUB_TOKEN": "fake-token",
                              "POLICY_REPO_NAME": "org/repo"})
    def test_pr_description_format(self):
        """PR body must contain '## Policy Sync Proposal' header."""
        bodies_seen = []

        def capture_pr(base, head, title, body):
            bodies_seen.append(body)
            pr_mock = MagicMock()
            pr_mock.html_url = "https://github.com/org/repo/pull/1"
            return pr_mock

        mock_repo = MagicMock()
        mock_repo.create_pull.side_effect = capture_pr
        mock_repo.default_branch = "main"
        mock_repo.create_git_ref = MagicMock()

        with patch("github.Github") as mock_gh:
            mock_gh.return_value.get_repo.return_value = mock_repo

            from gitops import open_pr as op_module  # noqa: PLC0415
            import importlib
            importlib.reload(op_module)

            proposal = _patch_proposal_with_findings(
                _finding("over_permissive", "MEDIUM", "svc-b")
            )
            try:
                op_module.open_pr(proposal)
            except Exception:
                pass

        self.assertTrue(len(bodies_seen) > 0, "No PR body captured")
        for body in bodies_seen:
            self.assertIn(
                "## Policy Sync Proposal", body,
                "PR body must contain '## Policy Sync Proposal' header",
            )

    # ------------------------------------------------------------------
    # test_pr_description_groups_by_severity
    # ------------------------------------------------------------------
    @patch.dict(os.environ, {"GITHUB_TOKEN": "fake-token",
                              "POLICY_REPO_NAME": "org/repo"})
    def test_pr_description_groups_by_severity(self):
        """HIGH findings must appear before MEDIUM findings in PR body."""
        bodies_seen = []

        def capture_pr(base, head, title, body):
            bodies_seen.append(body)
            pr_mock = MagicMock()
            pr_mock.html_url = "https://github.com/org/repo/pull/1"
            return pr_mock

        mock_repo = MagicMock()
        mock_repo.create_pull.side_effect = capture_pr
        mock_repo.default_branch = "main"
        mock_repo.create_git_ref = MagicMock()

        with patch("github.Github") as mock_gh:
            mock_gh.return_value.get_repo.return_value = mock_repo

            from gitops import open_pr as op_module  # noqa: PLC0415
            import importlib
            importlib.reload(op_module)

            proposal = _patch_proposal_with_findings(
                _finding("over_permissive", "MEDIUM", "svc-b",
                         detail="medium finding"),
                _finding("under_permissive", "HIGH", "svc-c",
                         detail="high finding"),
            )
            try:
                op_module.open_pr(proposal)
            except Exception:
                pass

        self.assertTrue(len(bodies_seen) > 0, "No PR body captured")
        for body in bodies_seen:
            high_pos = body.find("HIGH")
            medium_pos = body.find("MEDIUM")
            if high_pos == -1 or medium_pos == -1:
                # At minimum, both severities must appear
                self.assertIn("HIGH", body)
                self.assertIn("MEDIUM", body)
            else:
                self.assertLess(
                    high_pos, medium_pos,
                    "HIGH findings must appear before MEDIUM in PR body",
                )

    # ------------------------------------------------------------------
    # test_missing_token_exits
    # ------------------------------------------------------------------
    def test_missing_token_exits(self):
        """Missing GITHUB_TOKEN must raise ValueError or SystemExit."""
        # Remove GITHUB_TOKEN from environment
        env_without_token = {k: v for k, v in os.environ.items()
                             if k != "GITHUB_TOKEN"}
        env_without_token["POLICY_REPO_NAME"] = "org/repo"

        with patch.dict(os.environ, env_without_token, clear=True):
            from gitops import open_pr as op_module  # noqa: PLC0415
            import importlib
            importlib.reload(op_module)

            proposal = _patch_proposal_with_findings(
                _finding("under_permissive", "HIGH", "svc-b")
            )
            with self.assertRaises((ValueError, SystemExit)):
                op_module.open_pr(proposal)


if __name__ == "__main__":
    unittest.main()
