"""
tests/test_diff_engine.py
Unit tests for Module 4 – Diff Engine (diff_engine/diff.py)
"""
import json
import os
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


def _make_policy(service, namespace, rules):
    """Return a minimal inferred-policy dict."""
    return {
        "service": service,
        "namespace": namespace,
        "rules": rules,
    }


def _make_rule(source_principal, methods):
    return {"source_principal": source_principal, "methods": methods}


class TestDiffEngine(unittest.TestCase):

    def _run_diff(self, inferred_policies, enforced_policies,
                  output_path=None, stale_rule_age_windows=10):
        """Helper: call diff_engine.diff.compute_diff and return result."""
        from diff_engine.diff import compute_diff  # noqa: PLC0415

        with patch.dict(os.environ,
                        {"STALE_RULE_AGE_WINDOWS": str(stale_rule_age_windows)}):
            import importlib
            import diff_engine.diff as diff_mod
            importlib.reload(diff_mod)
            return diff_mod.compute_diff(inferred_policies, enforced_policies,
                                         output_path)

    # ------------------------------------------------------------------
    # test_over_permissive_detected
    # ------------------------------------------------------------------
    def test_over_permissive_detected(self):
        """Enforced has a rule not in inferred → finding type=over_permissive."""
        inferred = [_make_policy("svc-b", "default", [
            _make_rule("cluster.local/ns/default/sa/svc-a-sa", ["GET"]),
        ])]
        # Enforced has an EXTRA rule for svc-x that inferred doesn't have
        enforced = [_make_policy("svc-b", "default", [
            _make_rule("cluster.local/ns/default/sa/svc-a-sa", ["GET"]),
            _make_rule("cluster.local/ns/default/sa/svc-x-sa", ["DELETE"]),
        ])]

        with tempfile.TemporaryDirectory() as tmpdir:
            out = os.path.join(tmpdir, "patch.json")
            result = self._run_diff(inferred, enforced, out)

        findings = result.get("findings", [])
        over = [f for f in findings if f["type"] == "over_permissive"]
        self.assertTrue(len(over) >= 1, "Expected at least one over_permissive finding")

    # ------------------------------------------------------------------
    # test_under_permissive_detected
    # ------------------------------------------------------------------
    def test_under_permissive_detected(self):
        """Inferred has a rule not in enforced → finding type=under_permissive."""
        inferred = [_make_policy("svc-b", "default", [
            _make_rule("cluster.local/ns/default/sa/svc-a-sa", ["GET"]),
            _make_rule("cluster.local/ns/default/sa/svc-new-sa", ["POST"]),
        ])]
        enforced = [_make_policy("svc-b", "default", [
            _make_rule("cluster.local/ns/default/sa/svc-a-sa", ["GET"]),
        ])]

        with tempfile.TemporaryDirectory() as tmpdir:
            out = os.path.join(tmpdir, "patch.json")
            result = self._run_diff(inferred, enforced, out)

        findings = result.get("findings", [])
        under = [f for f in findings if f["type"] == "under_permissive"]
        self.assertTrue(len(under) >= 1, "Expected at least one under_permissive finding")

    # ------------------------------------------------------------------
    # test_no_drift
    # ------------------------------------------------------------------
    def test_no_drift(self):
        """When inferred == enforced, findings must be empty."""
        policy = _make_policy("svc-b", "default", [
            _make_rule("cluster.local/ns/default/sa/svc-a-sa", ["GET"]),
        ])

        with tempfile.TemporaryDirectory() as tmpdir:
            out = os.path.join(tmpdir, "patch.json")
            result = self._run_diff([policy], [policy], out)

        self.assertEqual(result.get("findings", []), [],
                         "No drift expected when inferred == enforced")

    # ------------------------------------------------------------------
    # test_severity_high_for_under_permissive
    # ------------------------------------------------------------------
    def test_severity_high_for_under_permissive(self):
        """under_permissive findings must always have severity HIGH."""
        inferred = [_make_policy("svc-b", "default", [
            _make_rule("cluster.local/ns/default/sa/svc-new-sa", ["POST"]),
        ])]
        enforced = [_make_policy("svc-b", "default", [])]

        with tempfile.TemporaryDirectory() as tmpdir:
            out = os.path.join(tmpdir, "patch.json")
            result = self._run_diff(inferred, enforced, out)

        under = [f for f in result.get("findings", [])
                 if f["type"] == "under_permissive"]
        self.assertTrue(len(under) >= 1)
        for f in under:
            self.assertEqual(f["severity"].upper(), "HIGH",
                             f"under_permissive must be HIGH, got {f['severity']}")

    # ------------------------------------------------------------------
    # test_severity_escalation_for_stale
    # ------------------------------------------------------------------
    def test_severity_escalation_for_stale(self):
        """over_permissive with stale_windows > STALE_RULE_AGE_WINDOWS → HIGH severity."""
        # Enforced has an extra rule with stale_windows injected via the rule dict
        inferred = [_make_policy("svc-b", "default", [])]
        stale_rule = _make_rule("cluster.local/ns/default/sa/stale-sa", ["GET"])
        stale_rule["stale_windows"] = 15  # > STALE_RULE_AGE_WINDOWS (10)
        enforced = [_make_policy("svc-b", "default", [stale_rule])]

        with tempfile.TemporaryDirectory() as tmpdir:
            out = os.path.join(tmpdir, "patch.json")
            result = self._run_diff(inferred, enforced, out,
                                    stale_rule_age_windows=10)

        over = [f for f in result.get("findings", [])
                if f["type"] == "over_permissive"]
        self.assertTrue(len(over) >= 1, "Expected over_permissive finding")
        stale_findings = [f for f in over
                          if "stale" in f.get("detail", "").lower()
                          or f.get("severity", "").upper() == "HIGH"]
        self.assertTrue(
            len(stale_findings) >= 1,
            "Stale over_permissive rule should escalate to HIGH",
        )

    # ------------------------------------------------------------------
    # test_patch_proposal_json_schema
    # ------------------------------------------------------------------
    def test_patch_proposal_json_schema(self):
        """Output JSON must contain 'generated_at' and 'findings' fields."""
        inferred = [_make_policy("svc-b", "default", [
            _make_rule("cluster.local/ns/default/sa/svc-new-sa", ["POST"]),
        ])]
        enforced = [_make_policy("svc-b", "default", [])]

        with tempfile.TemporaryDirectory() as tmpdir:
            out = os.path.join(tmpdir, "patch.json")
            result = self._run_diff(inferred, enforced, out)

            self.assertIn("generated_at", result,
                          "patch proposal must have 'generated_at'")
            self.assertIn("findings", result,
                          "patch proposal must have 'findings'")

            # Also verify the file was written
            self.assertTrue(os.path.isfile(out), "patch.json file not written")
            with open(out) as f:
                on_disk = json.load(f)
            self.assertIn("generated_at", on_disk)
            self.assertIn("findings", on_disk)


if __name__ == "__main__":
    unittest.main()
