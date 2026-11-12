"""
tests/test_inferencer.py
Unit tests for Module 2 – Inferencer (inferencer/infer_policy.py)
"""
import os
import sqlite3
import sys
import tempfile
import unittest
from unittest.mock import MagicMock, patch

import yaml

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


def _create_db_with_edges(db_path, edges):
    """Helper: initialise a traffic.db and populate it with given edges."""
    conn = sqlite3.connect(db_path)
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS traffic_edges (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            window_start  TEXT NOT NULL,
            window_end    TEXT NOT NULL,
            source_workload       TEXT NOT NULL,
            destination_workload  TEXT NOT NULL,
            method        TEXT NOT NULL,
            response_code TEXT NOT NULL,
            request_count INTEGER NOT NULL,
            last_seen     TEXT NOT NULL
        )
        """
    )
    conn.executemany(
        """
        INSERT INTO traffic_edges
            (window_start, window_end, source_workload, destination_workload,
             method, response_code, request_count, last_seen)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        edges,
    )
    conn.commit()
    return conn


class TestInferencer(unittest.TestCase):

    def test_min_request_count_filter(self):
        """Edges below MIN_REQUEST_COUNT threshold must be excluded from policy."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = os.path.join(tmpdir, "traffic.db")
            output_dir = os.path.join(tmpdir, "policies")
            os.makedirs(output_dir)

            # Edge with count=2 (below threshold of 5) and one with count=10
            edges = [
                ("2024-01-01T00:00:00Z", "2024-01-01T01:00:00Z",
                 "low-svc", "dest-svc", "GET", "200", 2, "2024-01-01T00:30:00Z"),
                ("2024-01-01T00:00:00Z", "2024-01-01T01:00:00Z",
                 "high-svc", "dest-svc", "GET", "200", 10, "2024-01-01T00:30:00Z"),
            ]
            conn = _create_db_with_edges(db_path, edges)
            conn.close()

            with patch.dict(os.environ, {"MIN_REQUEST_COUNT": "5"}):
                from inferencer.infer_policy import infer_policies  # noqa: PLC0415

                policies = infer_policies(db_path, output_dir)

            # Only high-svc should produce a policy rule
            source_principals = []
            for p in policies:
                for rule in p.get("rules", []):
                    source_principals.append(rule.get("source_principal", ""))
            self.assertFalse(
                any("low-svc" in sp for sp in source_principals),
                "low-svc should be filtered out",
            )
            self.assertTrue(
                any("high-svc" in sp for sp in source_principals),
                "high-svc should be present",
            )

    def test_staleness_filter(self):
        """Edges from windows older than MAX_STALENESS_WINDOWS must be excluded."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = os.path.join(tmpdir, "traffic.db")
            output_dir = os.path.join(tmpdir, "policies")
            os.makedirs(output_dir)

            # Create 5 windows; with MAX_STALENESS_WINDOWS=2, only last 2 matter
            edges = [
                ("2024-01-01T00:00:00Z", "2024-01-01T01:00:00Z",
                 "old-svc", "dest", "GET", "200", 50, "2024-01-01T00:30:00Z"),
                ("2024-01-01T01:00:00Z", "2024-01-01T02:00:00Z",
                 "old-svc", "dest", "GET", "200", 50, "2024-01-01T01:30:00Z"),
                ("2024-01-01T02:00:00Z", "2024-01-01T03:00:00Z",
                 "old-svc", "dest", "GET", "200", 50, "2024-01-01T02:30:00Z"),
                ("2024-01-01T03:00:00Z", "2024-01-01T04:00:00Z",
                 "new-svc", "dest", "GET", "200", 50, "2024-01-01T03:30:00Z"),
                ("2024-01-01T04:00:00Z", "2024-01-01T05:00:00Z",
                 "new-svc", "dest", "GET", "200", 50, "2024-01-01T04:30:00Z"),
            ]
            conn = _create_db_with_edges(db_path, edges)
            conn.close()

            with patch.dict(os.environ, {"MAX_STALENESS_WINDOWS": "2",
                                          "MIN_REQUEST_COUNT": "5"}):
                from inferencer import infer_policy  # noqa: PLC0415
                import importlib
                importlib.reload(infer_policy)
                policies = infer_policy.infer_policies(db_path, output_dir)

            source_principals = []
            for p in policies:
                for rule in p.get("rules", []):
                    source_principals.append(rule.get("source_principal", ""))

            self.assertFalse(
                any("old-svc" in sp for sp in source_principals),
                "old-svc is outside staleness window, should be excluded",
            )

    def test_principal_fallback(self):
        """When K8s is unavailable, service-a maps to service-a-sa as principal."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = os.path.join(tmpdir, "traffic.db")
            output_dir = os.path.join(tmpdir, "policies")
            os.makedirs(output_dir)

            edges = [
                ("2024-01-01T00:00:00Z", "2024-01-01T01:00:00Z",
                 "service-a", "service-b", "GET", "200", 10, "2024-01-01T00:30:00Z"),
            ]
            conn = _create_db_with_edges(db_path, edges)
            conn.close()

            with patch("kubernetes.client.CoreV1Api",
                       side_effect=Exception("K8s not available")), \
                 patch.dict(os.environ, {"MIN_REQUEST_COUNT": "5",
                                          "MAX_STALENESS_WINDOWS": "10"}):
                from inferencer import infer_policy  # noqa: PLC0415
                import importlib
                importlib.reload(infer_policy)
                policies = infer_policy.infer_policies(db_path, output_dir)

            # At least one policy should exist for service-b
            self.assertTrue(len(policies) > 0, "Expected at least one policy")
            all_principals = [
                rule.get("source_principal", "")
                for p in policies
                for rule in p.get("rules", [])
            ]
            # Fallback: principal should contain "service-a-sa" or "service-a"
            self.assertTrue(
                any("service-a" in sp for sp in all_principals),
                f"Expected service-a principal in {all_principals}",
            )

    def test_policy_yaml_schema(self):
        """Output YAML files must have correct apiVersion, kind, namespace fields."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = os.path.join(tmpdir, "traffic.db")
            output_dir = os.path.join(tmpdir, "policies")
            os.makedirs(output_dir)

            edges = [
                ("2024-01-01T00:00:00Z", "2024-01-01T01:00:00Z",
                 "caller", "server", "POST", "200", 20, "2024-01-01T00:30:00Z"),
            ]
            conn = _create_db_with_edges(db_path, edges)
            conn.close()

            with patch.dict(os.environ, {"MIN_REQUEST_COUNT": "5",
                                          "MAX_STALENESS_WINDOWS": "10",
                                          "K8S_NAMESPACE": "default"}):
                from inferencer import infer_policy  # noqa: PLC0415
                import importlib
                importlib.reload(infer_policy)
                infer_policy.infer_policies(db_path, output_dir)

            yaml_files = [f for f in os.listdir(output_dir) if f.endswith(".yaml")]
            self.assertTrue(len(yaml_files) > 0, "Expected at least one YAML file")

            for fname in yaml_files:
                with open(os.path.join(output_dir, fname)) as f:
                    doc = yaml.safe_load(f)
                self.assertIn(doc.get("apiVersion"), ("security.istio.io/v1", "security.istio.io/v1beta1"),
                              f"{fname}: wrong apiVersion")
                self.assertEqual(doc.get("kind"), "AuthorizationPolicy",
                                 f"{fname}: wrong kind")
                self.assertIn("namespace",
                              doc.get("metadata", {}),
                              f"{fname}: missing namespace in metadata")

    def test_no_edges_produces_no_policy(self):
        """Empty SQLite database → no YAML files should be emitted."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = os.path.join(tmpdir, "traffic.db")
            output_dir = os.path.join(tmpdir, "policies")
            os.makedirs(output_dir)

            conn = _create_db_with_edges(db_path, [])
            conn.close()

            with patch.dict(os.environ, {"MIN_REQUEST_COUNT": "5",
                                          "MAX_STALENESS_WINDOWS": "10"}):
                from inferencer import infer_policy  # noqa: PLC0415
                import importlib
                importlib.reload(infer_policy)
                policies = infer_policy.infer_policies(db_path, output_dir)

            yaml_files = [f for f in os.listdir(output_dir) if f.endswith(".yaml")]
            self.assertEqual(yaml_files, [], "No YAML files expected for empty DB")
            self.assertEqual(policies, [], "No policies expected for empty DB")


if __name__ == "__main__":
    unittest.main()
