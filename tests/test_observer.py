"""
tests/test_observer.py
Unit tests for Module 1 – Observer (observer/collect.py)
"""
import json
import os
import sqlite3
import sys
import tempfile
import unittest
from unittest.mock import MagicMock, patch

# Ensure project root is on the path so observer can be imported
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


class TestQueryTraffic(unittest.TestCase):
    """Tests for the query_traffic function in observer/collect.py."""

    def _make_response(self, results):
        """Build a minimal Prometheus-style response dict."""
        return {
            "status": "success",
            "data": {
                "resultType": "vector",
                "result": results,
            },
        }

    @patch("requests.get")
    def test_query_traffic_empty(self, mock_get):
        """mock requests.get to return empty result – verify returns []."""
        mock_resp = MagicMock()
        mock_resp.json.return_value = self._make_response([])
        mock_resp.raise_for_status = MagicMock()
        mock_get.return_value = mock_resp

        from observer.collect import query_traffic  # noqa: PLC0415

        edges = query_traffic()
        self.assertEqual(edges, [])

    @patch("requests.get")
    def test_query_traffic_filters_zero_count(self, mock_get):
        """Results with request_count == 0 must be filtered out."""
        raw_results = [
            {
                "metric": {
                    "source_workload": "svc-a",
                    "destination_workload": "svc-b",
                    "request_protocol": "http",
                    "response_code": "200",
                },
                "value": [1699999999, "0"],  # count = 0
            },
            {
                "metric": {
                    "source_workload": "svc-c",
                    "destination_workload": "svc-d",
                    "request_protocol": "http",
                    "response_code": "200",
                },
                "value": [1699999999, "10"],  # count = 10 → kept
            },
        ]
        mock_resp = MagicMock()
        mock_resp.json.return_value = self._make_response(raw_results)
        mock_resp.raise_for_status = MagicMock()
        mock_get.return_value = mock_resp

        from observer.collect import query_traffic  # noqa: PLC0415

        edges = query_traffic()
        self.assertEqual(len(edges), 1)
        self.assertEqual(edges[0]["source_workload"], "svc-c")

    def test_store_edges_and_retrieve(self):
        """Write edges to a temp SQLite DB and verify they are stored correctly."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = os.path.join(tmpdir, "traffic.db")

            from observer.collect import init_db, store_edges  # noqa: PLC0415

            conn = init_db(db_path)

            edges = [
                {
                    "source_workload": "svc-a",
                    "destination_workload": "svc-b",
                    "method": "GET",
                    "response_code": "200",
                    "request_count": 42,
                    "last_seen": "2024-01-01T00:00:00Z",
                }
            ]
            window_start = "2024-01-01T00:00:00Z"
            window_end = "2024-01-01T01:00:00Z"
            store_edges(conn, edges, window_start, window_end)
            conn.commit()

            cur = conn.execute("SELECT * FROM traffic_edges")
            rows = cur.fetchall()
            conn.close()

            self.assertEqual(len(rows), 1)
            row = rows[0]
            # Columns: window_start, window_end, source_workload,
            #          destination_workload, method, response_code,
            #          request_count, last_seen
            col_names = [desc[0] for desc in cur.description]
            row_dict = dict(zip(col_names, row))
            self.assertEqual(row_dict["source_workload"], "svc-a")
            self.assertEqual(row_dict["destination_workload"], "svc-b")
            self.assertEqual(row_dict["request_count"], 42)

    def test_write_traffic_graph_json(self):
        """write_traffic_graph writes JSON that matches the expected schema."""
        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = os.path.join(tmpdir, "traffic_graph.json")

            from observer.collect import write_traffic_graph  # noqa: PLC0415

            edges = [
                {
                    "source_workload": "svc-a",
                    "destination_workload": "svc-b",
                    "method": "POST",
                    "response_code": "201",
                    "request_count": 5,
                    "last_seen": "2024-01-01T00:00:00Z",
                }
            ]
            window_start = "2024-01-01T00:00:00Z"
            window_end = "2024-01-01T01:00:00Z"
            write_traffic_graph(edges, window_start, window_end, output_path)

            with open(output_path) as f:
                data = json.load(f)

            self.assertIn("window_start", data)
            self.assertIn("window_end", data)
            self.assertIn("edges", data)
            self.assertIsInstance(data["edges"], list)
            self.assertEqual(len(data["edges"]), 1)
            self.assertEqual(data["edges"][0]["source_workload"], "svc-a")

    @patch("requests.get", side_effect=ConnectionError("Prometheus unreachable"))
    def test_collection_cycle_prometheus_down(self, mock_get):
        """When Prometheus is unreachable, collection_cycle must not raise."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = os.path.join(tmpdir, "traffic.db")
            output_path = os.path.join(tmpdir, "traffic_graph.json")

            from observer.collect import collection_cycle, init_db  # noqa: PLC0415

            conn = init_db(db_path)
            # Should complete without raising
            try:
                collection_cycle(conn, output_path)
            except Exception as exc:  # pragma: no cover
                self.fail(f"collection_cycle raised unexpectedly: {exc}")
            finally:
                conn.close()


if __name__ == "__main__":
    unittest.main()
