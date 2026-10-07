"""
observer/graph_store.py

SQLite-backed storage for traffic graph edges, plus JSON export
for inter-module consumption.

Schema and behavior per Architecture.md §9.1.3.
"""

import sqlite3
import json
import os
import logging
from datetime import datetime

logger = logging.getLogger(__name__)

DB_PATH = os.path.join(os.path.dirname(__file__), "traffic.db")
OUTPUT_DIR = os.path.join(os.path.dirname(__file__), "output")
OUTPUT_FILE = os.path.join(OUTPUT_DIR, "traffic_graph.json")


def _get_connection(db_path: str = DB_PATH) -> sqlite3.Connection:
    """Get a SQLite connection, creating the table if needed."""
    conn = sqlite3.connect(db_path)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS traffic_edges (
            window_start TEXT NOT NULL,
            window_end TEXT NOT NULL,
            source_workload TEXT NOT NULL,
            destination_workload TEXT NOT NULL,
            method TEXT NOT NULL,
            response_code TEXT NOT NULL,
            request_count INTEGER NOT NULL,
            last_seen TEXT NOT NULL
        )
    """)
    conn.commit()
    return conn


def store_edges(window_start: str, window_end: str, edges: list[dict],
                db_path: str = DB_PATH) -> None:
    """
    Append edges to the SQLite traffic_edges table.

    Each edge dict must have keys: source_workload, destination_workload,
    method, response_code, request_count, last_seen.
    """
    conn = _get_connection(db_path)
    try:
        for edge in edges:
            conn.execute(
                """
                INSERT INTO traffic_edges
                    (window_start, window_end, source_workload, destination_workload,
                     method, response_code, request_count, last_seen)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    window_start,
                    window_end,
                    edge["source_workload"],
                    edge["destination_workload"],
                    edge["method"],
                    edge["response_code"],
                    edge["request_count"],
                    edge["last_seen"],
                ),
            )
        conn.commit()
        logger.info("Stored %d edges for window %s -> %s", len(edges), window_start, window_end)
    finally:
        conn.close()


def write_traffic_graph_json(window_start: str, window_end: str,
                             edges: list[dict],
                             output_file: str = OUTPUT_FILE) -> None:
    """
    Write the latest window's traffic graph to JSON file for other modules
    to consume directly, per §8.1 schema.

    Empty edges list is valid (no traffic in window) — writes edges: [].
    """
    os.makedirs(os.path.dirname(output_file), exist_ok=True)

    graph = {
        "window_start": window_start,
        "window_end": window_end,
        "edges": edges,
    }

    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(graph, f, indent=2)

    logger.info("Wrote traffic_graph.json with %d edges", len(edges))
