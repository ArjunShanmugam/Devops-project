"""
observer/collect.py
Compatibility wrapper exposing unified functions for collector, prometheus_client, and graph_store.
"""
import os
import sqlite3
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import List, Dict, Any, Optional

from observer.prometheus_client import query_traffic as _raw_query_traffic
from observer.graph_store import (
    _get_connection,
    store_edges as _raw_store_edges,
    write_traffic_graph_json as _raw_write_traffic_graph_json,
    DB_PATH as DEFAULT_DB_PATH,
    OUTPUT_FILE as DEFAULT_OUTPUT_FILE,
)
from shared.config import PROMETHEUS_URL, POLL_INTERVAL_SECONDS


def init_db(db_path: str = DEFAULT_DB_PATH) -> sqlite3.Connection:
    """Initialize SQLite database and return connection."""
    return _get_connection(db_path)


def query_traffic(prometheus_url: str = PROMETHEUS_URL,
                  window_start: Optional[datetime] = None,
                  window_end: Optional[datetime] = None) -> List[Dict[str, Any]]:
    """Query Prometheus for traffic in time window."""
    now = datetime.now(timezone.utc)
    if window_end is None:
        window_end = now
    if window_start is None:
        window_start = now - timedelta(seconds=POLL_INTERVAL_SECONDS)
    return _raw_query_traffic(prometheus_url, window_start, window_end)


def store_edges(conn_or_start, edges=None, window_start=None, window_end=None, db_path=None):
    """
    Store edges into database. Handles both signatures:
    store_edges(conn, edges, window_start, window_end)
    and
    store_edges(window_start, window_end, edges, db_path)
    """
    if isinstance(conn_or_start, sqlite3.Connection):
        conn = conn_or_start
        for edge in (edges or []):
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
                    edge.get("method") or edge.get("request_protocol", "GET"),
                    str(edge.get("response_code", "200")),
                    int(edge.get("request_count", 0)),
                    edge.get("last_seen", window_end),
                ),
            )
        conn.commit()
    else:
        w_start = str(conn_or_start)
        w_end = str(edges)
        actual_edges = window_start or []
        _raw_store_edges(w_start, w_end, actual_edges, db_path or DEFAULT_DB_PATH)


def write_traffic_graph(*args, **kwargs) -> None:
    """
    Write traffic graph JSON. Supports multiple calling conventions:
    write_traffic_graph(edges, window_start, window_end, output_path)
    or
    write_traffic_graph(edges, output_path=..., window_start=..., window_end=...)
    """
    now = datetime.now(timezone.utc).isoformat()
    edges = []
    window_start = now
    window_end = now
    output_path = DEFAULT_OUTPUT_FILE

    if len(args) == 4:
        edges, window_start, window_end, output_path = args
    elif len(args) == 3:
        edges, window_start, window_end = args
    elif len(args) == 2:
        edges, output_path = args
    elif len(args) == 1:
        edges = args[0]

    if "output_path" in kwargs:
        output_path = kwargs["output_path"]
    if "window_start" in kwargs:
        window_start = kwargs["window_start"]
    if "window_end" in kwargs:
        window_end = kwargs["window_end"]

    dir_name = os.path.dirname(str(output_path))
    if dir_name:
        os.makedirs(dir_name, exist_ok=True)

    _raw_write_traffic_graph_json(
        window_start or now,
        window_end or now,
        edges,
        output_path,
    )


def collection_cycle(conn_or_none=None, output_path: str = DEFAULT_OUTPUT_FILE) -> None:
    """Run single collection cycle."""
    from observer.collector import run_collection_cycle
    run_collection_cycle()
