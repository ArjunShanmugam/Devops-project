"""
observer/collector.py

Main collector loop for Module 1 — Traffic Observation Pipeline.
Runs on a fixed interval (default 60s), queries Prometheus for the last
window's traffic, stores results in SQLite, and writes traffic_graph.json.

Behavior per Architecture.md §9.1.3 and §9.1.4.
"""

import sys
import os
import time
import logging
from datetime import datetime, timezone, timedelta

# Add project root to path so shared/ is importable
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from shared.config import PROMETHEUS_URL, POLL_INTERVAL_SECONDS
from observer.prometheus_client import query_traffic
from observer.graph_store import store_edges, write_traffic_graph_json

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)


def print_edge_table(edges: list[dict]) -> None:
    """Print a human-readable table of edges for faculty demo visibility."""
    if not edges:
        print("\n  (no traffic edges in this window)\n")
        return

    header = f"{'Source':<20} {'Destination':<20} {'Method':<8} {'Code':<6} {'Count':<8} {'Last Seen'}"
    print(f"\n  {header}")
    print(f"  {'-' * len(header)}")
    for e in edges:
        print(
            f"  {e['source_workload']:<20} "
            f"{e['destination_workload']:<20} "
            f"{e['method']:<8} "
            f"{e['response_code']:<6} "
            f"{e['request_count']:<8} "
            f"{e['last_seen']}"
        )
    print()


def run_collection_cycle() -> None:
    """Execute a single collection cycle."""
    now = datetime.now(timezone.utc)
    window_end = now
    window_start = now - timedelta(seconds=POLL_INTERVAL_SECONDS)

    window_start_str = window_start.isoformat()
    window_end_str = window_end.isoformat()

    logger.info(
        "Collecting traffic for window %s -> %s",
        window_start_str,
        window_end_str,
    )

    try:
        edges = query_traffic(PROMETHEUS_URL, window_start, window_end)
    except Exception as e:
        # §9.1.4: Prometheus unreachable — log failure, skip this cycle, retry next interval
        logger.error("Failed to query Prometheus, skipping this cycle: %s", e)
        return

    # §9.1.4: Empty result set is valid — write empty edges: [], not an error
    # §9.1.3: Store in SQLite
    store_edges(window_start_str, window_end_str, edges)

    # §9.1.3: Write latest window to traffic_graph.json
    write_traffic_graph_json(window_start_str, window_end_str, edges)

    # Print table for faculty demo
    print_edge_table(edges)


def main() -> None:
    """Main collector loop — runs on POLL_INTERVAL_SECONDS interval."""
    logger.info(
        "Starting traffic observer collector (interval=%ds, prometheus=%s)",
        POLL_INTERVAL_SECONDS,
        PROMETHEUS_URL,
    )

    while True:
        run_collection_cycle()
        logger.info("Sleeping %ds until next collection cycle...", POLL_INTERVAL_SECONDS)
        time.sleep(POLL_INTERVAL_SECONDS)


if __name__ == "__main__":
    main()
