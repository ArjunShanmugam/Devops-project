"""
diff_engine/classify.py

Staleness checking and severity classification for drift findings.
Per Architecture.md §8.4 rules:
  - over_permissive → MEDIUM by default; HIGH if stale > STALE_RULE_AGE_WINDOWS
  - under_permissive → always HIGH
"""

import sqlite3
import logging
from typing import Optional

logger = logging.getLogger(__name__)


def check_staleness(
    source_principal: str,
    service: str,
    method: str,
    db_path: str,
    stale_windows: int = 10,
) -> int:
    """
    Count how many of the most-recent `stale_windows` observation windows have
    NO traffic for the edge (source_principal → service, method).

    The source_principal is of the form
    "cluster.local/ns/<ns>/sa/<sa-name>"; we derive the source workload by
    taking the service-account name (last path component) and stripping the
    trailing "-sa" suffix if present.

    Returns:
        int: number of consecutive stale windows (0 = seen in every recent window).
    """
    # Derive a workload name from the principal for the DB lookup.
    sa_name = source_principal.rstrip("/").split("/")[-1]
    source_workload = sa_name[: -len("-sa")] if sa_name.endswith("-sa") else sa_name

    try:
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()

        # Collect the last `stale_windows` distinct window_end values.
        cur.execute(
            """
            SELECT DISTINCT window_end
            FROM traffic_edges
            ORDER BY window_end DESC
            LIMIT ?
            """,
            (stale_windows,),
        )
        windows = [row["window_end"] for row in cur.fetchall()]

        if not windows:
            conn.close()
            return 0

        stale_count = 0
        for window_end in windows:
            cur.execute(
                """
                SELECT COUNT(*) as cnt
                FROM traffic_edges
                WHERE source_workload = ?
                  AND destination_workload = ?
                  AND method = ?
                  AND window_end = ?
                  AND request_count > 0
                """,
                (source_workload, service, method, window_end),
            )
            row = cur.fetchone()
            if row and row["cnt"] > 0:
                # Hit — stop counting consecutive stale windows from the front.
                break
            stale_count += 1

        conn.close()
        return stale_count

    except sqlite3.Error as exc:
        logger.warning("check_staleness DB error (%s): %s", db_path, exc)
        return 0


def classify_severity(
    finding_type: str,
    stale_window_count: int = 0,
    stale_threshold: int = 10,
) -> str:
    """
    Classify drift finding severity.

    Rules:
      - under_permissive → always "high" (broken traffic risk)
      - over_permissive  → "high" if stale_window_count >= stale_threshold,
                           else "medium"

    Args:
        finding_type:       "over_permissive" or "under_permissive"
        stale_window_count: result of check_staleness()
        stale_threshold:    STALE_RULE_AGE_WINDOWS (default 10)

    Returns:
        "high" or "medium"
    """
    if finding_type == "under_permissive":
        return "high"

    if finding_type == "over_permissive":
        if stale_window_count >= stale_threshold:
            return "high"
        return "medium"

    # Unknown type — default to high to be safe.
    logger.warning("Unknown finding type '%s'; defaulting severity to 'high'.", finding_type)
    return "high"
