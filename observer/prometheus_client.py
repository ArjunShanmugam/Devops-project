"""
observer/prometheus_client.py

Queries Prometheus for Istio traffic metrics using the exact range query
specified in Architecture.md §9.1.2.
"""

import requests
import logging
from datetime import datetime, timezone

logger = logging.getLogger(__name__)


def query_traffic(prometheus_url: str, window_start: datetime, window_end: datetime) -> list[dict]:
    """
    Query Prometheus range query endpoint for istio_requests_total traffic
    in the given time window.

    Returns a list of edge dicts:
        {
            "source_workload": str,
            "destination_workload": str,
            "method": str,
            "response_code": str,
            "request_count": int,
            "last_seen": str (ISO 8601)
        }
    """
    query = (
        'sum(increase(istio_requests_total{reporter="destination"}[1m])) '
        'by (source_workload, destination_workload, request_method, destination_service, response_code)'
    )

    params = {
        "query": query,
        "time": window_end.timestamp(),
    }

    url = f"{prometheus_url}/api/v1/query"

    try:
        resp = requests.get(url, params=params, timeout=10)
        resp.raise_for_status()
    except requests.RequestException as e:
        logger.error("Prometheus query failed: %s", e)
        raise

    data = resp.json()

    if data.get("status") != "success":
        logger.error("Prometheus returned non-success status: %s", data.get("status"))
        raise RuntimeError(f"Prometheus query failed: {data}")

    results = data.get("data", {}).get("result", [])
    edges = []

    for series in results:
        metric = series.get("metric", {})
        val = series.get("value", [])

        if not val or len(val) < 2:
            continue

        timestamp, val_str = val[0], val[1]
        count = float(val_str)
        if count <= 0:
            continue

        total_count = int(round(count))
        last_seen = (
            datetime.fromtimestamp(timestamp, tz=timezone.utc).isoformat()
            if timestamp
            else window_end.isoformat()
        )

        edges.append({
            "source_workload": metric.get("source_workload", "unknown"),
            "destination_workload": metric.get("destination_workload", "unknown"),
            "method": metric.get("request_method", "unknown"),
            "response_code": metric.get("response_code", "unknown"),
            "request_count": total_count,
            "last_seen": last_seen,
        })

    return edges
