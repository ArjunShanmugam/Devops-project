"""
inferencer/infer_policy.py

Module 2 — Policy Inferencer for the Zero-Trust Policy Synthesis Engine.

Reads traffic edges from observer/traffic.db, filters noisy edges, looks up
Kubernetes ServiceAccounts, and emits Istio AuthorizationPolicy YAMLs to
inferred_policy/<service>.yaml plus a summary JSON.

Usage:
    python inferencer/infer_policy.py [--dry-run]
"""
import sys
import os
import json
import sqlite3
import argparse
import logging
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Tuple, Optional

# ---------------------------------------------------------------------------
# Ensure project root is on sys.path so shared/ imports work
# ---------------------------------------------------------------------------
_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

import yaml  # pyyaml

from inferencer.thresholds import MIN_REQUEST_COUNT, MAX_STALENESS_WINDOWS

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
log = logging.getLogger("inferencer.infer_policy")

# ---------------------------------------------------------------------------
# Constants / paths
# ---------------------------------------------------------------------------
DB_PATH = _ROOT / "observer" / "traffic.db"
OUTPUT_DIR = _ROOT / "inferred_policy"
SUMMARY_PATH = OUTPUT_DIR / "summary.json"
K8S_NAMESPACE = os.environ.get("K8S_NAMESPACE", "default")

# ---------------------------------------------------------------------------
# Step 1 — Read traffic edges from SQLite
# ---------------------------------------------------------------------------

def _get_last_n_window_ends(cursor: sqlite3.Cursor, n: int) -> List[str]:
    """Return the N most recent distinct window_end timestamps."""
    cursor.execute(
        "SELECT DISTINCT window_end FROM traffic_edges ORDER BY window_end DESC LIMIT ?",
        (n,),
    )
    return [row[0] for row in cursor.fetchall()]


def load_traffic_edges(db_path: Path, max_windows: int = MAX_STALENESS_WINDOWS) -> List[dict]:
    """
    Load edges from the last *max_windows* observation windows.

    Returns a list of dicts with keys:
        source_workload, destination_workload, method, response_code,
        request_count, window_end
    """
    if not db_path.exists():
        log.error("SQLite DB not found at %s", db_path)
        return []

    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    try:
        cur = conn.cursor()
        window_ends = _get_last_n_window_ends(cur, max_windows)
        if not window_ends:
            log.warning("No traffic windows found in DB.")
            return []

        log.info(
            "Using %d window(s): %s … %s",
            len(window_ends),
            window_ends[-1],
            window_ends[0],
        )

        placeholders = ",".join("?" * len(window_ends))
        cur.execute(
            f"""
            SELECT source_workload, destination_workload, method,
                   response_code, request_count, window_end
            FROM traffic_edges
            WHERE window_end IN ({placeholders})
            """,
            window_ends,
        )
        return [dict(row) for row in cur.fetchall()]
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Step 2 — Filter and aggregate edges
# ---------------------------------------------------------------------------

def aggregate_edges(
    edges: List[dict],
    min_request_count: int = MIN_REQUEST_COUNT,
) -> Dict[Tuple[str, str, str], int]:
    """
    Group by (source_workload, destination_workload, method), sum request_count.
    Return only groups meeting the min_request_count threshold.
    """
    aggregated: Dict[Tuple[str, str, str], int] = defaultdict(int)
    for edge in edges:
        key = (
            edge["source_workload"],
            edge["destination_workload"],
            edge["method"],
        )
        aggregated[key] += edge["request_count"]

    filtered = {k: v for k, v in aggregated.items() if v >= min_request_count}
    log.info(
        "Aggregated %d edge groups; %d survive threshold (min=%d).",
        len(aggregated),
        len(filtered),
        min_request_count,
    )
    return filtered


# ---------------------------------------------------------------------------
# Step 3 — Kubernetes ServiceAccount lookup (with fallback)
# ---------------------------------------------------------------------------

def _fallback_sa(workload: str) -> str:
    """Derive a SA name from workload name when K8s is unavailable."""
    return f"{workload}-sa"


def _lookup_sa_k8s(workload: str, namespace: str) -> Optional[str]:
    """
    Query the K8s API for the ServiceAccount name of the first pod
    with label app=<workload> in <namespace>.

    Returns None on any failure so the caller can fall back gracefully.
    """
    try:
        from kubernetes import client, config  # type: ignore

        try:
            config.load_incluster_config()
        except Exception:
            config.load_kube_config()

        v1 = client.CoreV1Api()
        pods = v1.list_namespaced_pod(
            namespace=namespace,
            label_selector=f"app={workload}",
        )
        if pods.items:
            sa = pods.items[0].spec.service_account_name
            log.debug("K8s SA for %s: %s", workload, sa)
            return sa
        log.debug("No pods found for workload=%s in ns=%s", workload, namespace)
        return None
    except Exception as exc:  # noqa: BLE001
        log.debug("K8s lookup failed for %s: %s", workload, exc)
        return None


def resolve_service_accounts(
    workloads: List[str],
    namespace: str = K8S_NAMESPACE,
) -> Dict[str, str]:
    """
    Map each source workload → principal string.

    Falls back to <workload>-sa when K8s is unreachable.
    """
    sa_map: Dict[str, str] = {}
    for wl in workloads:
        sa = _lookup_sa_k8s(wl, namespace)
        if sa is None:
            sa = _fallback_sa(wl)
            log.info("Fallback SA for %s → %s", wl, sa)
        principal = f"cluster.local/ns/{namespace}/sa/{sa}"
        sa_map[wl] = principal
    return sa_map


# ---------------------------------------------------------------------------
# Step 4 — Build per-destination policy data structures
# ---------------------------------------------------------------------------

def build_policy_map(
    filtered_edges: Dict[Tuple[str, str, str], int],
    sa_map: Dict[str, str],
) -> Dict[str, Dict[str, List[str]]]:
    """
    Returns:
        {
          destination_workload: {
            principal: [method, ...],
            ...
          }
        }
    """
    policy: Dict[str, Dict[str, List[str]]] = defaultdict(lambda: defaultdict(list))
    for (src, dst, method), _count in filtered_edges.items():
        principal = sa_map.get(src, f"cluster.local/ns/{K8S_NAMESPACE}/sa/{_fallback_sa(src)}")
        if method not in policy[dst][principal]:
            policy[dst][principal].append(method)
    return policy


# ---------------------------------------------------------------------------
# Step 5 — Emit Istio AuthorizationPolicy YAML
# ---------------------------------------------------------------------------

def build_authz_yaml(
    service: str,
    namespace: str,
    principal_methods: Dict[str, List[str]],
) -> str:
    """
    Build an Istio AuthorizationPolicy YAML document for *service*.

    One `rules` entry per unique source principal; methods are grouped.
    """
    rules = []
    for principal, methods in sorted(principal_methods.items()):
        rules.append(
            {
                "from": [{"source": {"principals": [principal]}}],
                "to": [{"operation": {"methods": sorted(methods)}}],
            }
        )

    doc = {
        "apiVersion": "security.istio.io/v1",
        "kind": "AuthorizationPolicy",
        "metadata": {
            "name": f"{service}-policy",
            "namespace": namespace,
        },
        "spec": {
            "selector": {"matchLabels": {"app": service}},
            "action": "ALLOW",
            "rules": rules,
        },
    }
    return yaml.dump(doc, default_flow_style=False, sort_keys=False)


def emit_policies(
    policy_map: Dict[str, Dict[str, List[str]]],
    output_dir: Path,
    namespace: str = K8S_NAMESPACE,
    dry_run: bool = False,
) -> List[dict]:
    """
    Write one YAML per destination workload.

    Returns a list of summary dicts for the JSON summary.
    """
    summary_records: List[dict] = []

    for service, principal_methods in sorted(policy_map.items()):
        yaml_text = build_authz_yaml(service, namespace, principal_methods)
        dest_file = output_dir / f"{service}.yaml"

        if dry_run:
            print(f"\n# --- DRY RUN: {dest_file} ---")
            print(yaml_text)
        else:
            output_dir.mkdir(parents=True, exist_ok=True)
            dest_file.write_text(yaml_text, encoding="utf-8")
            log.info("Wrote %s", dest_file)

        rules = [
            {"source_principal": p, "methods": sorted(m)}
            for p, m in sorted(principal_methods.items())
        ]
        summary_records.append(
            {
                "service": service,
                "namespace": namespace,
                "policy_file": str(dest_file),
                "principals": list(principal_methods.keys()),
                "rule_count": len(principal_methods),
                "rules": rules,
            }
        )

    return summary_records


def save_summary(
    summary_records: List[dict],
    summary_path: Path,
    dry_run: bool = False,
) -> None:
    payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "total_policies": len(summary_records),
        "policies": summary_records,
    }
    if dry_run:
        print("\n# --- DRY RUN: summary.json ---")
        print(json.dumps(payload, indent=2))
    else:
        summary_path.parent.mkdir(parents=True, exist_ok=True)
        summary_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        log.info("Wrote summary → %s", summary_path)


# ---------------------------------------------------------------------------
# Step 6 — Print summary table
# ---------------------------------------------------------------------------

def print_summary_table(summary_records: List[dict]) -> None:
    if not summary_records:
        print("\nNo policies inferred.")
        return

    try:
        from tabulate import tabulate  # type: ignore

        rows = [
            [
                r["service"],
                r["namespace"],
                r["rule_count"],
                ", ".join(r["principals"]),
            ]
            for r in summary_records
        ]
        print(
            "\n"
            + tabulate(
                rows,
                headers=["Service", "Namespace", "Rules", "Principals"],
                tablefmt="github",
            )
        )
    except ImportError:
        # Fallback plain-text table
        print(f"\n{'Service':<30} {'Namespace':<12} {'Rules':>5}  Principals")
        print("-" * 80)
        for r in summary_records:
            print(
                f"{r['service']:<30} {r['namespace']:<12} {r['rule_count']:>5}  "
                + ", ".join(r["principals"])
            )
    print(f"\nTotal policies inferred: {len(summary_records)}")


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def infer_policies(
    db_path: Path | str = DB_PATH,
    output_dir: Path | str = OUTPUT_DIR,
    namespace: str = K8S_NAMESPACE,
    dry_run: bool = False,
) -> List[dict]:
    """
    Callable interface for tests and external runners.
    """
    db = Path(db_path)
    out = Path(output_dir)
    max_staleness = int(os.environ.get("MAX_STALENESS_WINDOWS", MAX_STALENESS_WINDOWS))
    min_count = int(os.environ.get("MIN_REQUEST_COUNT", MIN_REQUEST_COUNT))

    edges = load_traffic_edges(db, max_staleness)
    filtered = aggregate_edges(edges, min_count)

    if not filtered:
        return []

    source_workloads = list({src for src, _dst, _method in filtered})
    sa_map = resolve_service_accounts(source_workloads, namespace)
    policy_map = build_policy_map(filtered, sa_map)

    summary_records = emit_policies(policy_map, out, namespace, dry_run)
    save_summary(summary_records, out / "summary.json", dry_run)

    result = []
    for service, pmap in policy_map.items():
        rules = []
        for principal, methods in pmap.items():
            rules.append({"source_principal": principal, "methods": sorted(methods)})
        result.append({"service": service, "namespace": namespace, "rules": rules})

    return result


def run(dry_run: bool = False) -> List[dict]:
    """
    Execute the full inferencer pipeline.

    Returns the list of summary records (useful for unit tests and pipeline
    orchestrators that import this module directly).
    """
    log.info(
        "Starting inferencer  MIN_REQUEST_COUNT=%d  MAX_STALENESS_WINDOWS=%d",
        MIN_REQUEST_COUNT,
        MAX_STALENESS_WINDOWS,
    )

    # 1. Load edges
    edges = load_traffic_edges(DB_PATH, MAX_STALENESS_WINDOWS)

    # 2. Aggregate and filter
    filtered = aggregate_edges(edges, MIN_REQUEST_COUNT)

    if not filtered:
        log.warning("No edges survived filtering — no policies will be emitted.")
        print_summary_table([])
        return []

    # 3. Resolve ServiceAccounts
    source_workloads = list({src for src, _dst, _method in filtered})
    sa_map = resolve_service_accounts(source_workloads, K8S_NAMESPACE)

    # 4. Build policy map
    policy_map = build_policy_map(filtered, sa_map)

    # 5. Emit YAMLs
    summary_records = emit_policies(policy_map, OUTPUT_DIR, K8S_NAMESPACE, dry_run)

    # 6. Save summary JSON
    save_summary(summary_records, SUMMARY_PATH, dry_run)

    # 7. Print table
    print_summary_table(summary_records)

    return summary_records


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Infer Istio AuthorizationPolicy YAMLs from observed traffic."
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print policies to stdout without writing files.",
    )
    args = parser.parse_args()
    run(dry_run=args.dry_run)


if __name__ == "__main__":
    main()
