"""
policy_fetcher/fetch_enforced.py

Fetches all Istio AuthorizationPolicy CRDs from the live Kubernetes cluster
and normalizes them into per-service YAML files in enforced_policy/.

Per Architecture.md §9.3

Usage:
    python policy_fetcher/fetch_enforced.py
"""

import sys
import os
import json
import logging
from pathlib import Path
from datetime import datetime, timezone

# Add project root to path so shared/ imports work
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))

import yaml

try:
    from tabulate import tabulate
    _HAS_TABULATE = True
except ImportError:
    _HAS_TABULATE = False

from policy_fetcher.k8s_client import list_authorization_policies

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-8s %(name)s — %(message)s",
)
logger = logging.getLogger(__name__)

ENFORCED_POLICY_DIR = _PROJECT_ROOT / "enforced_policy"


# ---------------------------------------------------------------------------
# Normalization helpers
# ---------------------------------------------------------------------------

def _service_name_from_policy(policy: dict) -> str:
    """
    Derive the service name from an AuthorizationPolicy object.

    Priority:
    1. spec.selector.matchLabels.app  (most explicit)
    2. metadata.name with "-policy" suffix stripped
    """
    spec = policy.get("spec", {})
    match_labels = spec.get("selector", {}).get("matchLabels", {})
    if "app" in match_labels:
        return match_labels["app"]

    name: str = policy.get("metadata", {}).get("name", "unknown")
    if name.endswith("-policy"):
        name = name[: -len("-policy")]
    return name


def _extract_rules(policy: dict) -> list[dict]:
    """
    Extract a list of {source_principal, methods} dicts from an
    AuthorizationPolicy spec.

    Handles multiple rules / multiple from-blocks / multiple to-blocks by
    producing the cross-product within each rule (each from × each to).
    If a rule has no 'from' block it uses principal='*'; if it has no
    'to' block it uses methods=['*'].
    """
    spec = policy.get("spec", {})
    raw_rules: list[dict] = spec.get("rules", [])
    extracted: list[dict] = []

    for rule in raw_rules:
        froms: list[dict] = rule.get("from", [])
        tos: list[dict] = rule.get("to", [])

        # Collect principals
        principals: list[str] = []
        for from_block in froms:
            source = from_block.get("source", {})
            for p in source.get("principals", []):
                if p not in principals:
                    principals.append(p)
        if not principals:
            principals = ["*"]

        # Collect methods
        methods: list[str] = []
        for to_block in tos:
            operation = to_block.get("operation", {})
            for m in operation.get("methods", []):
                if m not in methods:
                    methods.append(m)
        if not methods:
            methods = ["*"]

        # Cross-product: one entry per (principal, methods-list)
        for principal in principals:
            extracted.append(
                {
                    "source_principal": principal,
                    "methods": sorted(methods),
                }
            )

    return extracted


def normalize_policy(policy: dict) -> dict:
    """
    Normalize a raw AuthorizationPolicy into the shared inferred_policy schema:

    service: <name>
    namespace: <namespace>
    generated_at: <ISO-8601>
    rules:
      - source_principal: <str>
        methods: [<str>, ...]
    """
    metadata = policy.get("metadata", {})
    return {
        "service": _service_name_from_policy(policy),
        "namespace": metadata.get("namespace", "default"),
        "generated_at": datetime.now(tz=timezone.utc).isoformat(),
        "rules": _extract_rules(policy),
    }


# ---------------------------------------------------------------------------
# I/O helpers
# ---------------------------------------------------------------------------

def _ensure_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)


def write_service_yaml(normalized: dict, output_dir: Path) -> Path:
    """Write a single per-service YAML file; returns the path written."""
    _ensure_dir(output_dir)
    service = normalized["service"]
    out_path = output_dir / f"{service}.yaml"
    with out_path.open("w", encoding="utf-8") as fh:
        yaml.dump(normalized, fh, default_flow_style=False, sort_keys=False, allow_unicode=True)
    logger.debug("Wrote %s", out_path)
    return out_path


def write_summary_json(entries: list[dict], output_dir: Path) -> Path:
    """
    Write enforced_policy/summary.json.

    Schema:
    {
      "generated_at": "<ISO-8601>",
      "namespace": "<ns>",
      "policies": [
        {
          "service": "<name>",
          "source_principal": "<principal>",
          "methods": ["GET", ...]
        },
        ...
      ]
    }
    """
    _ensure_dir(output_dir)
    flat_policies: list[dict] = []
    for entry in entries:
        for rule in entry.get("rules", []):
            flat_policies.append(
                {
                    "service": entry["service"],
                    "source_principal": rule["source_principal"],
                    "methods": rule["methods"],
                }
            )

    summary = {
        "generated_at": datetime.now(tz=timezone.utc).isoformat(),
        "namespace": entries[0]["namespace"] if entries else "default",
        "policies": flat_policies,
    }
    out_path = output_dir / "summary.json"
    with out_path.open("w", encoding="utf-8") as fh:
        json.dump(summary, fh, indent=2)
    logger.debug("Wrote %s", out_path)
    return out_path


# ---------------------------------------------------------------------------
# Tabular output
# ---------------------------------------------------------------------------

def _print_table(normalized_policies: list[dict]) -> None:
    """Pretty-print a summary table of fetched policies."""
    rows: list[list] = []
    for np in normalized_policies:
        service = np["service"]
        namespace = np["namespace"]
        for rule in np["rules"]:
            rows.append(
                [
                    service,
                    namespace,
                    rule["source_principal"],
                    ", ".join(rule["methods"]),
                ]
            )

    headers = ["Service", "Namespace", "Source Principal", "Methods"]
    if _HAS_TABULATE:
        print(tabulate(rows, headers=headers, tablefmt="github"))
    else:
        # Fallback plain text table
        col_widths = [max(len(h), max((len(str(r[i])) for r in rows), default=0)) for i, h in enumerate(headers)]
        fmt = "  ".join(f"{{:<{w}}}" for w in col_widths)
        print(fmt.format(*headers))
        print("  ".join("-" * w for w in col_widths))
        for row in rows:
            print(fmt.format(*row))


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def fetch_and_write(namespace: str = "default", output_dir: Path = ENFORCED_POLICY_DIR) -> list[dict]:
    """
    Fetch AuthorizationPolicies from K8s, normalize, write YAML + summary.

    Returns the list of normalized policy dicts.
    """
    logger.info("Fetching AuthorizationPolicies from namespace '%s' …", namespace)
    raw_policies = list_authorization_policies(namespace=namespace)

    _ensure_dir(output_dir)

    if not raw_policies:
        print(f"No AuthorizationPolicies found in namespace {namespace}")
        # Still write an empty summary so downstream modules don't fail
        write_summary_json([], output_dir)
        return []

    normalized_policies: list[dict] = []
    for raw in raw_policies:
        norm = normalize_policy(raw)
        write_service_yaml(norm, output_dir)
        normalized_policies.append(norm)
        logger.info("  Normalized policy for service '%s' (%d rule(s))", norm["service"], len(norm["rules"]))

    write_summary_json(normalized_policies, output_dir)
    logger.info("Wrote %d service YAML(s) + summary.json to %s", len(normalized_policies), output_dir)

    _print_table(normalized_policies)
    return normalized_policies


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(
        description="Fetch Istio AuthorizationPolicies and normalize to enforced_policy/."
    )
    parser.add_argument(
        "--namespace",
        default=os.environ.get("K8S_NAMESPACE", "default"),
        help="Kubernetes namespace to query (default: 'default')",
    )
    parser.add_argument(
        "--output-dir",
        default=str(ENFORCED_POLICY_DIR),
        help=f"Output directory for YAML files (default: {ENFORCED_POLICY_DIR})",
    )
    args = parser.parse_args()

    output_dir = Path(args.output_dir)
    fetch_and_write(namespace=args.namespace, output_dir=output_dir)


if __name__ == "__main__":
    main()
