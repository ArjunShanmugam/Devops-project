"""
diff_engine/diff.py

Diff & Classification Engine — Module 4 of the Zero-Trust Policy Synthesis Engine.

Reads:
  inferred_policy/summary.json   (Module 2 output)
  enforced_policy/summary.json   (Module 3 output)

Writes:
  patch_proposal.json            (§8.4 schema)

Usage:
  python diff_engine/diff.py
"""

import sys
import os
import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Allow running as a standalone script from anywhere inside the project.
# ---------------------------------------------------------------------------
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from diff_engine.classify import check_staleness, classify_severity  # noqa: E402

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
INFERRED_SUMMARY = _PROJECT_ROOT / "inferred_policy" / "summary.json"
ENFORCED_SUMMARY = _PROJECT_ROOT / "enforced_policy" / "summary.json"
PATCH_PROPOSAL   = _PROJECT_ROOT / "patch_proposal.json"
OBSERVER_DB      = _PROJECT_ROOT / "observer" / "traffic.db"

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("diff_engine.diff")

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _load_summary(path: Path) -> dict[str, Any]:
    """Load a summary.json and index by service name."""
    if not path.exists():
        logger.warning("Summary file not found: %s — treating as empty.", path)
        return {}

    with path.open("r", encoding="utf-8") as fh:
        raw = json.load(fh)

    index: dict[str, set[tuple[str, str]]] = {}
    for policy in raw.get("policies", []):
        service = policy.get("service", "")
        rule_set: set[tuple[str, str]] = set()
        for rule in policy.get("rules", []):
            principal = rule.get("source_principal", "")
            for method in rule.get("methods", []):
                rule_set.add((principal, method))
        index[service] = rule_set

    return index


def _build_finding(
    service: str,
    finding_type: str,
    source_principal: str,
    method: str,
    db_path: str,
) -> dict[str, Any]:
    """Build a single finding dict (§8.4 schema)."""
    stale_count = check_staleness(
        source_principal=source_principal,
        service=service,
        method=method,
        db_path=db_path,
    )
    severity = classify_severity(finding_type, stale_window_count=stale_count)

    if finding_type == "over_permissive":
        suggested_action = "remove_rule"
        detail = (
            f"Enforced policy allows {source_principal} → {service} [{method}] "
            f"but no matching inferred rule exists."
        )
        if stale_count > 0:
            detail += f" Rule has been stale for {stale_count} consecutive observation window(s)."
    else:  # under_permissive
        suggested_action = "add_rule"
        detail = (
            f"Inferred policy requires {source_principal} → {service} [{method}] "
            f"but no matching enforced rule exists (breakage risk)."
        )

    return {
        "service": service,
        "type": finding_type,
        "detail": detail,
        "severity": severity,
        "suggested_action": suggested_action,
        "rule_ref": {
            "source_principal": source_principal,
            "methods": [method],
        },
    }


# ---------------------------------------------------------------------------
# Core diff logic
# ---------------------------------------------------------------------------

def run_diff(
    inferred_summary_path: Path = INFERRED_SUMMARY,
    enforced_summary_path: Path = ENFORCED_SUMMARY,
    patch_proposal_path:   Path = PATCH_PROPOSAL,
    observer_db_path:      Path = OBSERVER_DB,
) -> list[dict[str, Any]]:
    """
    Perform the full diff and return the list of findings.
    Also writes patch_proposal.json to `patch_proposal_path`.
    """
    logger.info("Loading inferred policy summary from %s", inferred_summary_path)
    inferred_index = _load_summary(inferred_summary_path)

    logger.info("Loading enforced policy summary from %s", enforced_summary_path)
    enforced_index = _load_summary(enforced_summary_path)

    all_services = set(inferred_index) | set(enforced_index)
    findings: list[dict[str, Any]] = []
    db_path = str(observer_db_path)

    for service in sorted(all_services):
        inferred_rules: set[tuple[str, str]] = inferred_index.get(service, set())
        enforced_rules: set[tuple[str, str]] = enforced_index.get(service, set())

        over_permissive  = enforced_rules - inferred_rules   # extra enforced
        under_permissive = inferred_rules  - enforced_rules  # missing enforced

        for principal, method in sorted(over_permissive):
            findings.append(
                _build_finding(service, "over_permissive", principal, method, db_path)
            )

        for principal, method in sorted(under_permissive):
            findings.append(
                _build_finding(service, "under_permissive", principal, method, db_path)
            )

    # Write patch_proposal.json
    proposal = {
        "generated_at": datetime.now(tz=timezone.utc).isoformat(),
        "findings": findings,
    }

    patch_proposal_path.parent.mkdir(parents=True, exist_ok=True)
    with patch_proposal_path.open("w", encoding="utf-8") as fh:
        json.dump(proposal, fh, indent=2)

    logger.info("Wrote %d finding(s) to %s", len(findings), patch_proposal_path)
    return findings


# ---------------------------------------------------------------------------
# Compatibility functions for tests and pipeline runner
# ---------------------------------------------------------------------------

def compute_diff(
    inferred_policies: list[dict[str, Any]] | dict[str, Any],
    enforced_policies: list[dict[str, Any]] | dict[str, Any],
    output_path: Path | str | None = None,
    observer_db_path: Path | str = OBSERVER_DB,
) -> dict[str, Any]:
    """
    Direct in-memory diff between inferred and enforced policy structures.
    Returns a patch proposal dictionary: {'generated_at': ..., 'findings': [...]}.
    """
    def _to_index(data):
        index: dict[str, set[tuple[str, str]]] = {}
        policies = data.get("policies", []) if isinstance(data, dict) else (data or [])
        for policy in policies:
            service = policy.get("service", "")
            rule_set: set[tuple[str, str]] = set()
            for rule in policy.get("rules", []):
                principal = rule.get("source_principal", "")
                for method in rule.get("methods", []):
                    rule_set.add((principal, method))
            index[service] = rule_set
        return index

    inferred_index = _to_index(inferred_policies)
    enforced_index = _to_index(enforced_policies)
    all_services = set(inferred_index) | set(enforced_index)
    findings: list[dict[str, Any]] = []
    db_path = str(observer_db_path)

    for service in sorted(all_services):
        inferred_rules = inferred_index.get(service, set())
        enforced_rules = enforced_index.get(service, set())

        over_permissive = enforced_rules - inferred_rules
        under_permissive = inferred_rules - enforced_rules

        for principal, method in sorted(over_permissive):
            findings.append(_build_finding(service, "over_permissive", principal, method, db_path))

        for principal, method in sorted(under_permissive):
            findings.append(_build_finding(service, "under_permissive", principal, method, db_path))

    proposal = {
        "generated_at": datetime.now(tz=timezone.utc).isoformat(),
        "findings": findings,
    }

    if output_path:
        out = Path(output_path)
        out.parent.mkdir(parents=True, exist_ok=True)
        with out.open("w", encoding="utf-8") as fh:
            json.dump(proposal, fh, indent=2)

    return proposal


def load_inferred(inferred_dir: Path | str) -> list[dict[str, Any]]:
    summary = Path(inferred_dir) / "summary.json"
    if summary.exists():
        with summary.open("r", encoding="utf-8") as fh:
            return json.load(fh).get("policies", [])
    return []


def load_enforced(enforced_dir: Path | str) -> list[dict[str, Any]]:
    summary = Path(enforced_dir) / "summary.json"
    if summary.exists():
        with summary.open("r", encoding="utf-8") as fh:
            return json.load(fh).get("policies", [])
    return []


# ---------------------------------------------------------------------------
# CLI output
# ---------------------------------------------------------------------------

def _print_findings_table(findings: list[dict[str, Any]]) -> None:
    """Print a formatted table of findings to stdout."""
    try:
        from tabulate import tabulate  # optional but preferred

        rows = [
            [
                f["service"],
                f["type"],
                f["severity"].upper(),
                f["suggested_action"],
                f["detail"],
            ]
            for f in findings
        ]
        headers = ["Service", "Type", "Severity", "Action", "Detail"]
        print(tabulate(rows, headers=headers, tablefmt="github"))

    except ImportError:
        # Fallback plain-text table if tabulate is not installed.
        col_widths = [12, 18, 10, 14, 60]
        header = (
            f"{'Service':<{col_widths[0]}} "
            f"{'Type':<{col_widths[1]}} "
            f"{'Severity':<{col_widths[2]}} "
            f"{'Action':<{col_widths[3]}} "
            f"{'Detail':<{col_widths[4]}}"
        )
        separator = "-" * sum(col_widths + [len(col_widths)])
        print(header)
        print(separator)
        for f in findings:
            print(
                f"{f['service']:<{col_widths[0]}} "
                f"{f['type']:<{col_widths[1]}} "
                f"{f['severity'].upper():<{col_widths[2]}} "
                f"{f['suggested_action']:<{col_widths[3]}} "
                f"{f['detail']:<{col_widths[4]}}"
            )


def main() -> None:
    print("=" * 70)
    print("Module 4 — Diff & Classification Engine")
    print("=" * 70)

    findings = run_diff()

    if not findings:
        print("\nNo drift detected.\n")
    else:
        print(f"\nFound {len(findings)} drift finding(s):\n")
        _print_findings_table(findings)

    print(f"\npatch_proposal.json written to: {PATCH_PROPOSAL}")


if __name__ == "__main__":
    main()
