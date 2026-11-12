"""
evaluation/metrics.py
Precision/recall/time-to-detect metrics for the Zero-Trust Evaluation Harness.
Per Architecture.md §9.6.1
"""

import json
import sys
import os
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import List, Optional


# ---------------------------------------------------------------------------
# Dataclass
# ---------------------------------------------------------------------------

@dataclass
class ScenarioResult:
    scenario_type: str            # "under_permissive" or "over_permissive"
    run_number: int
    injection_time: str           # ISO-8601 timestamp
    detection_time: Optional[str] # ISO-8601 timestamp, or None if not detected
    detected: bool
    precision: float
    recall: float
    time_to_detect_seconds: Optional[float]  # None if not detected


# ---------------------------------------------------------------------------
# Loading helpers
# ---------------------------------------------------------------------------

def load_patch_proposal(path: str = "patch_proposal.json") -> dict:
    """Load and return patch_proposal.json as a dict.

    Returns an empty dict with an empty findings list when the file does not
    exist or cannot be parsed.
    """
    if not os.path.exists(path):
        return {"findings": []}
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        if "findings" not in data:
            data["findings"] = []
        return data
    except (json.JSONDecodeError, OSError) as exc:
        print(f"[metrics] WARNING: could not read {path}: {exc}", file=sys.stderr)
        return {"findings": []}


# ---------------------------------------------------------------------------
# Core metric functions
# ---------------------------------------------------------------------------

def compute_precision(findings: list, injected_scenarios: list) -> float:
    """Fraction of reported findings that correspond to an injected scenario.

    precision = true_positives / total_findings

    A finding is a true positive when its (service, type) pair matches at least
    one entry in *injected_scenarios*.  Each injected scenario dict is expected
    to have at least the keys ``scenario_type`` and optionally ``service``.

    Returns 1.0 when findings is empty (no false positives by definition).
    """
    if not findings:
        return 1.0

    injected_keys = {
        (s.get("service", ""), s.get("scenario_type", "")) for s in injected_scenarios
    }

    true_positives = sum(
        1
        for f in findings
        if (f.get("service", ""), f.get("type", "")) in injected_keys
    )
    return true_positives / len(findings)


def compute_recall(findings: list, injected_scenarios: list) -> float:
    """Fraction of injected scenarios that were detected.

    recall = detected_scenarios / total_injected

    Returns 1.0 when injected_scenarios is empty (nothing to miss).
    """
    if not injected_scenarios:
        return 1.0

    detected = set()
    for f in findings:
        key = (f.get("service", ""), f.get("type", ""))
        detected.add(key)

    true_positives = sum(
        1
        for s in injected_scenarios
        if (s.get("service", ""), s.get("scenario_type", "")) in detected
    )
    return true_positives / len(injected_scenarios)


def compute_time_to_detect(injection_time: str, detection_time: str) -> float:
    """Return elapsed seconds between injection and detection timestamps.

    Both timestamps must be ISO-8601 strings (with or without timezone).
    """
    def _parse(ts: str) -> datetime:
        # Python 3.7+ fromisoformat does not handle trailing 'Z'
        ts = ts.replace("Z", "+00:00")
        return datetime.fromisoformat(ts)

    t0 = _parse(injection_time)
    t1 = _parse(detection_time)

    # Make both offset-aware for subtraction
    if t0.tzinfo is None:
        t0 = t0.replace(tzinfo=timezone.utc)
    if t1.tzinfo is None:
        t1 = t1.replace(tzinfo=timezone.utc)

    delta = t1 - t0
    return delta.total_seconds()


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

def print_metrics_report(results: List[dict]) -> None:
    """Print a formatted evaluation report with per-run rows and averages.

    *results* is a list of dicts that match the ``ScenarioResult`` fields
    (or ``ScenarioResult`` instances converted with ``dataclasses.asdict``).
    """
    if not results:
        print("[metrics] No results to report.")
        return

    sep = "-" * 80
    header = (
        f"{'Run':>4}  {'Scenario':<20}  {'Detected':>8}  "
        f"{'Precision':>10}  {'Recall':>8}  {'TTD (s)':>10}"
    )

    print("\n" + "=" * 80)
    print("  EVALUATION HARNESS — METRICS REPORT")
    print("=" * 80)
    print(header)
    print(sep)

    precisions: List[float] = []
    recalls: List[float] = []
    ttds: List[float] = []

    for r in results:
        run_no = r.get("run_number", "?")
        stype = r.get("scenario_type", "unknown")
        detected = r.get("detected", False)
        precision = r.get("precision", 0.0)
        recall = r.get("recall", 0.0)
        ttd = r.get("time_to_detect_seconds")

        ttd_str = f"{ttd:.2f}" if ttd is not None else "N/A"
        det_str = "YES" if detected else "NO"

        print(
            f"{run_no:>4}  {stype:<20}  {det_str:>8}  "
            f"{precision:>10.4f}  {recall:>8.4f}  {ttd_str:>10}"
        )

        precisions.append(precision)
        recalls.append(recall)
        if ttd is not None:
            ttds.append(ttd)

    print(sep)

    avg_precision = sum(precisions) / len(precisions) if precisions else 0.0
    avg_recall = sum(recalls) / len(recalls) if recalls else 0.0
    avg_ttd = sum(ttds) / len(ttds) if ttds else None
    detection_rate = sum(1 for r in results if r.get("detected", False)) / len(results)

    avg_ttd_str = f"{avg_ttd:.2f}" if avg_ttd is not None else "N/A"

    print(
        f"{'AVG':>4}  {'':20}  {detection_rate:>8.1%}  "
        f"{avg_precision:>10.4f}  {avg_recall:>8.4f}  {avg_ttd_str:>10}"
    )
    print("=" * 80 + "\n")

    print(f"  Detection Rate  : {detection_rate:.1%}  ({sum(1 for r in results if r.get('detected', False))}/{len(results)} runs)")
    print(f"  Avg Precision   : {avg_precision:.4f}")
    print(f"  Avg Recall      : {avg_recall:.4f}")
    print(f"  Avg TTD (s)     : {avg_ttd_str}")
    print("=" * 80 + "\n")
