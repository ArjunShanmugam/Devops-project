"""
evaluation/inject_drift.py
Full evaluation harness for the Zero-Trust Policy Synthesis Engine.
Implements Scenario A (under_permissive) and Scenario B (over_permissive)
per Architecture.md §9.6.1.

Usage:
    python evaluation/inject_drift.py --scenario A --runs 5
    python evaluation/inject_drift.py --scenario B --runs 5
    python evaluation/inject_drift.py --scenario both --runs 5
"""

import argparse
import json
import os
import sys
import time
import subprocess
import tempfile
import traceback
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

# ---------------------------------------------------------------------------
# Project root on sys.path so shared/ and evaluation/ are importable
# ---------------------------------------------------------------------------
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))

from evaluation.metrics import (
    ScenarioResult,
    load_patch_proposal,
    compute_precision,
    compute_recall,
    compute_time_to_detect,
    print_metrics_report,
)

# ---------------------------------------------------------------------------
# Config / constants
# ---------------------------------------------------------------------------
try:
    from shared.config import POLL_INTERVAL_SECONDS, K8S_NAMESPACE
except ImportError:
    POLL_INTERVAL_SECONDS = int(os.environ.get("POLL_INTERVAL_SECONDS", 60))
    K8S_NAMESPACE = os.environ.get("K8S_NAMESPACE", "default")

PATCH_PROPOSAL_PATH = str(_PROJECT_ROOT / "patch_proposal.json")
RESULTS_OUTPUT_PATH = str(_PROJECT_ROOT / "evaluation" / "results.json")

# Maximum time (seconds) to wait for a detection before declaring a miss
DETECTION_TIMEOUT_SECONDS = int(os.environ.get("DETECTION_TIMEOUT_SECONDS", 600))

# Fake AuthorizationPolicy name used in Scenario B
FAKE_POLICY_NAME = "eval-fake-svc-c-to-svc-a-delete"


# ---------------------------------------------------------------------------
# Kubernetes availability check
# ---------------------------------------------------------------------------

def _check_k8s_available() -> bool:
    """Return True if kubectl can reach the cluster."""
    try:
        result = subprocess.run(
            ["kubectl", "cluster-info"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        return result.returncode == 0
    except FileNotFoundError:
        return False
    except subprocess.TimeoutExpired:
        return False
    except Exception:  # noqa: BLE001
        return False


def _now_iso() -> str:
    """Return current UTC time as ISO-8601 string."""
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# Kubernetes helpers (subprocess-based)
# ---------------------------------------------------------------------------

def _kubectl(*args: str, check: bool = True) -> subprocess.CompletedProcess:
    """Run a kubectl command, returning the CompletedProcess."""
    cmd = ["kubectl"] + list(args)
    return subprocess.run(cmd, capture_output=True, text=True, check=check)


def _apply_yaml(yaml_text: str) -> None:
    """Apply a YAML manifest via kubectl apply -f -."""
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".yaml", delete=False, encoding="utf-8"
    ) as tmp:
        tmp.write(yaml_text)
        tmp_path = tmp.name
    try:
        _kubectl("apply", "-f", tmp_path)
    finally:
        os.unlink(tmp_path)


def _delete_yaml(yaml_text: str, ignore_not_found: bool = True) -> None:
    """Delete resources described by a YAML manifest via kubectl delete -f -."""
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".yaml", delete=False, encoding="utf-8"
    ) as tmp:
        tmp.write(yaml_text)
        tmp_path = tmp.name
    try:
        args = ["delete", "-f", tmp_path]
        if ignore_not_found:
            args.append("--ignore-not-found=true")
        _kubectl(*args, check=False)
    finally:
        os.unlink(tmp_path)


# ---------------------------------------------------------------------------
# Polling helpers
# ---------------------------------------------------------------------------

def _poll_for_finding(
    scenario_type: str,
    service: str,
    timeout_seconds: int = DETECTION_TIMEOUT_SECONDS,
    poll_interval: int = POLL_INTERVAL_SECONDS,
) -> Optional[str]:
    """Poll patch_proposal.json until a matching finding appears.

    Returns the ISO-8601 detection timestamp, or None on timeout.
    """
    deadline = time.monotonic() + timeout_seconds
    print(
        f"[harness] Polling for {scenario_type} finding on '{service}' "
        f"(timeout={timeout_seconds}s, interval={poll_interval}s)…"
    )
    while time.monotonic() < deadline:
        proposal = load_patch_proposal(PATCH_PROPOSAL_PATH)
        for finding in proposal.get("findings", []):
            if (
                finding.get("type") == scenario_type
                and finding.get("service") == service
            ):
                detected_at = _now_iso()
                print(f"[harness] ✓ Detection confirmed at {detected_at}")
                return detected_at
        remaining = int(deadline - time.monotonic())
        print(f"[harness]   Not yet detected. Retrying in {poll_interval}s ({remaining}s remaining)…")
        time.sleep(poll_interval)

    print(f"[harness] ✗ Timeout reached — {scenario_type} finding for '{service}' not detected.")
    return None


# ---------------------------------------------------------------------------
# Scenario A — Under-permissive injection
# ---------------------------------------------------------------------------

_SCENARIO_A_ENV_PATCH = {
    "spec": {
        "template": {
            "spec": {
                "containers": [
                    {
                        "name": "service-a",
                        "env": [
                            {
                                "name": "SERVICE_C_LOG_URL",
                                "value": "http://service-c:8080/api/log",
                            }
                        ],
                    }
                ]
            }
        }
    }
}

# ConfigMap that simulates service-a learning about the new outbound call
_SCENARIO_A_CONFIGMAP = """\
apiVersion: v1
kind: ConfigMap
metadata:
  name: service-a-eval-drift
  namespace: {namespace}
data:
  SERVICE_C_LOG_URL: "http://service-c:8080/api/log"
"""


def _run_scenario_a(run_number: int, namespace: str) -> ScenarioResult:
    """Inject an under-permissive condition and measure detection time.

    Steps:
    1. Record injection_time.
    2. Patch service-a Deployment to add SERVICE_C_LOG_URL env var.
    3. Apply a ConfigMap to persist the intent.
    4. Poll patch_proposal.json for an under_permissive finding on service-a.
    5. Record detection_time.
    6. Clean up: remove the env var patch and the ConfigMap.
    """
    print(f"\n[Scenario A | run {run_number}] Starting under-permissive injection…")

    configmap_yaml = _SCENARIO_A_CONFIGMAP.format(namespace=namespace)
    injection_time = _now_iso()
    detected = False
    detection_time: Optional[str] = None

    try:
        # Apply ConfigMap
        print("[Scenario A] Applying eval ConfigMap…")
        _apply_yaml(configmap_yaml)

        # Patch the Deployment with the new env var (strategic merge)
        patch_json = json.dumps(_SCENARIO_A_ENV_PATCH)
        print("[Scenario A] Patching service-a deployment…")
        _kubectl(
            "patch",
            "deployment",
            "service-a",
            "--namespace",
            namespace,
            "--type",
            "strategic",
            "--patch",
            patch_json,
            check=False,  # non-fatal if deployment doesn't exist in test env
        )

        # Poll for detection
        detection_time = _poll_for_finding(
            scenario_type="under_permissive",
            service="service-a",
        )
        detected = detection_time is not None

    except Exception as exc:  # noqa: BLE001
        print(f"[Scenario A | run {run_number}] ERROR: {exc}", file=sys.stderr)
        traceback.print_exc()
    finally:
        # --- Cleanup ---
        print("[Scenario A] Cleaning up: reverting env var patch…")
        # Remove the injected env var by patching it back to empty
        revert_patch = json.dumps(
            {
                "spec": {
                    "template": {
                        "spec": {
                            "containers": [
                                {
                                    "name": "service-a",
                                    "$patch": "delete",
                                    "env": [{"name": "SERVICE_C_LOG_URL"}],
                                }
                            ]
                        }
                    }
                }
            }
        )
        _kubectl(
            "patch",
            "deployment",
            "service-a",
            "--namespace",
            namespace,
            "--type",
            "strategic",
            "--patch",
            revert_patch,
            check=False,
        )
        print("[Scenario A] Deleting eval ConfigMap…")
        _delete_yaml(configmap_yaml)
        print("[Scenario A] Cleanup complete.")

    # Build injected_scenarios list for metric computation
    injected_scenarios = [{"service": "service-a", "scenario_type": "under_permissive"}]

    # Load proposal findings for precision/recall
    proposal = load_patch_proposal(PATCH_PROPOSAL_PATH)
    findings = proposal.get("findings", [])

    precision = compute_precision(findings, injected_scenarios)
    recall = compute_recall(findings, injected_scenarios)
    ttd: Optional[float] = None
    if detected and detection_time:
        ttd = compute_time_to_detect(injection_time, detection_time)

    result = ScenarioResult(
        scenario_type="under_permissive",
        run_number=run_number,
        injection_time=injection_time,
        detection_time=detection_time,
        detected=detected,
        precision=precision,
        recall=recall,
        time_to_detect_seconds=ttd,
    )
    print(
        f"[Scenario A | run {run_number}] Result: detected={detected}, "
        f"TTD={ttd:.1f}s" if ttd is not None else
        f"[Scenario A | run {run_number}] Result: detected={detected}, TTD=N/A"
    )
    return result


# ---------------------------------------------------------------------------
# Scenario B — Over-permissive injection
# ---------------------------------------------------------------------------

_FAKE_AUTHORIZATION_POLICY = """\
apiVersion: security.istio.io/v1beta1
kind: AuthorizationPolicy
metadata:
  name: {policy_name}
  namespace: {namespace}
  labels:
    eval-harness: "true"
spec:
  selector:
    matchLabels:
      app: service-a
  rules:
    - from:
        - source:
            principals:
              - "cluster.local/ns/{namespace}/sa/service-c-sa"
      to:
        - operation:
            methods: ["DELETE"]
"""


def _run_scenario_b(run_number: int, namespace: str) -> ScenarioResult:
    """Inject an over-permissive condition and measure detection time.

    Steps:
    1. Record injection_time.
    2. kubectl apply a fake AuthorizationPolicy: service-c→service-a DELETE.
    3. Poll patch_proposal.json for an over_permissive finding for service-a.
    4. Record detection_time.
    5. Clean up: kubectl delete the fake policy.
    """
    print(f"\n[Scenario B | run {run_number}] Starting over-permissive injection…")

    policy_yaml = _FAKE_AUTHORIZATION_POLICY.format(
        policy_name=FAKE_POLICY_NAME,
        namespace=namespace,
    )
    injection_time = _now_iso()
    detected = False
    detection_time: Optional[str] = None

    try:
        print("[Scenario B] Applying fake AuthorizationPolicy…")
        _apply_yaml(policy_yaml)

        # Poll for detection
        detection_time = _poll_for_finding(
            scenario_type="over_permissive",
            service="service-a",
        )
        detected = detection_time is not None

    except Exception as exc:  # noqa: BLE001
        print(f"[Scenario B | run {run_number}] ERROR: {exc}", file=sys.stderr)
        traceback.print_exc()
    finally:
        # --- Cleanup ---
        print("[Scenario B] Deleting fake AuthorizationPolicy…")
        _delete_yaml(policy_yaml)
        print("[Scenario B] Cleanup complete.")

    # Metric computation
    injected_scenarios = [{"service": "service-a", "scenario_type": "over_permissive"}]
    proposal = load_patch_proposal(PATCH_PROPOSAL_PATH)
    findings = proposal.get("findings", [])

    precision = compute_precision(findings, injected_scenarios)
    recall = compute_recall(findings, injected_scenarios)
    ttd: Optional[float] = None
    if detected and detection_time:
        ttd = compute_time_to_detect(injection_time, detection_time)

    result = ScenarioResult(
        scenario_type="over_permissive",
        run_number=run_number,
        injection_time=injection_time,
        detection_time=detection_time,
        detected=detected,
        precision=precision,
        recall=recall,
        time_to_detect_seconds=ttd,
    )
    print(
        f"[Scenario B | run {run_number}] Result: detected={detected}, "
        f"TTD={ttd:.1f}s" if ttd is not None else
        f"[Scenario B | run {run_number}] Result: detected={detected}, TTD=N/A"
    )
    return result


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def _parse_args(argv=None):
    parser = argparse.ArgumentParser(
        description="Zero-Trust Evaluation Harness — drift injection & metrics"
    )
    parser.add_argument(
        "--scenario",
        choices=["A", "B", "both"],
        default="both",
        help="Which scenario to run: A (under_permissive), B (over_permissive), or both",
    )
    parser.add_argument(
        "--runs",
        type=int,
        default=5,
        help="Number of times to run each scenario (default: 5)",
    )
    parser.add_argument(
        "--namespace",
        default=K8S_NAMESPACE,
        help=f"Kubernetes namespace (default: {K8S_NAMESPACE})",
    )
    parser.add_argument(
        "--poll-interval",
        type=int,
        default=POLL_INTERVAL_SECONDS,
        dest="poll_interval",
        help=f"Polling interval in seconds (default: {POLL_INTERVAL_SECONDS})",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=DETECTION_TIMEOUT_SECONDS,
        help=f"Detection timeout in seconds per run (default: {DETECTION_TIMEOUT_SECONDS})",
    )
    return parser.parse_args(argv)


def main(argv=None):
    args = _parse_args(argv)

    # Apply CLI overrides to module-level constants so helpers pick them up
    global POLL_INTERVAL_SECONDS, DETECTION_TIMEOUT_SECONDS
    POLL_INTERVAL_SECONDS = args.poll_interval
    DETECTION_TIMEOUT_SECONDS = args.timeout

    # K8s availability gate
    print("[harness] Checking Kubernetes cluster availability…")
    if not _check_k8s_available():
        print(
            "[harness] WARNING: Kubernetes cluster is not reachable. "
            "kubectl is unavailable or the cluster is down. "
            "Cannot run evaluation scenarios. Exiting gracefully.",
            file=sys.stderr,
        )
        sys.exit(0)
    print("[harness] Kubernetes cluster reachable ✓")

    runs: int = max(1, args.runs)
    namespace: str = args.namespace
    all_results: list[ScenarioResult] = []

    scenarios_to_run = []
    if args.scenario in ("A", "both"):
        scenarios_to_run.append("A")
    if args.scenario in ("B", "both"):
        scenarios_to_run.append("B")

    for scenario in scenarios_to_run:
        print(f"\n{'='*70}")
        print(f"  Running Scenario {scenario} × {runs} runs  (namespace={namespace})")
        print(f"{'='*70}")
        for run_no in range(1, runs + 1):
            if scenario == "A":
                result = _run_scenario_a(run_no, namespace)
            else:
                result = _run_scenario_b(run_no, namespace)
            all_results.append(result)

            # Brief pause between runs to let the system settle
            if run_no < runs:
                settle = max(5, POLL_INTERVAL_SECONDS // 4)
                print(f"[harness] Pausing {settle}s before next run…")
                time.sleep(settle)

    # ---- Report ----
    results_as_dicts = [asdict(r) for r in all_results]
    print_metrics_report(results_as_dicts)

    # ---- Persist results ----
    output_path = Path(RESULTS_OUTPUT_PATH)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_data = {
        "generated_at": _now_iso(),
        "runs_per_scenario": runs,
        "scenarios": scenarios_to_run,
        "results": results_as_dicts,
    }
    with open(output_path, "w", encoding="utf-8") as fh:
        json.dump(output_data, fh, indent=2, default=str)
    print(f"[harness] Results written to {output_path}")


if __name__ == "__main__":
    main()
