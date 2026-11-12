#!/usr/bin/env python3
"""
run_pipeline.py
Zero-Trust Policy Synthesis Engine – Pipeline Orchestrator

Usage:
    python run_pipeline.py [--once] [--skip-pr] [--dry-run]

Options:
    --once      Run the pipeline once then exit (overrides continuous loop).
    --skip-pr   Skip Module 5 (do not open GitHub PRs).
    --dry-run   Run without writing files or opening PRs (implies --skip-pr
                and suppresses all write-side-effects).
    --loop      Run continuously, sleeping POLL_INTERVAL_SECONDS between runs
                (default behaviour when --once is not set).
"""
import argparse
import logging
import sys
import time
import os

# ---------------------------------------------------------------------------
# Ensure the project root is on sys.path so all modules are importable.
# ---------------------------------------------------------------------------
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
log = logging.getLogger("pipeline")


# ---------------------------------------------------------------------------
# Import shared config (tolerates missing module gracefully)
# ---------------------------------------------------------------------------
try:
    from shared.config import POLL_INTERVAL_SECONDS  # type: ignore
except Exception:
    POLL_INTERVAL_SECONDS = int(os.environ.get("POLL_INTERVAL_SECONDS", 60))


# ---------------------------------------------------------------------------
# Individual step runners
# ---------------------------------------------------------------------------

def run_module1_collect(dry_run: bool) -> None:
    """Module 1 – Observer: collect Istio traffic metrics from Prometheus."""
    from observer.collect import collection_cycle, init_db  # type: ignore

    db_path = os.path.join(PROJECT_ROOT, "observer", "traffic.db")
    output_path = os.path.join(PROJECT_ROOT, "observer", "output", "traffic_graph.json")

    if dry_run:
        log.info("[dry-run] Would collect traffic (Module 1 skipped write).")
        return

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    conn = init_db(db_path)
    try:
        collection_cycle(conn, output_path)
    finally:
        conn.close()


def run_module3_fetch(dry_run: bool) -> None:
    """Module 3 – Policy Fetcher: pull enforced AuthorizationPolicies from K8s."""
    from policy_fetcher.fetch_policies import fetch_policies  # type: ignore

    output_dir = os.path.join(PROJECT_ROOT, "policy_fetcher", "output")

    if dry_run:
        log.info("[dry-run] Would fetch enforced policies (Module 3 skipped write).")
        return

    os.makedirs(output_dir, exist_ok=True)
    fetch_policies(output_dir)


def run_module2_infer(dry_run: bool) -> None:
    """Module 2 – Inferencer: infer Istio policies from observed traffic."""
    from inferencer.infer_policy import infer_policies  # type: ignore

    db_path = os.path.join(PROJECT_ROOT, "observer", "traffic.db")
    output_dir = os.path.join(PROJECT_ROOT, "inferencer", "output")

    if dry_run:
        log.info("[dry-run] Would infer policies (Module 2 skipped write).")
        return

    os.makedirs(output_dir, exist_ok=True)
    infer_policies(db_path, output_dir)


def run_module4_diff(dry_run: bool) -> dict:
    """Module 4 – Diff Engine: compare inferred vs. enforced policies."""
    from diff_engine.diff import compute_diff, load_inferred, load_enforced  # type: ignore

    inferred_dir = os.path.join(PROJECT_ROOT, "inferencer", "output")
    enforced_dir = os.path.join(PROJECT_ROOT, "policy_fetcher", "output")
    output_path = os.path.join(PROJECT_ROOT, "diff_engine", "output", "patch_proposal.json")

    if dry_run:
        log.info("[dry-run] Would compute policy diff (Module 4 skipped write).")
        return {"generated_at": "", "findings": []}

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    inferred = load_inferred(inferred_dir)
    enforced = load_enforced(enforced_dir)
    return compute_diff(inferred, enforced, output_path)


def run_module5_pr(patch_proposal: dict, dry_run: bool) -> None:
    """Module 5 – GitOps PR: open a GitHub PR with the patch proposal."""
    if dry_run:
        log.info("[dry-run] Would open GitHub PR (Module 5 skipped).")
        return

    from gitops.open_pr import open_pr  # type: ignore

    pr_url = open_pr(patch_proposal)
    if pr_url:
        log.info("Module 5 opened PR: %s", pr_url)
    else:
        log.info("Module 5: no PR created (no findings).")


# ---------------------------------------------------------------------------
# Pipeline runner
# ---------------------------------------------------------------------------

STEPS = [
    ("Module 1 (Observer/Collect)",    "module1"),
    ("Module 3 (Policy Fetcher)",       "module3"),
    ("Module 2 (Inferencer)",           "module2"),
    ("Module 4 (Diff Engine)",          "module4"),
    ("Module 5 (GitOps PR)",            "module5"),
]


def run_pipeline(skip_pr: bool = False, dry_run: bool = False) -> tuple[int, int]:
    """
    Execute all pipeline steps in order.

    Returns:
        (succeeded, failed) counts.
    """
    succeeded = 0
    failed = 0
    patch_proposal: dict = {"generated_at": "", "findings": []}

    for label, step_id in STEPS:
        if step_id == "module5" and skip_pr:
            log.info("Skipping %s (--skip-pr).", label)
            continue

        log.info("Running %s...", label)
        try:
            if step_id == "module1":
                run_module1_collect(dry_run)
            elif step_id == "module3":
                run_module3_fetch(dry_run)
            elif step_id == "module2":
                run_module2_infer(dry_run)
            elif step_id == "module4":
                patch_proposal = run_module4_diff(dry_run) or patch_proposal
            elif step_id == "module5":
                run_module5_pr(patch_proposal, dry_run)

            log.info("%s succeeded.", label)
            succeeded += 1

        except Exception as exc:  # pylint: disable=broad-except
            log.error("%s FAILED: %s", label, exc, exc_info=True)
            failed += 1
            # Continue to next step regardless of failure

    return succeeded, failed


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Zero-Trust Policy Synthesis Engine – Pipeline Orchestrator",
    )
    parser.add_argument(
        "--once",
        action="store_true",
        help="Run the pipeline once then exit (overrides --loop).",
    )
    parser.add_argument(
        "--loop",
        action="store_true",
        help="Run continuously, sleeping POLL_INTERVAL_SECONDS between runs "
             "(default when --once is not supplied).",
    )
    parser.add_argument(
        "--skip-pr",
        action="store_true",
        dest="skip_pr",
        help="Skip Module 5 (do not open GitHub PRs).",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        dest="dry_run",
        help="Run without writing files or opening PRs.",
    )
    return parser.parse_args()


def main() -> None:
    args = _parse_args()

    # --dry-run implies --skip-pr
    skip_pr = args.skip_pr or args.dry_run
    continuous = args.loop and not args.once

    run_count = 0
    while True:
        run_count += 1
        if continuous:
            log.info("=== Pipeline run #%d ===", run_count)

        succeeded, failed = run_pipeline(skip_pr=skip_pr, dry_run=args.dry_run)
        total = succeeded + failed
        log.info(
            "Pipeline complete: %d/%d steps succeeded, %d steps failed.",
            succeeded, total, failed,
        )
        print(
            f"Pipeline complete: {succeeded} steps succeeded, {failed} steps failed."
        )

        if not continuous:
            break

        log.info(
            "Sleeping %d seconds before next run (Ctrl-C to stop)...",
            POLL_INTERVAL_SECONDS,
        )
        try:
            time.sleep(POLL_INTERVAL_SECONDS)
        except KeyboardInterrupt:
            log.info("Pipeline loop interrupted by user.")
            break


if __name__ == "__main__":
    main()
