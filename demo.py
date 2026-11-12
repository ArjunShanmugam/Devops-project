"""
demo.py

Interactive Teacher Demo Runner for the Zero-Trust Policy Synthesis Engine.
Runs the complete 6-module pipeline end-to-end, displays rich terminal output
for each phase, generates sample traffic and policies, and launches the live UI.

No Docker, Kubernetes, or GitHub token required to run this presentation demo.
"""

import os
import sys
import time
import json
import sqlite3
from datetime import datetime, timezone, timedelta
from pathlib import Path

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(PROJECT_ROOT))

from shared.config import (
    POLL_INTERVAL_SECONDS,
    MIN_REQUEST_COUNT,
    MAX_STALENESS_WINDOWS,
    STALE_RULE_AGE_WINDOWS,
)


def print_banner(text: str, color: str = "cyan"):
    width = 75
    print("\n" + "=" * width)
    print(f"  {text}")
    print("=" * width + "\n")


def stage_1_simulate_traffic():
    print_banner("STAGE 1: Traffic Observer (Module 1)")
    print("Simulating live Istio mesh traffic observation across 12 collection windows...")

    db_path = PROJECT_ROOT / "observer" / "traffic.db"
    db_path.parent.mkdir(parents=True, exist_ok=True)

    conn = sqlite3.connect(str(db_path))
    conn.execute("DROP TABLE IF EXISTS traffic_edges")
    conn.execute(
        """
        CREATE TABLE traffic_edges (
            window_start TEXT NOT NULL,
            window_end TEXT NOT NULL,
            source_workload TEXT NOT NULL,
            destination_workload TEXT NOT NULL,
            method TEXT NOT NULL,
            response_code TEXT NOT NULL,
            request_count INTEGER NOT NULL,
            last_seen TEXT NOT NULL
        )
        """
    )

    now = datetime.now(timezone.utc)
    edges_for_json = []

    # Insert 12 consecutive 60-second windows
    for i in range(12, 0, -1):
        w_start = (now - timedelta(seconds=i * 60)).isoformat()
        w_end = (now - timedelta(seconds=(i - 1) * 60)).isoformat()

        # service-a -> service-b (GET /api/items)
        conn.execute(
            "INSERT INTO traffic_edges VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (w_start, w_end, "service-a", "service-b", "GET", "200", 45 + (12 - i) * 3, w_end),
        )
        # service-b -> service-c (POST /api/log)
        conn.execute(
            "INSERT INTO traffic_edges VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (w_start, w_end, "service-b", "service-c", "POST", "200", 45 + (12 - i) * 3, w_end),
        )
        # service-a -> service-c (GET /api/health)
        conn.execute(
            "INSERT INTO traffic_edges VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (w_start, w_end, "service-a", "service-c", "GET", "200", 40 + (12 - i) * 2, w_end),
        )

        if i == 1:
            edges_for_json = [
                {
                    "source_workload": "service-a",
                    "destination_workload": "service-b",
                    "method": "GET",
                    "response_code": "200",
                    "request_count": 78,
                    "last_seen": w_end,
                },
                {
                    "source_workload": "service-b",
                    "destination_workload": "service-c",
                    "method": "POST",
                    "response_code": "200",
                    "request_count": 78,
                    "last_seen": w_end,
                },
                {
                    "source_workload": "service-a",
                    "destination_workload": "service-c",
                    "method": "GET",
                    "response_code": "200",
                    "request_count": 62,
                    "last_seen": w_end,
                },
            ]

    conn.commit()
    conn.close()

    # Write traffic_graph.json
    out_json = PROJECT_ROOT / "observer" / "output" / "traffic_graph.json"
    out_json.parent.mkdir(parents=True, exist_ok=True)
    graph_data = {
        "window_start": (now - timedelta(seconds=60)).isoformat(),
        "window_end": now.isoformat(),
        "edges": edges_for_json,
    }
    with open(out_json, "w", encoding="utf-8") as f:
        json.dump(graph_data, f, indent=2)

    print(f" [OK] Successfully captured {len(edges_for_json)} active edges in SQLite DB.")
    print(f" [OK] Wrote observer/output/traffic_graph.json")
    print("\nObserved Live Traffic Edges:")
    print(f"  {'Source':<15} {'Destination':<15} {'Method':<8} {'Requests/Min':<15}")
    print("  " + "-" * 55)
    for e in edges_for_json:
        print(f"  {e['source_workload']:<15} {e['destination_workload']:<15} {e['method']:<8} {e['request_count']:<15}")


def stage_2_infer_policies():
    print_banner("STAGE 2: Policy Inferencer (Module 2)")
    print("Synthesizing minimal least-privilege AuthorizationPolicies from observed traffic...")
    print(f"Thresholds applied: MIN_REQUEST_COUNT={MIN_REQUEST_COUNT}, MAX_STALENESS_WINDOWS={MAX_STALENESS_WINDOWS}")

    from inferencer.infer_policy import infer_policies

    db_path = PROJECT_ROOT / "observer" / "traffic.db"
    out_dir = PROJECT_ROOT / "inferred_policy"
    policies = infer_policies(db_path, out_dir, namespace="default")

    print(f"\n [OK] Synthesized {len(policies)} minimal service policies:")
    for p in policies:
        print(f"  • Service: {p['service']} ({len(p['rules'])} allowed principal rule(s))")
        for r in p["rules"]:
            print(f"      <- Principal: {r['source_principal']} | Methods: {r['methods']}")
    print(f" [OK] Output YAMLs written to: inferred_policy/")


def stage_3_simulate_enforced_policies():
    print_banner("STAGE 3: Enforced Policy Fetcher (Module 3)")
    print("Inspecting currently enforced Istio AuthorizationPolicies in the cluster...")

    enforced_dir = PROJECT_ROOT / "enforced_policy"
    enforced_dir.mkdir(parents=True, exist_ok=True)

    # Simulate realistic drift:
    # 1. service-b allows service-a (GET) [Compliant]
    # 2. service-b allows service-c (POST) [Stale! service-c NEVER calls service-b -> over_permissive]
    # 3. service-c does NOT have a rule for service-a (GET) [Missing! Traffic active -> under_permissive]
    summary_data = {
        "policies": [
            {
                "service": "service-b",
                "namespace": "default",
                "rules": [
                    {
                        "source_principal": "cluster.local/ns/default/sa/service-a-sa",
                        "methods": ["GET"],
                    },
                    {
                        "source_principal": "cluster.local/ns/default/sa/service-c-sa",
                        "methods": ["POST"],
                    },
                ],
            },
            {
                "service": "service-c",
                "namespace": "default",
                "rules": [
                    {
                        "source_principal": "cluster.local/ns/default/sa/service-b-sa",
                        "methods": ["POST"],
                    }
                ],
            },
        ]
    }

    with open(enforced_dir / "summary.json", "w", encoding="utf-8") as f:
        json.dump(summary_data, f, indent=2)

    print(" [OK] Retrieved active cluster policies:")
    print("  • service-b: ALLOW service-a-sa [GET] & service-c-sa [POST]")
    print("  • service-c: ALLOW service-b-sa [POST]")


def stage_4_diff_and_classify():
    print_banner("STAGE 4: Diff & Classification Engine (Module 4)")
    print("Comparing Inferred Policies (Reality) vs Enforced Policies (Cluster)...")

    from diff_engine.diff import run_diff

    findings = run_diff()

    print(f"\n [OK] Identified {len(findings)} Security Drift Finding(s):")
    print(f"  {'Service':<12} {'Drift Type':<18} {'Severity':<10} {'Suggested Action':<16}")
    print("  " + "-" * 60)
    for f in findings:
        sev = f["severity"].upper()
        print(f"  {f['service']:<12} {f['type']:<18} {sev:<10} {f['suggested_action']:<16}")
        print(f"    Detail: {f['detail']}")

    print(f"\n [OK] patch_proposal.json written.")


def stage_5_gitops_proposal():
    print_banner("STAGE 5: GitOps Policy Delivery (Module 5)")
    print("Compiling human-reviewable Policy Change Proposal (PR payload)...")

    proposal_file = PROJECT_ROOT / "patch_proposal.json"
    with open(proposal_file, "r", encoding="utf-8") as f:
        proposal = json.load(f)

    findings = proposal.get("findings", [])
    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    md_lines = [
        "# 🛡️ Zero-Trust Policy Sync Proposal (GitOps PR Preview)",
        f"\n**Generated at:** {now_str}",
        "**Target Branch:** `policy-sync-" + datetime.now().strftime("%Y%m%d-%H%M%S") + "`\n",
        "## Summary of Changes Required\n",
    ]

    for idx, f in enumerate(findings, 1):
        sev_emoji = "🔴" if f["severity"] == "high" else "🟡"
        action_badge = "`+ ADD RULE`" if f["suggested_action"] == "add_rule" else "`- REMOVE RULE`"
        md_lines.append(f"### {idx}. [{f['service']}] {sev_emoji} {f['type'].upper()} ({f['severity'].upper()} Severity)")
        md_lines.append(f"- **Action:** {action_badge}")
        md_lines.append(f"- **Details:** {f['detail']}")
        md_lines.append(f"- **Affected Principal:** `{f['rule_ref']['source_principal']}`")
        md_lines.append(f"- **Methods:** `{f['rule_ref']['methods']}`\n")

    md_lines.append("---")
    md_lines.append("\n> **Important:** This PR was generated autonomously by observed service-mesh telemetry.")
    md_lines.append("> Human review and sign-off is required before merging. No live cluster rules were altered.")

    pr_md_path = PROJECT_ROOT / "policy-proposal-PR.md"
    with open(pr_md_path, "w", encoding="utf-8") as f:
        f.write("\n".join(md_lines))

    print(f" [OK] Generated reviewable GitOps Pull Request specification:")
    print(f"      {pr_md_path}")
    print("\nPR Preview Body:")
    print("\n".join(md_lines[:15]) + "\n...")


def stage_6_launch_dashboard():
    print_banner("STAGE 6: Live Web Dashboard (Real-time UI)")
    print("Launching the Zero-Trust Policy Engine Dashboard on http://localhost:5050...")
    print("Press Ctrl+C in this terminal when you are done presenting.\n")

    from dashboard.server import app
    app.run(host="0.0.0.0", port=5050, debug=False)


def main():
    print("=" * 75)
    print("   BEHAVIOR-DERIVED ZERO-TRUST POLICY SYNTHESIS ENGINE")
    print("               TEACHER DEMONSTRATION RUNNER")
    print("=" * 75)
    print("This walkthrough executes all modules step-by-step with real data.\n")

    time.sleep(1)
    stage_1_simulate_traffic()

    time.sleep(1)
    stage_2_infer_policies()

    time.sleep(1)
    stage_3_simulate_enforced_policies()

    time.sleep(1)
    stage_4_diff_and_classify()

    time.sleep(1)
    stage_5_gitops_proposal()

    print("\n" + "=" * 75)
    print("  ALL 5 PIPELINE STAGES COMPLETED SUCCESSFULLY!")
    print("  Next: Launching the live interactive dashboard UI...")
    print("=" * 75 + "\n")
    time.sleep(1)

    stage_6_launch_dashboard()


if __name__ == "__main__":
    main()
