"""
dashboard/server.py

Flask server for the Zero-Trust Policy Synthesis Engine dashboard.
Serves index.html and exposes API endpoints for all pipeline modules.

Routes:
  GET /              -> dashboard/index.html
  GET /api/graph     -> reads observer/output/traffic_graph.json
  GET /api/findings  -> reads patch_proposal.json
  GET /api/policies  -> reads enforced_policy/summary.json
  GET /api/inferred  -> reads inferred_policy/summary.json
  GET /api/history   -> reads observer/traffic.db, returns last 20 windows

Run with:
  python dashboard/server.py

Port: 5050
"""

import json
import sqlite3
from pathlib import Path

from flask import Flask, jsonify, send_from_directory

HERE        = Path(__file__).parent.resolve()
ROOT        = HERE.parent

GRAPH_JSON      = ROOT / "observer" / "output" / "traffic_graph.json"
FINDINGS_JSON   = ROOT / "patch_proposal.json"
POLICIES_JSON   = ROOT / "enforced_policy" / "summary.json"
INFERRED_JSON   = ROOT / "inferred_policy" / "summary.json"
TRAFFIC_DB      = ROOT / "observer" / "traffic.db"

app = Flask(__name__, static_folder=None)


# ── helpers ──────────────────────────────────────────────────────────────────

def _load_json(path: Path, fallback):
    """Load JSON from path; return fallback on any error."""
    try:
        with open(path, "r", encoding="utf-8-sig") as fh:
            return json.load(fh)
    except (FileNotFoundError, json.JSONDecodeError):
        return fallback


# ── existing route ────────────────────────────────────────────────────────────

@app.get("/")
def index():
    return send_from_directory(str(HERE), "index.html")


@app.get("/api/graph")
def api_graph():
    try:
        with open(GRAPH_JSON, "r", encoding="utf-8-sig") as fh:
            data = json.load(fh)
        data["ok"] = True
        return jsonify(data)
    except FileNotFoundError:
        return jsonify({
            "ok": False,
            "error": "traffic_graph.json not found – is collector.py running?",
            "window_start": None,
            "window_end": None,
            "edges": [],
        })
    except json.JSONDecodeError as exc:
        return jsonify({
            "ok": False,
            "error": f"traffic_graph.json is not valid JSON: {exc}",
            "window_start": None,
            "window_end": None,
            "edges": [],
        })


# ── new routes ────────────────────────────────────────────────────────────────

@app.get("/api/findings")
def api_findings():
    """Return findings list from patch_proposal.json."""
    data = _load_json(FINDINGS_JSON, {"findings": []})
    findings = data.get("findings", []) if isinstance(data, dict) else []
    return jsonify({"ok": True, "findings": findings})


@app.get("/api/policies")
def api_policies():
    """Return enforced policy summary."""
    data = _load_json(POLICIES_JSON, {"policies": []})
    policies = data.get("policies", []) if isinstance(data, dict) else []
    return jsonify({"ok": True, "policies": policies})


@app.get("/api/inferred")
def api_inferred():
    """Return inferred policy summary."""
    data = _load_json(INFERRED_JSON, {"policies": []})
    policies = data.get("policies", []) if isinstance(data, dict) else []
    return jsonify({"ok": True, "policies": policies})


@app.get("/api/history")
def api_history():
    """
    Query observer/traffic.db for the last 20 window aggregates.
    Returns [{window_end, total_requests}, ...] oldest-first for the chart.
    """
    if not TRAFFIC_DB.exists():
        return jsonify({"ok": True, "history": []})
    try:
        con = sqlite3.connect(str(TRAFFIC_DB))
        cur = con.execute(
            """
            SELECT window_end, SUM(request_count) AS total
            FROM   traffic_edges
            GROUP  BY window_end
            ORDER  BY window_end DESC
            LIMIT  20
            """
        )
        rows = [{"window_end": r[0], "total_requests": r[1]} for r in cur.fetchall()]
        con.close()
        rows.reverse()          # chronological order for the chart
        return jsonify({"ok": True, "history": rows})
    except sqlite3.Error as exc:
        return jsonify({"ok": False, "error": str(exc), "history": []})


if __name__ == "__main__":
    print(f"Dashboard root : {ROOT}")
    print("Open http://localhost:5050 in a browser.")
    app.run(host="0.0.0.0", port=5050, debug=False)
