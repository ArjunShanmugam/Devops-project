"""
dashboard/server.py

Minimal Flask server for the Module 1 traffic-observation demo dashboard.
Serves index.html and proxies traffic_graph.json to the browser.

Routes:
  GET /          -> dashboard/index.html
  GET /api/graph -> reads observer/output/traffic_graph.json fresh on every
                    request (no caching) and returns it as JSON.

Run with:
  python dashboard/server.py

Port: 5050 (does not conflict with service-a:8080 or prometheus:9090).

This file does NOT touch any file under observer/, shared/, or infra/.
"""

import json
from pathlib import Path

from flask import Flask, jsonify, send_from_directory

# Resolve relative to this file so the server can be launched from any cwd.
HERE = Path(__file__).parent.resolve()
GRAPH_JSON = HERE.parent / "observer" / "output" / "traffic_graph.json"

app = Flask(__name__, static_folder=None)


@app.get("/")
def index():
    """Serve the dashboard HTML."""
    return send_from_directory(str(HERE), "index.html")


@app.get("/api/graph")
def api_graph():
    """
    Read traffic_graph.json fresh off disk on every request.
    Returns the JSON as-is. If missing or malformed, returns a safe
    empty-graph response so the frontend degrades gracefully.
    """
    try:
        with open(GRAPH_JSON, "r", encoding="utf-8-sig") as fh:
            data = json.load(fh)
        data["ok"] = True
        return jsonify(data)
    except FileNotFoundError:
        return jsonify({
            "ok": False,
            "error": "traffic_graph.json not found — is collector.py running?",
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


if __name__ == "__main__":
    print(f"Dashboard reading from: {GRAPH_JSON}")
    print("Open http://localhost:5050 in a browser.")
    app.run(host="0.0.0.0", port=5050, debug=False)
