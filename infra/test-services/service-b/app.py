from flask import Flask, request, jsonify
import requests
import os

app = Flask(__name__)
SERVICE_C_URL = os.environ.get("SERVICE_C_URL", "http://service-c:8080")

# Sample data for /api/items
ITEMS = [
    {"id": 1, "name": "item-1"},
    {"id": 2, "name": "item-2"},
    {"id": 3, "name": "item-3"},
]

@app.route("/api/items")
def get_items():
    # service-b calls service-c POST /api/log on each request
    try:
        requests.post(f"{SERVICE_C_URL}/api/log",
                       json={"event": "items_requested"}, timeout=5)
    except Exception:
        pass  # logging is best-effort
    return jsonify(ITEMS)

@app.route("/api/items/<int:item_id>")
def get_item(item_id):
    for item in ITEMS:
        if item["id"] == item_id:
            return jsonify(item)
    return jsonify({"error": "not found"}), 404

@app.route("/healthz")
def healthz():
    return {"status": "ok"}

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
