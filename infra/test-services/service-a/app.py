from flask import Flask
import requests
import os

app = Flask(__name__)
SERVICE_B_URL = os.environ.get("SERVICE_B_URL", "http://service-b:8080")
SERVICE_C_URL = os.environ.get("SERVICE_C_URL", "http://service-c:8080")

@app.route("/trigger")
def trigger():
    items = requests.get(f"{SERVICE_B_URL}/api/items", timeout=5).json()
    health = requests.get(f"{SERVICE_C_URL}/api/health", timeout=5).json()
    return {"items": items, "health": health}

@app.route("/healthz")
def healthz():
    return {"status": "ok"}

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
