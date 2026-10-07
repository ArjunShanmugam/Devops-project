from flask import Flask, request, jsonify

app = Flask(__name__)

# In-memory log store (intentionally simple — this is a test service)
logs = []

@app.route("/api/health")
def health():
    return {"status": "healthy"}

@app.route("/api/log", methods=["POST"])
def log_event():
    data = request.get_json(silent=True) or {}
    logs.append(data)
    return {"logged": True}

@app.route("/healthz")
def healthz():
    return {"status": "ok"}

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
