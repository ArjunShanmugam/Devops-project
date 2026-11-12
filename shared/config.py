import os

PROMETHEUS_URL = os.environ.get("PROMETHEUS_URL", "http://localhost:9090")
K8S_NAMESPACE = os.environ.get("K8S_NAMESPACE", "default")
POLL_INTERVAL_SECONDS = int(os.environ.get("POLL_INTERVAL_SECONDS", 60))
MIN_REQUEST_COUNT = int(os.environ.get("MIN_REQUEST_COUNT", 5))
MAX_STALENESS_WINDOWS = int(os.environ.get("MAX_STALENESS_WINDOWS", 3))
STALE_RULE_AGE_WINDOWS = int(os.environ.get("STALE_RULE_AGE_WINDOWS", 10))
GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN", "")
POLICY_REPO_NAME = os.environ.get("POLICY_REPO_NAME", "")
