# Behavior-Derived Zero-Trust Policy Synthesis Engine

An automated policy engine that observes live microservice traffic in an Istio service mesh, infers least-privilege `AuthorizationPolicy` CRDs, diffs them against enforced cluster policies to identify architectural drift, and delivers remediation Pull Requests via GitOps without ever making unreviewed live mutations.

---

## 🏛️ Pipeline Architecture

```
                    ┌────────────────────────────┐
                    │ Kind + Istio Service Mesh  │
                    │  (service-a, -b, -c pods)  │
                    └─────────────┬──────────────┘
                                  │ Prometheus telemetry
                                  ▼
                    ┌────────────────────────────┐
                    │    Module 1: Observer      │
                    │    observer/collector.py   │
                    └─────────────┬──────────────┘
                                  │ observer/traffic.db & traffic_graph.json
                 ┌────────────────┴────────────────┐
                 ▼                                 ▼
   ┌────────────────────────────┐    ┌────────────────────────────┐
   │    Module 2: Inferencer    │    │ Module 3: Policy Fetcher   │
   │ inferencer/infer_policy.py │    │ policy_fetcher/            │
   └─────────────┬──────────────┘    │   fetch_enforced.py        │
                 │                   └─────────────┬──────────────┘
                 │ inferred_policy/                │ enforced_policy/
                 └────────────────┬────────────────┘
                                  ▼
                    ┌────────────────────────────┐
                    │   Module 4: Diff Engine    │
                    │    diff_engine/diff.py     │
                    └─────────────┬──────────────┘
                                  │ patch_proposal.json
                                  ▼
                    ┌────────────────────────────┐
                    │   Module 5: GitOps PR      │
                    │   gitops/pr_builder.py     │
                    └─────────────┬──────────────┘
                                  │ Pull Request (Human Review)
                                  ▼
                    ┌────────────────────────────┐
                    │   policy-repo/ (GitOps)    │
                    └────────────────────────────┘
```

---

## 📦 Project Modules & Status

| Module | Purpose | Key File(s) | Status |
|---|---|---|---|
| **Module 1: Observer** | Polls Prometheus every 60s for `istio_requests_total`, stores in SQLite | `observer/collector.py`, `observer/collect.py` | ✅ 100% Complete |
| **Module 2: Inferencer** | Filters noise (`MIN_REQUEST_COUNT=5`), maps pods to SAs, generates `AuthorizationPolicy` YAMLs | `inferencer/infer_policy.py` | ✅ 100% Complete |
| **Module 3: Policy Fetcher** | Queries live Kubernetes cluster for Istio `AuthorizationPolicy` CRDs and normalizes | `policy_fetcher/fetch_enforced.py` | ✅ 100% Complete |
| **Module 4: Diff Engine** | Computes `over_permissive` and `under_permissive` drift with staleness severity | `diff_engine/diff.py`, `diff_engine/classify.py` | ✅ 100% Complete |
| **Module 5: GitOps PR** | Commits policy deltas to a dated branch and opens a GitHub Pull Request | `gitops/pr_builder.py`, `gitops/open_pr.py` | ✅ 100% Complete |
| **Module 6: Evaluation** | Injects synthetic drift (scenarios A & B) and measures precision, recall, and time-to-detect | `evaluation/inject_drift.py`, `evaluation/metrics.py` | ✅ 100% Complete |
| **Unified Orchestrator** | Executes the full pipeline in sequence (`--once`, `--skip-pr`, `--dry-run`) | `run_pipeline.py` | ✅ 100% Complete |
| **Modern Dashboard UI** | Clean light enterprise UI with D3 area chart, donut chart, drift table, and activity feed | `dashboard/server.py`, `dashboard/index.html` | ✅ 100% Complete |
| **Unit Test Suite** | 21 comprehensive unit tests covering all modules | `tests/` | ✅ 100% (21/21 Passing) |

---

## 🚀 Quickstart & Setup

### 1. Prerequisites
- Python 3.11+
- Docker Desktop
- `kind`, `kubectl`, `istioctl`, and `k6`

### 2. Install Python Dependencies
```bash
pip install -r requirements.txt
```

### 3. Configure Environment Variables
Copy `.env.example` to `.env` and fill in your values:
```bash
cp .env.example .env
```
Key settings:
- `PROMETHEUS_URL=http://localhost:9090`
- `K8S_NAMESPACE=default`
- `POLL_INTERVAL_SECONDS=60`
- `GITHUB_TOKEN=<your_personal_access_token>` (only required for Module 5 PR creation)
- `POLICY_REPO_NAME=<your_user_or_org>/<repo_name>`

---

## 🧪 Running the Test Suite

Run all 21 automated unit tests across all modules:
```bash
python -m unittest discover -s tests
```
Output:
```
Ran 21 tests in 4.148s
OK
```

---

## 🏃 Running the Full Pipeline

### Run Once in Dry-Run Mode (Safe, no writes or PRs)
```bash
python run_pipeline.py --once --dry-run
```

### Run Once Locally (Without opening GitHub PRs)
```bash
python run_pipeline.py --once --skip-pr
```

### Run Continuous Polling Loop
```bash
python run_pipeline.py --loop --skip-pr
```

### Run with GitOps PR Delivery Enabled
```bash
export GITHUB_TOKEN="ghp_xxx"
export POLICY_REPO_NAME="myorg/zt-policy-repo"
python run_pipeline.py --once
```

---

## 📊 Modern Dashboard UI (Template Design)

Start the live web dashboard on port `5050`:
```bash
python dashboard/server.py
```
Open **[http://localhost:5050](http://localhost:5050)** in your browser.

Features:
- **Clean SaaS Light Theme**: Pure white card layout with subtle shadows and rounded corners
- **Left Navigation**: Shield logo with active indicators for Dashboard, Traffic, Policies, Findings, GitOps
- **4 Real-Time Metrics**: Active Services, Enforced Policies, Drift Findings, Open PR Proposals
- **D3.js Traffic Volume Wave**: Area chart plotting request throughput across time windows
- **D3.js Policy Donut Chart**: Visual distribution of compliant vs. over-permissive vs. under-permissive rules
- **Active Drift Table**: Colored severity pills (Red=High, Yellow=Medium, Blue=Low) with direct remediation actions
- **Live Activity Feed**: Real-time audit log of collector cycles and drift findings

---

## 🔬 Running Individual Modules

### Module 1 — Traffic Observer
```bash
python observer/collector.py
```

### Module 2 — Policy Inferencer
```bash
# Infer policies from traffic.db and write to inferred_policy/
python inferencer/infer_policy.py

# Or dry-run without writing files:
python inferencer/infer_policy.py --dry-run
```

### Module 3 — Policy Fetcher
```bash
# Fetch live AuthorizationPolicies from Kubernetes default namespace
python policy_fetcher/fetch_enforced.py
```

### Module 4 — Diff Engine
```bash
# Diff inferred_policy/summary.json against enforced_policy/summary.json
python diff_engine/diff.py
```

### Module 5 — GitOps PR Delivery
```bash
python gitops/pr_builder.py
```

### Module 6 — Evaluation & Benchmarking
```bash
# Run Scenario A (under_permissive injection) 5 times
python evaluation/inject_drift.py --scenario A --runs 5

# Run Scenario B (over_permissive injection) 5 times
python evaluation/inject_drift.py --scenario B --runs 5

# Run both scenarios and generate benchmark results
python evaluation/inject_drift.py --scenario both --runs 5
```
Results will be printed as a formatted table and saved to `evaluation/results.json`.

---

## ☸️ Infrastructure & Kubernetes Deployment

### 1. Create Kind Cluster & Install Istio
```bash
kind create cluster --name zt-mesh --config infra/kind-config.yaml
istioctl install --set profile=demo -y
kubectl label namespace default istio-injection=enabled
```

### 2. Build & Deploy Test Services
```bash
docker build -t service-a:local infra/test-services/service-a/
docker build -t service-b:local infra/test-services/service-b/
docker build -t service-c:local infra/test-services/service-c/

kind load docker-image service-a:local --name zt-mesh
kind load docker-image service-b:local --name zt-mesh
kind load docker-image service-c:local --name zt-mesh

kubectl apply -f infra/test-services/service-a/deployment.yaml
kubectl apply -f infra/test-services/service-b/deployment.yaml
kubectl apply -f infra/test-services/service-c/deployment.yaml
```

### 3. Port-Forward Services & Generate Traffic
```bash
# Port-forward service-a
kubectl port-forward svc/service-a 8080:8080

# In another terminal, run k6 load traffic
k6 run infra/k6/traffic-script.js

# Port-forward Prometheus
kubectl port-forward -n istio-system svc/prometheus 9090:9090
```

### 4. Sync Approved Policies to Cluster
When a PR is approved and merged, sync policies to the cluster:
```bash
# Linux / macOS
bash infra/sync-policies.sh

# Windows PowerShell
.\infra\sync-policies.ps1
```
