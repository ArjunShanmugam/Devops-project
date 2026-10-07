# Architecture — Behavior-Derived Zero-Trust Policy Synthesis Engine

**Document purpose:** Implementation-ready build specification for an AI coding assistant / code editor. Every module below specifies inputs, outputs, exact data shapes, and the concrete logic needed to implement it — not just goals. Where a design decision had to be made to avoid ambiguity, it is stated explicitly as a decision with rationale, not left open. If something here conflicts with reality once you start building (e.g., a library API differs from what's assumed), stop and flag it rather than silently improvising around it.

---

## 1. Problem Statement

Zero-trust authorization policy in service meshes (Istio `AuthorizationPolicy`, OPA Rego) is hand-authored and static. Once written, it drifts from reality:
- New services ship without matching policy (blocked traffic, or over-broad temporary allow rules).
- Deprecated call paths leave stale `ALLOW` rules in place (unnoticed attack surface growth).
- Service behavior changes faster than anyone revisits the policy files.

**Core idea:** treat authorization policy as a continuously-recomputed artifact derived from *observed* service-to-service traffic, rather than a document maintained by human memory. The system observes real traffic, infers the minimal access policy that traffic implies, diffs it against what is currently enforced, and proposes the delta as a GitHub Pull Request. A human merges the PR to apply the change. The system never applies policy changes directly to the live cluster.

## 2. Non-Goals / Explicit Limitations

- This system does not judge *intent*. If a service calls another due to a bug, the system will propose legalizing that call pattern unless a human rejects the PR. This is a stated limitation, not a hidden flaw — document it in the paper's discussion section.
- This system does not replace mTLS/identity-layer zero trust (handled by Istio's existing `PeerAuthentication`). It only addresses the authorization-policy layer (who is allowed to call whom).
- No automatic merge, ever. Every policy change requires a human-reviewed, human-merged PR.
- Out of scope for v1: multi-cluster federation, ingress/egress gateway policy (internal east-west traffic only), rate limiting, encryption policy.

## 3. Scope Decision: Reconciliation After Merge (resolved — do not re-litigate)

**Decision:** The system's scope ends at "PR merged." A merged PR updates the YAML files in `policy-repo/authz-policies/`. Applying those files to the live cluster is done via a thin, separate sync step (`infra/sync-policies.sh`, described in §9.4) that the developer runs manually or on a schedule — it is NOT an autonomous reconciler watching for merges in real time. This keeps Module 5 scoped to "generate and deliver a reviewable change," which is the actual research contribution, rather than reinventing ArgoCD/Flux. State this explicitly in the paper's scope section: a production deployment of this system would plug into an existing GitOps reconciler (ArgoCD/Flux); building one is out of scope here.

## 4. High-Level Architecture

```
 Kind cluster
 + Istio service mesh
 + test microservices
        |
        | emits telemetry (Prometheus metrics via Istio's demo-profile addon)
        v
 Module 1: Observer  -->  polls Prometheus, builds traffic graph
        |
        | traffic_graph.json
        v
 Module 2: Inferencer          Module 3: Policy Fetcher
 --> minimal policy set        --> current enforced policy
        |                               |
        | inferred_policy/*.yaml        | enforced_policy/*.yaml
        +---------------+---------------+
                        v
         Module 4: Diff Engine  -->  classifies drift, ranks severity
                        |
                        | patch_proposal.json
                        v
         Module 5: GitOps PR Delivery  -->  opens PR with policy YAML diff
                        |
                        | human reviews & merges
                        v
         Policy YAML lands in policy-repo/
         (manual/scheduled sync to cluster - sec 9.4, explicitly out of
          scope as an autonomous step - see sec 3)

 Module 6: Evaluation harness (runs alongside)
 --> injects synthetic drift, measures precision/recall/time-to-detect
```

## 5. Tech Stack (confirmed decisions)

| Layer | Choice | Notes |
|---|---|---|
| Local cluster | Kind (Kubernetes in Docker) | lighter than Minikube, better for repeated resets during Module 6 testing |
| Service mesh | Istio, `demo` profile | installed day 1 — `demo` profile bundles Prometheus + Grafana + Kiali, which is sufficient; do not install a separate Prometheus stack |
| Cloud (later phase) | AWS EC2 (`t3.large`/`t3.xlarge`) running the same Kind+Istio setup | NOT EKS initially |
| Metrics source | Prometheus bundled with Istio's demo profile, querying `istio_requests_total` | already labeled with workload identity |
| Backend language | Python 3.11+ | |
| K8s API access | `kubernetes` Python client (official, `pip install kubernetes`) | |
| Policy format | Istio `AuthorizationPolicy` CRDs (`security.istio.io/v1`) | |
| GitOps delivery | PyGithub (`pip install PyGithub`) | simpler to unit-test than shelling out to `gh` |
| Traffic generation | k6 | scriptable, good for varied/weighted traffic patterns needed by Module 2's thresholds |
| Local tooling | kubectl, istioctl, kind CLI, Helm (optional), k9s (optional, for demo visibility) | |
| Editor | VS Code + Kubernetes extension, YAML extension (Red Hat), GitHub PR extension, Python + Pylance | |

## 6. Repository Structure

```
zt-policy-engine/
├── infra/
│   ├── kind-config.yaml
│   ├── istio/
│   │   └── install-values.yaml        # demo profile overrides, if any
│   ├── test-services/
│   │   ├── service-a/                  # Flask app, see sec 7
│   │   ├── service-b/
│   │   └── service-c/
│   ├── k6/
│   │   └── traffic-script.js           # see sec 7.3
│   └── sync-policies.sh                # see sec 9.4
├── observer/                            # Module 1
│   ├── collector.py
│   ├── prometheus_client.py
│   └── graph_store.py
├── inferencer/                          # Module 2
│   ├── infer_policy.py
│   └── thresholds.py
├── policy_fetcher/                      # Module 3
│   ├── fetch_enforced.py
│   └── k8s_client.py
├── diff_engine/                         # Module 4
│   ├── diff.py
│   └── classify.py
├── gitops/                              # Module 5
│   ├── pr_builder.py
│   └── github_client.py
├── evaluation/                          # Module 6
│   ├── inject_drift.py
│   └── metrics.py
├── policy-repo/
│   └── authz-policies/
│       ├── service-a.yaml
│       ├── service-b.yaml
│       └── service-c.yaml
├── shared/
│   ├── schemas.py
│   └── config.py
├── tests/
│   ├── test_observer.py
│   ├── test_inferencer.py
│   ├── test_diff_engine.py
│   └── test_gitops.py
├── requirements.txt
├── .env.example
└── README.md
```

## 7. Test Environment Specification (previously unspecified — resolved)

**Decision:** three Flask-based microservices, deliberately simple, so the project's complexity lives in the policy engine, not the test apps.

- **service-a**: calls service-b (`GET /api/items`) and service-c (`GET /api/health`).
- **service-b**: calls service-c (`POST /api/log`). Exposes `GET /api/items` and `GET /api/items/{id}`.
- **service-c**: no outbound calls. Exposes `GET /api/health` and `POST /api/log`.

Each service: a single-file Flask app (`app.py`), a `Dockerfile`, and a `deployment.yaml` + `service.yaml` for Kubernetes. Each namespace-scoped with its own Kubernetes ServiceAccount (`service-a-sa`, `service-b-sa`, `service-c-sa`) — this matters because Module 2 needs real ServiceAccount-to-workload mappings, not assumed ones.

### 7.1 Example: service-a `app.py`

```python
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
```

service-b and service-c follow the same pattern (Flask, port 8080, a `/healthz` endpoint, and the specific routes listed above). The editor should fill these in analogously — not redesign the call graph.

### 7.2 Kubernetes manifests (per service)

```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: service-a-sa
  namespace: default
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: service-a
  namespace: default
spec:
  replicas: 1
  selector:
    matchLabels:
      app: service-a
  template:
    metadata:
      labels:
        app: service-a
      annotations:
        sidecar.istio.io/inject: "true"
    spec:
      serviceAccountName: service-a-sa
      containers:
        - name: service-a
          image: service-a:local
          ports:
            - containerPort: 8080
---
apiVersion: v1
kind: Service
metadata:
  name: service-a
  namespace: default
spec:
  selector:
    app: service-a
  ports:
    - port: 8080
      targetPort: 8080
```

Replicate for service-b and service-c with matching names. The `default` namespace must have the label `istio-injection=enabled` applied once (`kubectl label namespace default istio-injection=enabled`) — the per-pod annotation above is a belt-and-suspenders confirmation, the namespace label is what actually drives injection.

### 7.3 Traffic Generation (k6)

```javascript
import http from 'k6/http';
import { sleep } from 'k6';

export const options = {
  scenarios: {
    steady_traffic: {
      executor: 'constant-vus',
      vus: 3,
      duration: '10m',
    },
  },
};

export default function () {
  http.get('http://service-a.default.svc.cluster.local:8080/trigger');
  sleep(Math.random() * 2 + 1); // 1-3s between calls, varied timing
}
```

Run this from inside the cluster (as a Job) or port-forwarded from the host — document whichever you choose in the README. The varied sleep interval matters: Module 2's thresholds need traffic with some natural variance to be a meaningful test, not a perfectly uniform synthetic pattern.

## 8. Data Contracts Between Modules

All inter-module data is JSON/YAML on disk. File-based, not in-process objects — this keeps each module independently testable and gives you artifacts to show faculty at each milestone.

### 8.1 Traffic Graph (Module 1 output → `observer/output/traffic_graph.json`)

**Note: path granularity is dropped — see §9.1.2 for why.**

```json
{
  "window_start": "2026-10-06T10:00:00Z",
  "window_end": "2026-10-06T10:05:00Z",
  "edges": [
    {
      "source_workload": "service-a",
      "destination_workload": "service-b",
      "method": "GET",
      "response_code": "200",
      "request_count": 142,
      "last_seen": "2026-10-06T10:04:58Z"
    }
  ]
}
```

### 8.2 Inferred Policy (Module 2 output → `inferred_policy/<service>.yaml`)

```yaml
apiVersion: security.istio.io/v1
kind: AuthorizationPolicy
metadata:
  name: service-b-policy
  namespace: default
spec:
  selector:
    matchLabels:
      app: service-b
  action: ALLOW
  rules:
    - from:
        - source:
            principals: ["cluster.local/ns/default/sa/service-a-sa"]
      to:
        - operation:
            methods: ["GET"]
```

(no `paths` field — v1 policy granularity is service + method only, per §9.1.2)

### 8.3 Enforced Policy (Module 3 output → `enforced_policy/<service>.yaml`)

Same schema as §8.2, fetched live from the cluster.

### 8.4 Patch Proposal (Module 4 output → `patch_proposal.json`)

```json
{
  "generated_at": "2026-10-06T10:10:00Z",
  "findings": [
    {
      "service": "service-b",
      "type": "over_permissive",
      "detail": "Enforced policy allows service-c -> service-b on POST, but no traffic observed in last 10 windows.",
      "severity": "medium",
      "suggested_action": "remove_rule",
      "rule_ref": {
        "source_principal": "cluster.local/ns/default/sa/service-c-sa",
        "methods": ["POST"]
      }
    },
    {
      "service": "service-b",
      "type": "under_permissive",
      "detail": "Observed traffic service-a -> service-b on GET, no matching enforced rule.",
      "severity": "high",
      "suggested_action": "add_rule",
      "rule_ref": {
        "source_principal": "cluster.local/ns/default/sa/service-a-sa",
        "methods": ["GET"]
      }
    }
  ]
}
```

## 9. Module Specifications

### Module 1 — Traffic Observation Pipeline

**9.1.1 Infra setup**
1. `infra/kind-config.yaml`: single control-plane + 2 worker nodes.
2. `istioctl install --set profile=demo -y`.
3. `kubectl label namespace default istio-injection=enabled`.
4. Deploy the three test services (§7). Confirm injection: `kubectl get pods -n default -o jsonpath='{range .items[*]}{.metadata.name}{"\t"}{.spec.containers[*].name}{"\n"}{end}'` — each line must show two containers.
5. Run the k6 script (§7.3) for at least 10 minutes before testing Module 1's collector, so there's enough data for a meaningful graph.

**9.1.2 Exact Prometheus query**

Istio's demo profile exposes Prometheus at `http://prometheus.istio-system:9090` inside the cluster (port-forward for local dev: `kubectl port-forward -n istio-system svc/prometheus 9090:9090`).

`observer/prometheus_client.py` queries the **range query** endpoint:

```
GET http://localhost:9090/api/v1/query_range
  ?query=sum(increase(istio_requests_total{reporter="destination"}[1m])) by (source_workload, destination_workload, request_method, destination_service, response_code)
  &start=<window_start_unix>
  &end=<window_end_unix>
  &step=60s
```

Notes on this query, stated explicitly so the editor does not substitute a different one:
- `reporter="destination"` is required — Istio emits the same metric from both source and destination sidecars; using only one reporter avoids double-counting edges.
- `increase(...[1m])` over the window, summed, gives a request count per label-set per window — matches the `request_count` field in §8.1.
- Istio's `istio_requests_total` metric does not include a URL-path label by default (it has `destination_service`, `request_method`, but not path) — path-level granularity would require Envoy access logs, not this metric alone.

**Resolved design decision:** for v1, treat `method` + `destination_service` as the policy granularity (service-level + HTTP-method-level authorization), and **drop path-level granularity** entirely from the inferred policy's `to.operation` block. This is a legitimate, citable simplification — document it as a stated limitation in the paper ("path-level policy requires access-log-based ingestion, left as future work") rather than attempting to parse Envoy access logs in v1, which requires materially more infrastructure (log shipping, parsing) for marginal benefit to the core contribution. Path-level granularity later would require enabling Envoy access logging (`meshConfig.accessLogFile`) and shipping logs to a collector (Fluent Bit → file or Loki) — explicitly out of scope for v1.

**9.1.3 Collector logic (`observer/collector.py`)**
1. Run on a fixed interval (default: every 60s, configurable via `shared/config.py: POLL_INTERVAL_SECONDS`).
2. Each run queries the last `POLL_INTERVAL_SECONDS` window via §9.1.2's query.
3. Append results to a local SQLite table (`graph_store.py`): columns `(window_start, window_end, source_workload, destination_workload, method, response_code, request_count, last_seen)`. SQLite, not an in-memory list — you want this queryable across runs for Module 6's time-to-detect measurement and Module 4's stale-rule-age check.
4. Also write the latest window's result to `traffic_graph.json` for the other modules to consume directly.

**9.1.4 Error handling**
- Prometheus unreachable: log the failure, skip this cycle, retry next interval. Do not crash the collector loop.
- Empty result set: valid state (no traffic in window) — write an empty `edges: []`, not an error.

**Module 1 "done" checkpoint:** cluster running, sidecars injected, k6 traffic flowing, collector producing non-empty `traffic_graph.json` on a 60s cycle, visible via a simple printed table for the faculty demo.

### Module 2 — Least-Privilege Policy Inference

**9.2.1 Thresholds (previously unspecified — resolved defaults)**

`inferencer/thresholds.py`:
```python
MIN_REQUEST_COUNT = 5        # per window, below this an edge is noise
MAX_STALENESS_WINDOWS = 3    # edge must appear in at least 1 of the last 3 windows
```

Rationale to state in the paper: `MIN_REQUEST_COUNT = 5` filters single-request anomalies (a curl test, a health-check fluke) without requiring high sustained volume, appropriate for a low-traffic demo environment — tune upward for production-scale traffic. `MAX_STALENESS_WINDOWS = 3` (with a 60s window default, that's a 3-minute lookback) balances responsiveness against not reacting to single missed polling cycles.

**9.2.2 Logic (`infer_policy.py`)**
1. Query the SQLite store for all edges across the last `MAX_STALENESS_WINDOWS` windows.
2. Group by `(source_workload, destination_workload, method)`; sum `request_count` across windows; keep the max `last_seen`.
3. Keep only groups where summed `request_count >= MIN_REQUEST_COUNT`.
4. For each surviving group, resolve `source_workload` → ServiceAccount name via `kubernetes` client: `CoreV1Api().list_namespaced_pod(namespace, label_selector=f"app={source_workload}")`, read `.spec.service_account_name` from the first matching pod.
5. Build the principal string: `f"cluster.local/ns/{namespace}/sa/{service_account_name}"`.
6. Group surviving rules by `destination_workload`, emit one `AuthorizationPolicy` YAML per destination (§8.2 schema).

### Module 3 — Current Policy Fetcher

**9.3.1 Logic (`fetch_enforced.py`)**
```python
from kubernetes import client, config

config.load_kube_config()
api = client.CustomObjectsApi()
policies = api.list_namespaced_custom_object(
    group="security.istio.io",
    version="v1",
    namespace="default",
    plural="authorizationpolicies",
)
```
Normalize each returned object's `spec.rules` into the same per-service structure Module 2 produces (§8.3), so Module 4 can diff them at the `(source_principal, method)` tuple level directly.

**9.3.2 Error handling**
- If no `AuthorizationPolicy` objects exist yet (first run, nothing enforced): return an empty policy set per service, not an error — this is the expected starting state, and Module 4 should correctly classify everything as `under_permissive` on a first run.

### Module 4 — Diff & Classification Engine

**9.4.1 Logic (`diff.py` + `classify.py`)**
1. For each service present in either Module 2's or Module 3's output, build two sets of `(source_principal, method)` tuples: `inferred_rules` and `enforced_rules`.
2. `over_permissive = enforced_rules - inferred_rules`
3. `under_permissive = inferred_rules - enforced_rules`
4. Severity assignment (resolved default):
   - All `under_permissive` findings → `"high"` (breakage risk).
   - `over_permissive` findings → `"medium"` by default; escalate to `"high"` if the enforced rule's corresponding traffic has been absent for more than `STALE_RULE_AGE_WINDOWS = 10` consecutive observed windows (check this against the SQLite history, not just the latest window).
5. Emit `patch_proposal.json` (§8.4).

**9.4.2 Testing before moving to Module 5 — required gate**
- Manually `kubectl apply` an extra rule not reflected in current traffic → confirm it surfaces as `over_permissive`.
- Manually delete a rule for traffic that is actively flowing → confirm it surfaces as `under_permissive`.
- Do not proceed to Module 5 until both cases are verified correct.

### Module 5 — GitOps PR Delivery

**9.5.1 Exact call sequence (previously unspecified — resolved)**

Using PyGithub, against a repo you control (`shared/config.py: POLICY_REPO_NAME`, e.g. `"yourname/zt-policy-repo"` — can be a separate repo or a subfolder-based repo, your choice, just keep it consistent):

```python
from github import Github
import os, datetime

gh = Github(os.environ["GITHUB_TOKEN"])
repo = gh.get_repo(os.environ["POLICY_REPO_NAME"])

base = repo.get_branch("main")
branch_name = f"policy-sync-{datetime.datetime.utcnow().strftime('%Y%m%d-%H%M%S')}"
repo.create_git_ref(ref=f"refs/heads/{branch_name}", sha=base.commit.sha)

for finding in findings:
    file_path = f"authz-policies/{finding['service']}.yaml"
    new_content = build_updated_yaml(finding)  # apply add/remove rule to existing YAML
    try:
        existing = repo.get_contents(file_path, ref=branch_name)
        repo.update_file(file_path, f"policy sync: {finding['type']} on {finding['service']}",
                          new_content, existing.sha, branch=branch_name)
    except Exception:
        repo.create_file(file_path, f"policy sync: create policy for {finding['service']}",
                          new_content, branch=branch_name)

pr_body = build_pr_description(findings)  # human-readable summary, one bullet per finding
repo.create_pull(title=f"Policy sync {branch_name}", body=pr_body,
                  head=branch_name, base="main")
```

**9.5.2 Error handling**
- Branch name collision (two runs in the same second): catch the `GithubException` on `create_git_ref`, append a short random suffix, retry once.
- GitHub API rate limit: catch `RateLimitExceededException`, log, exit the run cleanly (don't retry in a tight loop) — next scheduled run picks up current drift again.
- No findings (nothing to propose): skip PR creation entirely, log "no drift detected," exit 0.

**9.5.3 PR description format**

```
## Policy Sync Proposal

Generated: <timestamp>

### High severity (breakage risk)
- **service-b**: traffic observed from service-a (GET) with no matching enforced rule. Adding rule.

### Medium severity (stale access)
- **service-b**: enforced rule allows service-c (POST), no matching traffic in last 10 windows. Removing rule.

Review each change against the linked traffic evidence before merging. This PR was generated automatically from observed mesh traffic — it does not account for intent, only behavior.
```

### Module 6 — Evaluation & Benchmarking

**9.6.1 Drift injection (previously vague — resolved concrete mechanics)**

`evaluation/inject_drift.py` runs two scripted scenarios against the live test environment:

- **Scenario A (under-permissive injection):** add a new outbound call to one test service that does not already exist as an edge (e.g., have service-a additionally call service-c's `/api/log` endpoint, which it previously never did), redeploy that one service (`kubectl rollout restart deployment/service-a`), let k6 traffic run, then let Modules 1→4 execute. Record wall-clock time from redeploy to the new edge appearing in `patch_proposal.json` as `under_permissive`.
- **Scenario B (over-permissive injection):** manually `kubectl apply` an extra `AuthorizationPolicy` rule for an edge that does not exist in current traffic (e.g., allow service-c → service-a, which never happens). Record wall-clock time from `kubectl apply` to it appearing as `over_permissive`.

**9.6.2 Metrics (`metrics.py`)**
- **Precision** = (findings that match an intentionally-injected scenario) / (total findings produced during the test run).
- **Recall** = (injected scenarios correctly detected) / (total injected scenarios).
- **Time-to-detect** = timestamp of finding in `patch_proposal.json` minus timestamp of the injection action, bounded below by `POLL_INTERVAL_SECONDS` (report this bound explicitly — it's a property of the polling architecture, not a flaw to hide).
- Run each scenario at least 5 times for a reportable average, not a single anecdotal run.

**9.6.3 Baseline comparison**
Do not fabricate a specific "manual detection time" statistic. Instead, cite the Related Work papers' stated review cadences where available, or explicitly state a reasoned assumption (e.g., "assuming a quarterly manual audit cadence, as is common in the surveyed literature, mean time-to-detect for stale rules is on the order of weeks to months") and label it clearly as an assumption, not a measured result.

## 10. Configuration (`shared/config.py`)

```python
import os

PROMETHEUS_URL = os.environ.get("PROMETHEUS_URL", "http://localhost:9090")
K8S_NAMESPACE = os.environ.get("K8S_NAMESPACE", "default")
POLL_INTERVAL_SECONDS = int(os.environ.get("POLL_INTERVAL_SECONDS", 60))
MIN_REQUEST_COUNT = int(os.environ.get("MIN_REQUEST_COUNT", 5))
MAX_STALENESS_WINDOWS = int(os.environ.get("MAX_STALENESS_WINDOWS", 3))
STALE_RULE_AGE_WINDOWS = int(os.environ.get("STALE_RULE_AGE_WINDOWS", 10))
GITHUB_TOKEN = os.environ["GITHUB_TOKEN"]
POLICY_REPO_NAME = os.environ["POLICY_REPO_NAME"]
```

`.env.example` should list all of the above with placeholder values; `GITHUB_TOKEN` and `POLICY_REPO_NAME` have no defaults and must be set, everything else has a sane default.

## 11. AWS Deployment Notes

- Get Modules 1–5 fully working on local Kind first. Do not provision AWS until the local pipeline is stable.
- Provision one EC2 instance (`t3.large`/`t3.xlarge`), install Docker + Kind + Istio identically to local, point your local kubeconfig context at it over SSH tunnel or copy the remote kubeconfig down.
- EKS migration: optional, Phase 2 only, if the paper's evaluation section specifically benefits from "managed Kubernetes" framing. Added cost (~$0.10/hr control plane) and complexity (VPC/IAM/security groups) — do not pursue unless there's a concrete reason to.
- Check AWS Educate / GitHub Student Developer Pack for credits before running anything that incurs cost.

## 12. Development Order (confirmed)

1 → 3 → 2 → 4 → 5, with 6 running in parallel once Module 4 is verified correct (§9.4.2). Do not start Module 5 before Module 4's two manual test cases both pass.

## 13. Related Work (for paper framing — not build scope)

- **"A Runtime Trust Evaluation Mechanism in the Service Mesh Architecture"** (IEEE, 2023) — dynamic trust *scoring*, not policy generation. Closest anchor paper.
- **"Enhancing Microservice Security Through Vulnerability-Driven Trust in the Service Mesh Architecture"** (Sensors, 2025) — vulnerability-driven trust signal, not traffic-behavior-driven. Differentiator for this project.
- **eZTrust** — eBPF-based perimeterization enforcement; policy is still externally defined, not inferred from behavior. Nearest prior system.
- NIST SP 800-204B/800-204C — standards backing for service-mesh authorization enforcement and policy-as-code/GitOps patterns.

## 14. Summary for the Code Editor

Build order: Kind+Istio cluster → test services (§7, exact Flask apps and call graph given) + k6 traffic (§7.3) → Observer (§9.1, exact PromQL given) → Policy Fetcher (§9.3) → Inferencer (§9.2, exact thresholds given) → Diff Engine (§9.4, exact severity rules given) → GitOps PR delivery (§9.5, exact PyGithub call sequence given) → Evaluation harness (§9.6, exact drift scenarios given).

All inter-module data uses the schemas in §8 exactly as specified, with the path-granularity simplification from §9.1.2 applied consistently across every module — do not reintroduce path-level fields without also building Envoy access-log ingestion, which is explicitly out of scope. Do not build an autonomous post-merge reconciler (§3) — that is intentionally out of scope. If any step's real-world behavior (library version, API response shape) differs from what's assumed here, stop and flag it rather than silently working around it.
