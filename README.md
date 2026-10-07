# Behavior-Derived Zero-Trust Policy Synthesis Engine

## Module 1 — Traffic Observation Pipeline

This module observes service-to-service traffic in an Istio mesh via Prometheus
metrics and produces a traffic graph (`traffic_graph.json`) on a 60-second cycle.

### Prerequisites

- [Docker Desktop](https://www.docker.com/products/docker-desktop/) running
- [kind](https://kind.sigs.k8s.io/) CLI installed
- [istioctl](https://istio.io/latest/docs/setup/getting-started/#download) installed
- [kubectl](https://kubernetes.io/docs/tasks/tools/) installed
- [k6](https://k6.io/docs/get-started/installation/) installed
- Python 3.11+

### Setup

#### 1. Create the Kind cluster

```bash
kind create cluster --name zt-mesh --config infra/kind-config.yaml
```

#### 2. Install Istio (demo profile)

```bash
istioctl install --set profile=demo -y
```

#### 3. Enable sidecar injection on default namespace

```bash
kubectl label namespace default istio-injection=enabled
```

#### 4. Build and load test service images into Kind

```bash
docker build -t service-a:local infra/test-services/service-a/
docker build -t service-b:local infra/test-services/service-b/
docker build -t service-c:local infra/test-services/service-c/

kind load docker-image service-a:local --name zt-mesh
kind load docker-image service-b:local --name zt-mesh
kind load docker-image service-c:local --name zt-mesh
```

#### 5. Deploy test services

```bash
kubectl apply -f infra/test-services/service-a/deployment.yaml
kubectl apply -f infra/test-services/service-b/deployment.yaml
kubectl apply -f infra/test-services/service-c/deployment.yaml
```

#### 6. Verify sidecar injection

Each pod should show 2 containers (app + istio-proxy):

```bash
kubectl get pods -n default -o jsonpath='{range .items[*]}{.metadata.name}{"\t"}{.spec.containers[*].name}{"\n"}{end}'
```

#### 7. Start traffic generation (k6)

Port-forward service-a, then run k6 from the host. The k6 script targets
`http://localhost:8080/trigger`, which reaches service-a via the port-forward:

```bash
kubectl port-forward svc/service-a 8080:8080 &
k6 run infra/k6/traffic-script.js
```

Let k6 run for at least 10 minutes before starting the collector so there is
enough data for a meaningful traffic graph.

#### 8. Port-forward Prometheus

```bash
kubectl port-forward -n istio-system svc/prometheus 9090:9090
```

#### 9. Install Python dependencies

```bash
pip install -r requirements.txt
```

#### 10. Run the observer collector

```bash
python observer/collector.py
```

The collector prints a table of observed traffic edges every 60 seconds and
writes the latest window to `observer/output/traffic_graph.json`.

### Expected output

With k6 traffic flowing through service-a → service-b → service-c, the
collector should show edges like:

```
  Source               Destination          Method   Code   Count    Last Seen
  -----------------------------------------------------------------------
  service-a            service-b            GET      200    ~45      2026-10-06T10:04:58+00:00
  service-a            service-c            GET      200    ~45      2026-10-06T10:04:58+00:00
  service-b            service-c            POST     200    ~45      2026-10-06T10:04:58+00:00
```

### Verify

1. Check `observer/output/traffic_graph.json` exists and has non-empty `edges`.
2. Check `observer/traffic.db` SQLite database has rows in `traffic_edges` table.
