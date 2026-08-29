# SENTINEL LAB

SENTINEL LAB is a self-contained DDoS attack-simulation, detection, and threat-intelligence platform built for security research and learning.

> **Safety:** The attack environment is isolated and designed to prevent traffic from reaching external hosts.

## Overview

* **DDoS Simulation** — HTTP flood, Slowloris, UDP flood, and TCP exhaustion
* **Detection & Defense** — IsolationForest anomaly detection with adaptive rate limiting
* **Observability** — Prometheus and Grafana monitoring
* **Threat Intelligence** — Public threat-feed ingestion with REST/WebSocket APIs
* **3D Visualization** — Globe-based visualization of synthetic attacker locations
* **Benchmarking** — Record/replay and automated reports
* **Kubernetes** — Deployment manifests with network-isolation policies

## Architecture

```text
Attackers
   │
   ▼
Isolated Target Network
   │
   ├── Web / TCP / UDP Services
   ├── Rate Limiter
   ├── Defense Engine
   └── Suricata / Wazuh
            │
            ▼
     Prometheus + Grafana

Threat Intelligence
   │
   ├── Public Threat Feeds
   ├── PostgreSQL
   ├── Redis
   └── REST / WebSocket API
            │
            ▼
      React Dashboard
```

The attacker and target networks are isolated at the infrastructure level using Docker internal networks and Kubernetes network policies.

## Project Structure

```text
attackers/              DDoS simulation modules
targets/                Web, TCP, and UDP target services
defense/                Detection and adaptive mitigation
observability/          Prometheus and Grafana configuration
services/threat-intel/  Threat intelligence service
dashboard/              React + TypeScript dashboard
globe/                  3D attacker visualization
reports/                Benchmark report generation
infra/                  Kubernetes and Terraform configuration
tests/                  Isolation and project tests
```

## Tech Stack

**Backend:** Python, FastAPI
**Frontend:** React, TypeScript, Tailwind CSS
**Security:** IsolationForest, Suricata, Wazuh
**Data:** PostgreSQL, Redis
**Monitoring:** Prometheus, Grafana
**Infrastructure:** Docker, Kubernetes, Terraform
**Visualization:** Three.js / React Three Fiber

## Setup

Requires **Docker Desktop** or **Docker Engine with Compose v2**.

```bash
git clone <repository-url>
cd ddos-based-attacks

# Verify network isolation
bash tests/test_network_isolation.sh

# Start targets and monitoring
docker compose up -d --build web lb tcp-service dns-udp prometheus grafana
```

* Grafana: `http://localhost:3000`
* Prometheus: `http://localhost:9090`

## Running a Simulation

First, create a legitimate control run and train the classifier:

```bash
docker compose --profile legit-load run --rm legit-load

docker compose run --rm --entrypoint python \
  defense-engine classifier/train.py \
  --legit-runs legit_load_control_run

docker compose restart defense-engine
docker compose up -d --build defense-engine rate-limiter
```

Run an isolated attack scenario:

```bash
docker compose --profile attack-http-flood run --rm attacker-http-flood
docker compose --profile attack-slowloris run --rm attacker-slowloris
docker compose --profile attack-udp-flood run --rm attacker-udp-flood
docker compose --profile attack-tcp-exhaustion run --rm attacker-tcp-exhaustion
```

Recorded runs can be replayed for repeatable benchmarking.

## Threat Intelligence

The separate Threat Intelligence module ingests public feeds including:

* ThreatFox
* CISA KEV
* Spamhaus DROP
* Emerging Threats Open
* NVD CVE
* AbuseIPDB *(optional)*
* AlienVault OTX *(optional)*

Threat data is normalized and exposed through REST and WebSocket APIs, with PostgreSQL storage and Redis caching.

## Dashboard

The React dashboard provides:

* Global Threat Intelligence
* 3D threat visualization
* Threat feed and filtering
* Analytics
* Alerts
* Sandbox Lab controls
* Service health monitoring

Start the dashboard with:

```bash
docker compose up -d --build dashboard
```

Dashboard: `http://localhost:8080`

## Kubernetes

Kubernetes manifests are provided under `infra/k8s/`, including network-isolation policies and verification jobs.

```bash
kubectl apply -f infra/k8s/00-namespace-and-networkpolicy.yaml
kubectl apply -f infra/k8s/verify-isolation-job.yaml

kubectl wait --for=condition=complete job/verify-isolation \
  -n sentinel-lab --timeout=60s

---

**Built with Python, React, TypeScript, Docker, Kubernetes, and security-focused observability tools.**
