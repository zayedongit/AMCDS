# AMCDS — Autonomous Multi-Agent Cyber Defense System

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

A fully simulated, production-grade enterprise cybersecurity ecosystem that generates realistic telemetry, runs distributed monitoring agents, detects and classifies cyber threats, correlates incidents, generates containment strategies, and visualizes attacks/defenses — all inside Docker containers.

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    Dashboard (Next.js)                   │
│         localhost:3000 — Real-time Visualization         │
├─────────────────────────────────────────────────────────┤
│                  FastAPI Backend :8080                    │
│        REST API + WebSocket Live Events                  │
├─────────────┬───────────┬──────────┬────────────────────┤
│  PostgreSQL │  Neo4j    │  Redis   │  Apache Kafka      │
│  :5432      │  :7474    │  :6379   │  :9092 (KRaft)     │
├─────────────┴───────────┴──────────┴────────────────────┤
│              Ray-based Monitoring Agents                  │
│  Identity │ Network │ Endpoint │ Data │ Classifier       │
│  Business Impact │ Coordinator                           │
├─────────────────────────────────────────────────────────┤
│              Simulation Engine                           │
│  Topology │ Users │ Behavior │ Telemetry │ Attacks       │
└─────────────────────────────────────────────────────────┘
```

## Quick Start

```bash
# 1. Clone the repository
git clone https://github.com/your-org/amcds-simulation.git
cd amcds-simulation

# 2. Setup (validates Docker, creates .env, builds images)
chmod +x scripts/*.sh
./scripts/setup.sh

# 3. Launch everything
docker compose up

# 4. Access the dashboard
open http://localhost:3000
```

## Services

| Service | URL | Description |
|---------|-----|-------------|
| Dashboard | http://localhost:3000 | Real-time cyber defense visualization |
| API | http://localhost:8080 | FastAPI REST + WebSocket |
| Ray Dashboard | http://localhost:8265 | Ray cluster monitoring |
| Neo4j Browser | http://localhost:7474 | Graph database explorer |
| PostgreSQL | localhost:5432 | Incident/alert storage |
| Redis | localhost:6379 | Agent state cache |
| Kafka | localhost:9092 | Event streaming |

## Simulation Parameters

| Parameter | Default | Description |
|-----------|---------|-------------|
| `SIM_SEED` | 42 | Random seed for deterministic replay |
| `SIM_NUM_USERS` | 100 | Simulated enterprise users |
| `SIM_NUM_HOSTS` | 100 | Simulated endpoints |
| `SIM_NUM_SERVICES` | 10 | Enterprise services |
| `SIM_NUM_SUBNETS` | 5 | Network subnets |
| `SIM_SCENARIO` | baseline_medium | Attack scenario |

## Attack Scenarios

The `baseline_medium` scenario includes 3 concurrent attack chains:

1. **Phishing → Credential Theft → Lateral Movement**
2. **HTTP Exploitation → Privilege Escalation**
3. **Malicious Link → Ransomware Propagation**

## Reset

```bash
./scripts/reset.sh        # Stop + clear all data
docker compose up          # Restart fresh
```

## Development

```bash
# Branch strategy
main     → stable releases
dev      → integration branch
feature/* → new modules

# Run tests
./scripts/test.sh

# Run a specific test
python -m pytest tests/unit/test_topology.py -v
```

## Technology Stack

Python 3.11+ • Ray 2.9+ • FastAPI • Apache Kafka (KRaft) • Docker • PostgreSQL • Redis • Neo4j • React • Next.js 15 • Tailwind CSS v4 • D3.js • scikit-learn • PyTorch • NetworkX • OR-Tools • Faker • Scapy

## License

Apache License 2.0 — see [LICENSE](LICENSE)
