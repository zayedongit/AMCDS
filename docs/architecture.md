# AMCDS Architecture

## System Overview

AMCDS operates as a fully simulated enterprise cybersecurity ecosystem with the following layers:

### 1. Simulation Layer
Generates realistic enterprise behavior including user activity, network traffic, file operations, processes, and email communication. All simulation is deterministic and seed-based for replay.

### 2. Telemetry Engine
Normalizes all simulator output into OCSF-style JSON events and publishes to Kafka topics. Events include simulation metadata (`_sim` field) for replay tracking.

### 3. Messaging Layer (Kafka)
13 topics organized by telemetry type, alerts, incidents, and strategies. KRaft mode (no Zookeeper).

### 4. Agent Layer (Ray)
7 agents running as Ray actors:
- **Identity Agent**: Auth anomaly detection (brute force, credential stuffing)
- **Network Agent**: Traffic analysis (port scanning, SQL injection, data exfiltration)
- **Endpoint Agent**: Process monitoring (ransomware, suspicious execution)
- **Data Agent**: File access monitoring (bulk downloads, unauthorized access)
- **Classifier Agent**: ML-based attack type classification (PyTorch MLP)
- **Business Impact Agent**: Revenue/SLA impact calculation
- **Coordinator Agent**: Incident correlation, Pareto strategy selection

### 5. Attack Engine
Executes multi-stage attack scenarios from YAML configurations. Injects attack events into the telemetry pipeline for detection by monitoring agents.

### 6. Storage Layer
- **PostgreSQL**: Structured incident/alert/strategy storage
- **Neo4j**: Graph-based topology and incident relationships
- **Redis**: Agent state cache and real-time counters

### 7. Dashboard
Next.js 15 frontend with D3.js network visualization, connected to FastAPI backend via REST and WebSocket.

## Data Flow

```
Simulation → Telemetry Engine → Kafka → Detection Agents → Classifier → Correlator → Strategy Engine → Dashboard
                                    ↑
                              Attack Engine
```
