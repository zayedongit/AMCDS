# System Workflow

## Normal Operation Flow

1. Enterprise Simulator generates topology, users, services
2. User Behavior Engine creates background activity each tick
3. Telemetry Engine normalizes events to OCSF format
4. Events published to Kafka topics
5. Detection Agents consume and analyze telemetry
6. Normal activity generates no alerts — system monitors quietly

## Attack Detection Flow

1. Attack Engine injects malicious events (per scenario YAML)
2. Detection Agents identify anomalies in the telemetry stream
3. Alerts published to `alerts.raw` with MITRE ATT&CK mapping
4. Classifier Agent classifies attack type using MLP model
5. Coordinator correlates alerts into incidents
6. Business Impact Agent calculates revenue/SLA impact
7. Agents propose containment strategies
8. Coordinator selects optimal strategy via Pareto filtering
9. Selected strategy published; simulation state updated
10. Dashboard displays real-time progression
