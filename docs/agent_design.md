# Agent Design

## Detection Agents

Each detection agent follows the BaseAgent pattern:
1. **Consume** telemetry from subscribed Kafka topics
2. **Analyze** events using rule-based and statistical methods
3. **Detect** anomalies via thresholds, patterns, and ML
4. **Alert** by publishing to `alerts.raw` topic
5. **Propose** containment strategies to `strategies.proposed`

## Classification

The Classifier Agent uses a 3-layer MLP (PyTorch, CPU-only):
- Input: 8 features extracted from alert data
- Hidden: 32 → 16 neurons with ReLU + Dropout
- Output: 7 attack classes with Softmax
- Trained on synthetic balanced dataset during startup

## Incident Correlation

Groups alerts into incidents using:
- **Temporal proximity**: 300-second sliding window
- **Shared actors**: Same source IP or user ID
- **Kill chain progression**: MITRE ATT&CK tactic ordering
- **Confidence scoring**: Combined alert confidence with decay

## Strategy Selection

Pareto-optimal strategy selection:
1. Collect proposals from all agents
2. Filter dominated strategies
3. Validate against SLA constraints
4. Score: 50% confidence + 30% risk reduction + 20% minimal impact
5. Execute selected strategy and update simulation state
