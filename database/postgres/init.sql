-- AMCDS PostgreSQL Schema
-- Stores incidents, alerts, strategies, decisions, and simulation metadata

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Simulation runs
CREATE TABLE simulation_runs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    scenario_name VARCHAR(100) NOT NULL,
    seed INTEGER NOT NULL,
    started_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    ended_at TIMESTAMP WITH TIME ZONE,
    total_ticks INTEGER DEFAULT 0,
    status VARCHAR(20) DEFAULT 'running',
    config JSONB
);

-- Alerts
CREATE TABLE alerts (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    alert_id VARCHAR(50) UNIQUE NOT NULL,
    simulation_run_id UUID REFERENCES simulation_runs(id),
    agent_name VARCHAR(50) NOT NULL,
    alert_type VARCHAR(100) NOT NULL,
    attack_class VARCHAR(50),
    severity VARCHAR(20) NOT NULL,
    confidence REAL NOT NULL,
    mitre_tactic VARCHAR(100),
    mitre_technique VARCHAR(20),
    source_ip VARCHAR(45),
    source_host VARCHAR(100),
    target_ip VARCHAR(45),
    user_id VARCHAR(50),
    description TEXT,
    evidence JSONB,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX idx_alerts_type ON alerts(alert_type);
CREATE INDEX idx_alerts_severity ON alerts(severity);
CREATE INDEX idx_alerts_created ON alerts(created_at);
CREATE INDEX idx_alerts_simulation ON alerts(simulation_run_id);

-- Incidents
CREATE TABLE incidents (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    incident_id VARCHAR(50) UNIQUE NOT NULL,
    simulation_run_id UUID REFERENCES simulation_runs(id),
    attack_class VARCHAR(50),
    severity VARCHAR(20),
    confidence REAL,
    first_seen TIMESTAMP WITH TIME ZONE,
    last_seen TIMESTAMP WITH TIME ZONE,
    affected_users JSONB DEFAULT '[]',
    affected_hosts JSONB DEFAULT '[]',
    affected_ips JSONB DEFAULT '[]',
    mitre_tactics JSONB DEFAULT '[]',
    mitre_techniques JSONB DEFAULT '[]',
    kill_chain_phase INTEGER DEFAULT 0,
    alert_count INTEGER DEFAULT 0,
    status VARCHAR(20) DEFAULT 'open',
    business_impact JSONB,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX idx_incidents_status ON incidents(status);
CREATE INDEX idx_incidents_severity ON incidents(severity);
CREATE INDEX idx_incidents_created ON incidents(created_at);

-- Strategies
CREATE TABLE strategies (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    strategy_id VARCHAR(50) UNIQUE NOT NULL,
    incident_id VARCHAR(50) REFERENCES incidents(incident_id),
    agent_name VARCHAR(50),
    actions JSONB,
    confidence REAL,
    residual_risk REAL,
    impact_estimate JSONB,
    constraints JSONB DEFAULT '[]',
    status VARCHAR(20) DEFAULT 'proposed',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Decisions
CREATE TABLE decisions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    incident_id VARCHAR(50) REFERENCES incidents(incident_id),
    selected_strategy_id VARCHAR(50),
    actions_taken JSONB,
    rationale TEXT,
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Telemetry statistics (aggregated)
CREATE TABLE telemetry_stats (
    id SERIAL PRIMARY KEY,
    simulation_run_id UUID REFERENCES simulation_runs(id),
    tick INTEGER,
    event_type VARCHAR(30),
    event_count INTEGER,
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX idx_telemetry_stats_tick ON telemetry_stats(tick);
