"""
Attack Engine Main Entry Point

Runs attack scenarios against the simulated enterprise environment.
Waits for the simulation engine to be ready before starting attacks.
"""
from __future__ import annotations
import logging
import os
import time
import json

import structlog

logger = structlog.get_logger()


def main():
    level = os.environ.get("LOG_LEVEL", "INFO")
    logging.basicConfig(level=getattr(logging, level, logging.INFO))
    structlog.configure(wrapper_class=structlog.make_filtering_bound_logger(getattr(logging, level, logging.INFO)))

    seed = int(os.environ.get("SIM_SEED", "42"))
    scenario = os.environ.get("SIM_SCENARIO", "baseline_medium")
    kafka_bootstrap = os.environ.get("KAFKA_BOOTSTRAP_SERVERS", "kafka:9092")
    tick_interval_ms = int(os.environ.get("SIM_TICK_INTERVAL_MS", "100"))

    logger.info("Attack Engine starting", scenario=scenario, seed=seed)

    # Wait for Kafka
    from messaging.producers.base_producer import BaseProducer
    producer = BaseProducer(kafka_bootstrap)
    for attempt in range(30):
        try:
            producer.connect()
            logger.info("Kafka connected")
            break
        except Exception:
            time.sleep(2)

    # Wait for simulation engine to warm up
    logger.info("Waiting for simulation engine to warm up...")
    time.sleep(15)

    # Load enterprise state from Redis
    enterprise_state = _load_enterprise_state()

    # Initialize attack runner
    from attack_engine.scenario_runner import AttackScenarioRunner
    runner = AttackScenarioRunner(seed=seed)
    runner.load_scenario(scenario)
    runner.initialize_modules()

    # Run attack scenario
    base_timestamp = 1700000000.0
    tick = 0

    try:
        while True:
            timestamp = base_timestamp + (tick * tick_interval_ms / 1000.0)
            events = runner.execute_tick(tick, timestamp, enterprise_state)

            for evt in events:
                evt_type = evt.get("event_type", "unknown")
                topic = {
                    "auth": "telemetry.auth",
                    "network": "telemetry.network",
                    "http": "telemetry.http",
                    "file": "telemetry.file",
                    "process": "telemetry.process",
                    "email": "telemetry.email",
                }.get(evt_type, "telemetry.unknown")

                producer.produce(topic, evt)

            if events:
                producer.poll(0)

            if tick % 500 == 0:
                producer.flush(5.0)
                logger.info("Attack engine progress", tick=tick, events_this_tick=len(events))

            tick += 1
            time.sleep(tick_interval_ms / 1000.0)

    except KeyboardInterrupt:
        logger.info("Attack engine stopped", final_tick=tick)
    finally:
        producer.flush()


def _load_enterprise_state() -> dict:
    """Load simulated enterprise state. In production this comes from Redis/shared config."""
    try:
        redis_host = os.environ.get("REDIS_HOST", "redis")
        import redis as redis_lib
        r = redis_lib.Redis(host=redis_host, port=6379, decode_responses=True)
        state = r.get("enterprise_state")
        if state:
            return json.loads(state)
    except Exception:
        pass

    # Return minimal state for attack modules
    return {
        "users": {f"u-{i:04d}": {"id": f"u-{i:04d}", "username": f"user{i}", "email": f"user{i}@amcds-corp.sim",
                                    "department": "Engineering", "assigned_host_id": f"host-{i:04d}"}
                  for i in range(1, 101)},
        "hosts": {f"host-{i:04d}": {"id": f"host-{i:04d}", "hostname": f"ws-eng-{i:03d}",
                                      "ip_address": f"10.1.2.{10+i}", "host_type": "workstation", "subnet_id": "subnet-002"}
                  for i in range(1, 101)},
    }


if __name__ == "__main__":
    main()
