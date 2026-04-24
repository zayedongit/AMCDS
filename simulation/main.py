"""
AMCDS Simulation Main Entry Point

Initializes the enterprise environment, starts all agents via Ray,
and runs the simulation loop generating telemetry and processing events.
"""
from __future__ import annotations
import logging
import os
import time
import json

import structlog

logger = structlog.get_logger()


def setup_logging():
    level = os.environ.get("LOG_LEVEL", "INFO")
    logging.basicConfig(level=getattr(logging, level, logging.INFO), format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    structlog.configure(wrapper_class=structlog.make_filtering_bound_logger(getattr(logging, level, logging.INFO)))


def main():
    setup_logging()
    logger.info("AMCDS Simulation Engine starting...")

    seed = int(os.environ.get("SIM_SEED", "42"))
    num_users = int(os.environ.get("SIM_NUM_USERS", "100"))
    num_hosts = int(os.environ.get("SIM_NUM_HOSTS", "100"))
    num_services = int(os.environ.get("SIM_NUM_SERVICES", "10"))
    num_subnets = int(os.environ.get("SIM_NUM_SUBNETS", "5"))
    tick_interval_ms = int(os.environ.get("SIM_TICK_INTERVAL_MS", "100"))
    scenario = os.environ.get("SIM_SCENARIO", "baseline_medium")
    kafka_bootstrap = os.environ.get("KAFKA_BOOTSTRAP_SERVERS", "kafka:9092")

    # Phase 1: Generate enterprise topology
    from simulation.enterprise_simulator.topology import EnterpriseTopology
    from simulation.enterprise_simulator.users import UserGenerator
    from simulation.enterprise_simulator.services import ServiceRegistry
    from simulation.enterprise_simulator.credentials import CredentialVault

    logger.info("Phase 1: Generating enterprise topology", seed=seed)
    topology = EnterpriseTopology(seed=seed, num_subnets=num_subnets, num_hosts=num_hosts, num_services=num_services)
    topology.generate()
    logger.info("Topology generated", subnets=len(topology.subnets), hosts=len(topology.hosts))

    user_gen = UserGenerator(seed=seed, num_users=num_users)
    workstation_ids = [h.id for h in topology.get_workstations()]
    users = user_gen.generate(host_ids=workstation_ids)
    logger.info("Users generated", count=len(users))

    server_ids = [h.id for h in topology.get_servers()]
    svc_registry = ServiceRegistry(seed=seed, num_services=num_services)
    services = svc_registry.generate(server_host_ids=server_ids)
    logger.info("Services generated", count=len(services))

    cred_vault = CredentialVault(seed=seed)
    cred_vault.generate_for_users([(u.id, u.username) for u in users.values()])
    logger.info("Credentials generated")

    # Phase 2: Initialize behavior simulators
    from simulation.user_simulator.behavior_engine import UserBehaviorEngine
    from simulation.email_simulator.email_engine import EmailEngine
    from simulation.network_simulator.traffic_engine import TrafficEngine
    from simulation.process_simulator.proc_engine import ProcessEngine

    behavior = UserBehaviorEngine(seed=seed, tick_interval_ms=tick_interval_ms)
    behavior.initialize_users([u.__dict__ if hasattr(u, '__dict__') else u for u in users.values()])
    email_engine = EmailEngine(seed=seed)
    email_engine.initialize_mailboxes(list(users.keys()))
    traffic_engine = TrafficEngine(seed=seed)
    process_engine = ProcessEngine(seed=seed)

    # Initialize processes on all hosts
    for host in topology.hosts.values():
        process_engine.initialize_host(host.id, host.hostname, host.os_type)
    logger.info("Phase 2: Behavior simulators initialized")

    # Phase 3: Initialize telemetry
    from simulation.telemetry_engine.normalizer import TelemetryNormalizer
    from simulation.telemetry_engine.producer import TelemetryProducer

    normalizer = TelemetryNormalizer(seed=seed, scenario=scenario)
    producer = TelemetryProducer(bootstrap_servers=kafka_bootstrap)

    # Retry Kafka connection
    for attempt in range(30):
        try:
            producer.connect()
            logger.info("Phase 3+5: Kafka producer connected")
            break
        except Exception as e:
            logger.warning("Kafka not ready, retrying...", attempt=attempt)
            time.sleep(2)

    # Create Kafka topics
    _create_topics(kafka_bootstrap)

    # Phase 6: Initialize agents via Ray
    logger.info("Phase 6: Initializing Ray and agents")
    try:
        import ray
        ray.init(address="auto", ignore_reinit_error=True)
        logger.info("Ray connected", resources=ray.cluster_resources())
    except Exception as e:
        logger.warning("Ray not available, running agents in-process: %s", e)

    # Simulation loop
    logger.info("Starting simulation loop", scenario=scenario, tick_interval_ms=tick_interval_ms)
    base_timestamp = 1700000000.0  # Fixed base for determinism
    tick = 0
    host_ips = [h.ip_address for h in topology.hosts.values()]

    try:
        while True:
            timestamp = base_timestamp + (tick * tick_interval_ms / 1000.0)

            # Generate user behavior events
            activity_events = behavior.generate_tick_events(tick, base_timestamp)

            # Generate network background traffic
            net_events = traffic_engine.generate_background_noise(tick, timestamp, host_ips, count=3)

            # Generate process events for a few random hosts
            import random
            rng = random.Random(seed + tick)
            sample_hosts = rng.sample(list(topology.hosts.values()), min(5, len(topology.hosts)))
            proc_events = []
            for h in sample_hosts:
                proc_events.extend(process_engine.generate_tick_events(tick, timestamp, h.id, h.hostname, h.os_type))

            # Normalize and produce all events
            for evt in activity_events:
                if evt.activity_type in ("login", "logout"):
                    normalized = normalizer.normalize_auth_event(evt.__dict__, tick)
                    producer.produce(normalized)
                elif evt.activity_type in ("email_send", "email_read"):
                    normalized = normalizer.normalize_email_event(evt.__dict__, tick)
                    producer.produce(normalized)
                elif evt.activity_type == "file_access":
                    normalized = normalizer.normalize_file_event(evt.__dict__, tick)
                    producer.produce(normalized)
                elif evt.activity_type == "web_browse":
                    normalized = normalizer.normalize_http_event(evt.__dict__, tick)
                    producer.produce(normalized)

            for evt in net_events:
                normalized = normalizer.normalize_network_event(evt.__dict__, tick)
                producer.produce(normalized)

            for evt in proc_events:
                normalized = normalizer.normalize_process_event(evt.__dict__, tick)
                producer.produce(normalized)

            # Flush periodically
            if tick % 100 == 0:
                producer.flush(timeout=2.0)
                if tick % 1000 == 0:
                    logger.info("Simulation progress", tick=tick, stats=producer.get_stats())

            tick += 1
            time.sleep(tick_interval_ms / 1000.0)

    except KeyboardInterrupt:
        logger.info("Simulation stopped by user", final_tick=tick)
    finally:
        producer.flush()
        logger.info("Simulation engine shutdown complete")


def _create_topics(bootstrap_servers: str) -> None:
    """Create Kafka topics from topics.json."""
    try:
        from confluent_kafka.admin import AdminClient, NewTopic
        topics_path = os.path.join(os.path.dirname(__file__), "..", "messaging", "kafka", "topics.json")
        if not os.path.exists(topics_path):
            topics_path = "messaging/kafka/topics.json"
        with open(topics_path) as f:
            topic_defs = json.load(f)["topics"]

        admin = AdminClient({"bootstrap.servers": bootstrap_servers})
        new_topics = [NewTopic(t["name"], num_partitions=t["partitions"], replication_factor=1) for t in topic_defs]
        futures = admin.create_topics(new_topics)
        for topic, future in futures.items():
            try:
                future.result()
                logger.info("Created topic: %s", topic)
            except Exception:
                pass  # Topic may already exist
    except Exception as e:
        logger.warning("Could not create topics: %s", e)


if __name__ == "__main__":
    main()
