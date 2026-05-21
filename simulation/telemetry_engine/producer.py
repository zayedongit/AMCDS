"""
Telemetry Producer - Publishes normalized OCSF events to Kafka topics.
"""
from __future__ import annotations
import json
import logging
from typing import Any

from simulation.telemetry_engine.schema import (
    TelemetryEvent, AuthTelemetry, NetworkTelemetry, HttpTelemetry,
    FileTelemetry, ProcessTelemetry, EmailTelemetry,
)

logger = logging.getLogger(__name__)

# Topic routing by event class
TOPIC_MAP = {
    AuthTelemetry: "telemetry.auth",
    NetworkTelemetry: "telemetry.network",
    HttpTelemetry: "telemetry.http",
    FileTelemetry: "telemetry.file",
    ProcessTelemetry: "telemetry.process",
    EmailTelemetry: "telemetry.email",
}


class TelemetryProducer:
    """Publishes telemetry events to Kafka with batching support."""

    def __init__(self, bootstrap_servers: str = "kafka:9092", batch_size: int = 50):
        self.bootstrap_servers = bootstrap_servers
        self.batch_size = batch_size
        self._producer = None
        self._buffer: dict[str, list[dict]] = {}
        self._total_produced = 0

    def connect(self) -> None:
        """Initialize Kafka producer connection."""
        try:
            from confluent_kafka import Producer
            self._producer = Producer({
                "bootstrap.servers": self.bootstrap_servers,
                "queue.buffering.max.messages": 100000,
                "queue.buffering.max.ms": 100,
                "batch.num.messages": self.batch_size,
                "linger.ms": 50,
                "compression.type": "lz4",
            })
            logger.info("Kafka producer connected to %s", self.bootstrap_servers)
        except ImportError:
            logger.warning("confluent_kafka not available, using in-memory buffer")
            self._producer = None

    def produce(self, event: TelemetryEvent) -> None:
        """Produce a single telemetry event to the appropriate topic."""
        topic = self._get_topic(event)
        payload = json.dumps(event.to_kafka_dict(), default=str).encode("utf-8")

        if self._producer is not None:
            self._producer.produce(
                topic=topic,
                value=payload,
                key=event.metadata.uid.encode("utf-8"),
                callback=self._delivery_callback,
            )
            self._total_produced += 1
            if self._total_produced % self.batch_size == 0:
                self._producer.poll(0)
        else:
            # In-memory fallback
            self._buffer.setdefault(topic, []).append(event.to_kafka_dict())

    def produce_batch(self, events: list[TelemetryEvent]) -> None:
        """Produce a batch of events."""
        for event in events:
            self.produce(event)
        if self._producer:
            self._producer.poll(0)

    def flush(self, timeout: float = 10.0) -> None:
        """Flush all pending messages."""
        if self._producer:
            self._producer.flush(timeout)

    def get_buffer(self, topic: str) -> list[dict]:
        """Get buffered events for a topic (in-memory mode only)."""
        return self._buffer.get(topic, [])

    def get_all_buffers(self) -> dict[str, list[dict]]:
        return dict(self._buffer)

    def get_stats(self) -> dict[str, int]:
        if self._producer:
            return {"total_produced": self._total_produced}
        return {topic: len(events) for topic, events in self._buffer.items()}

    def _get_topic(self, event: TelemetryEvent) -> str:
        for cls, topic in TOPIC_MAP.items():
            if isinstance(event, cls):
                return topic
        return "telemetry.unknown"

    @staticmethod
    def _delivery_callback(err, msg):
        if err:
            logger.error("Delivery failed: %s", err)
