"""
Base Kafka Producer - Reusable wrapper around confluent-kafka Producer.
"""
from __future__ import annotations
import json
import logging
from typing import Any, Callable

logger = logging.getLogger(__name__)


class BaseProducer:
    """Reusable Kafka producer with serialization and error handling."""

    def __init__(self, bootstrap_servers: str = "kafka:9092", **kwargs):
        self.bootstrap_servers = bootstrap_servers
        self._producer = None
        self._config = {
            "bootstrap.servers": bootstrap_servers,
            "queue.buffering.max.messages": 50000,
            "queue.buffering.max.ms": 100,
            "batch.num.messages": 100,
            "linger.ms": 50,
            "compression.type": "lz4",
            "acks": "all",
            **kwargs,
        }
        self._stats = {"produced": 0, "errors": 0}

    def connect(self) -> None:
        try:
            from confluent_kafka import Producer
            self._producer = Producer(self._config)
            logger.info("Producer connected to %s", self.bootstrap_servers)
        except ImportError:
            logger.warning("confluent_kafka not available")

    def produce(self, topic: str, value: dict[str, Any],
                key: str | None = None,
                callback: Callable | None = None) -> None:
        payload = json.dumps(value, default=str).encode("utf-8")
        key_bytes = key.encode("utf-8") if key else None

        if self._producer:
            self._producer.produce(
                topic=topic, value=payload, key=key_bytes,
                callback=callback or self._default_callback,
            )
            self._stats["produced"] += 1
            if self._stats["produced"] % 100 == 0:
                self._producer.poll(0)
        else:
            logger.debug("Would produce to %s: %s", topic, key)

    def flush(self, timeout: float = 10.0) -> int:
        if self._producer:
            return self._producer.flush(timeout)
        return 0

    def poll(self, timeout: float = 0) -> int:
        if self._producer:
            return self._producer.poll(timeout)
        return 0

    def _default_callback(self, err, msg):
        if err:
            logger.error("Delivery error: %s", err)
            self._stats["errors"] += 1

    @property
    def stats(self) -> dict[str, int]:
        return dict(self._stats)
