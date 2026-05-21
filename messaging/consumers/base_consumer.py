"""
Base Kafka Consumer - Reusable wrapper around confluent-kafka Consumer.
"""
from __future__ import annotations
import json
import logging
from typing import Any, Callable
from collections.abc import Generator

logger = logging.getLogger(__name__)


class BaseConsumer:
    """Reusable Kafka consumer with deserialization and offset management."""

    def __init__(self, bootstrap_servers: str = "kafka:9092",
                 group_id: str = "amcds-default",
                 topics: list[str] | None = None,
                 auto_offset_reset: str = "earliest",
                 **kwargs):
        self.bootstrap_servers = bootstrap_servers
        self.group_id = group_id
        self.topics = topics or []
        self._consumer = None
        self._config = {
            "bootstrap.servers": bootstrap_servers,
            "group.id": group_id,
            "auto.offset.reset": auto_offset_reset,
            "enable.auto.commit": True,
            "auto.commit.interval.ms": 5000,
            "max.poll.interval.ms": 300000,
            **kwargs,
        }
        self._running = False
        self._stats = {"consumed": 0, "errors": 0}

    def connect(self) -> None:
        try:
            from confluent_kafka import Consumer
            self._consumer = Consumer(self._config)
            if self.topics:
                self._consumer.subscribe(self.topics)
            logger.info("Consumer %s connected, subscribed to %s", self.group_id, self.topics)
        except ImportError:
            logger.warning("confluent_kafka not available")

    def consume_one(self, timeout: float = 1.0) -> dict[str, Any] | None:
        if not self._consumer:
            return None
        msg = self._consumer.poll(timeout)
        if msg is None:
            return None
        if msg.error():
            logger.error("Consumer error: %s", msg.error())
            self._stats["errors"] += 1
            return None
        try:
            value = json.loads(msg.value().decode("utf-8"))
            self._stats["consumed"] += 1
            return value
        except (json.JSONDecodeError, UnicodeDecodeError) as e:
            logger.error("Deserialization error: %s", e)
            self._stats["errors"] += 1
            return None

    def consume_batch(self, max_messages: int = 100, timeout: float = 1.0) -> list[dict[str, Any]]:
        events = []
        for _ in range(max_messages):
            event = self.consume_one(timeout=timeout / max_messages)
            if event:
                events.append(event)
        return events

    def consume_loop(self, handler: Callable[[dict[str, Any]], None],
                     poll_timeout: float = 1.0) -> Generator[None, None, None]:
        """Generator-based consume loop for use in agents."""
        self._running = True
        while self._running:
            event = self.consume_one(timeout=poll_timeout)
            if event:
                try:
                    handler(event)
                except Exception as e:
                    logger.error("Handler error: %s", e)
            yield

    def stop(self) -> None:
        self._running = False
        if self._consumer:
            self._consumer.close()

    def commit(self) -> None:
        if self._consumer:
            self._consumer.commit()

    @property
    def stats(self) -> dict[str, int]:
        return dict(self._stats)
