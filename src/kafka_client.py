import asyncio
import json
import logging
import time
from typing import Any

try:
    from confluent_kafka import Producer
except ImportError:  # pragma: no cover - exercised only when dependency is missing
    Producer = None  # type: ignore[assignment]

from .config import get_settings

logger = logging.getLogger(__name__)


class KafkaClient:
    def __init__(self):
        if Producer is None:
            raise RuntimeError(
                "confluent-kafka is not installed. Install dependencies from requirements.txt before running the handler."
            )
        self.settings = get_settings()
        self.producer = Producer(
            {
                "bootstrap.servers": self.settings.kafka_bootstrap_servers,
                "client.id": self.settings.kafka_client_id,
            }
        )

    async def send_incident(self, json_data: dict[str, Any], topic: str) -> None:
        if not topic or not topic.strip():
            raise RuntimeError("Kafka topic is required for publish")
        topic = topic.strip()

        lumu_data = json_data.get("lumu") if isinstance(json_data.get("lumu"), dict) else {}
        incident_id = json_data.get("incident_uuid") or lumu_data.get("id")
        key = str(incident_id) if incident_id else None

        wrapped_payload = {"message": json.dumps(json_data, default=str)}
        encoded_value = json.dumps(wrapped_payload, default=str)

        loop = asyncio.get_running_loop()
        delivery_future: asyncio.Future[None] = loop.create_future()

        def delivery_report(err, msg):
            if err is not None:
                if not delivery_future.done():
                    delivery_future.set_exception(RuntimeError(f"Kafka delivery failed: {err}"))
                return
            if not delivery_future.done():
                delivery_future.set_result(None)
            logger.info(
                "Incident published to Kafka topic=%s partition=%s offset=%s",
                msg.topic(),
                msg.partition(),
                msg.offset(),
            )

        try:
            self.producer.produce(topic, key=key, value=encoded_value, callback=delivery_report)
        except BufferError as e:
            logger.error("Kafka producer local queue is full: %s", e)
            raise RuntimeError("Kafka producer local queue is full") from e
        except Exception:
            logger.exception("Failed to queue incident for Kafka production.")
            raise

        deadline = time.monotonic() + self.settings.kafka_delivery_timeout_seconds
        while not delivery_future.done():
            if time.monotonic() >= deadline:
                raise RuntimeError(
                    f"Kafka delivery timeout for incident={incident_id} topic={topic} after "
                    f"{self.settings.kafka_delivery_timeout_seconds}s"
                )
            self.producer.poll(0.1)
            await asyncio.sleep(0)

        await delivery_future

        remaining = self.producer.flush(timeout=self.settings.kafka_flush_timeout_seconds)
        if remaining != 0:
            raise RuntimeError(
                f"Kafka flush timeout for incident={incident_id} topic={topic}, "
                f"{remaining} message(s) still pending"
            )

    async def close(self):
        remaining = self.producer.flush(timeout=self.settings.kafka_flush_timeout_seconds)
        if remaining != 0:
            logger.warning("Kafka producer closed with %s pending message(s).", remaining)

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.close()
