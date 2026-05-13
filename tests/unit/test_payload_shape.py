import asyncio
import json
from types import SimpleNamespace

from src.kafka_client import KafkaClient
from src.main import shape_kafka_payload


class _FakeProducer:
    def __init__(self):
        self.messages = []
        self._callback = None
        self._topic = None
        self._key = None
        self._value = None

    def produce(self, topic, key=None, value=None, callback=None):
        self._topic = topic
        self._key = key
        self._value = value
        self._callback = callback
        self.messages.append({"topic": topic, "key": key, "value": value})

    def poll(self, _timeout):
        if self._callback is not None:
            callback = self._callback
            self._callback = None
            callback(None, _FakeMessage(self._topic))

    def flush(self, timeout=None):
        return 0


class _FakeMessage:
    def __init__(self, topic):
        self._topic = topic

    def topic(self):
        return self._topic

    def partition(self):
        return 0

    def offset(self):
        return 0


def test_shape_kafka_payload_nests_lumu_fields_under_data():
    settings = SimpleNamespace(event_type_test_mode=False, payload_timezone="UTC")
    event_dict = {
        "incident_uuid": "incident-123",
        "title": "Threat title",
        "adversary_id": "adv-1",
        "adversary_type": "Malware",
        "customer_uuid": "tenant-123",
        "customer_name": "Tenant Name",
        "endpoints_affected": 2,
        "affected_endpoints": [
            {
                "name": "host-01",
                "srcip": "10.0.0.1",
                "first_contact": "2026-05-12T11:00:00Z",
                "last_contact": "2026-05-12T11:30:00Z",
            }
        ],
        "status": "open",
        "event_type": "NewIncidentCreated",
        "details": "incident description",
        "mitre_techniques": [{"technique": "T1059"}],
        "related_artifacts": {"domains": ["example.com"]},
        "recommended_playbooks": [{"name": "Contain"}],
        "intelligence_tags": ["tag-1"],
        "intelligence_articles": [{"title": "Article"}],
        "extracted_iocs": [{"parsed_domain": "example.com"}],
        "disseminated": True,
        "dissemination_time": "2026-05-12T11:10:00Z",
        "dissemination_latency": "10m 0s",
        "mtt_response": "5m 0s",
        "mtt_resolution": "20m 0s",
        "triggered_integrations": ["Slack"],
        "tlp": "TLP: AMBER",
        "stix_indicators": [{"name": "ioc-1"}],
        "stix_malware": [{"name": "family-1"}],
        "stix_sighting": {"count": 1},
        "severity": "high",
        "first_contact": "2026-05-12T11:00:00Z",
        "last_contact": "2026-05-12T11:30:00Z",
    }

    payload = shape_kafka_payload(
        event_dict=event_dict,
        tenant_uuid="tenant-fallback",
        tenant_name="Tenant Fallback",
        settings=settings,
        hostname="handler-host",
        agent_id="agent-1",
        agent_ip="10.0.0.5",
    )

    assert "lumu" not in payload
    assert payload["data"]["lumu"]["id"] == "incident-123"
    assert payload["data"]["lumu"]["adversaries"] == "Threat title"
    assert payload["data"]["lumu"]["details"] == "incident description"
    assert payload["data"]["lumu"]["extracted_iocs"] == [{"parsed_domain": "example.com"}]
    assert payload["data"]["lumu"]["disseminated"] is True
    assert payload["data"]["lumu"]["affected_endpoints"] == [
        {
            "srchost": "host-01",
            "srcip": "10.0.0.1",
            "first_contact": "2026-05-12T11:00:00Z",
            "last_contact": "2026-05-12T11:30:00Z",
        }
    ]
    assert payload["agent"] == {"name": "handler-host", "id": "agent-1", "ip": "10.0.0.5"}
    assert payload["rule"]["level"] == "16"
    assert payload["product_name"] == "Lumu Defender"
    assert payload["timezone"] == "UTC"
    assert "details" not in payload
    assert "disseminated" not in payload
    assert "extracted_iocs" not in payload


def test_kafka_send_incident_uses_data_lumu_id_as_key():
    producer = _FakeProducer()
    client = KafkaClient.__new__(KafkaClient)
    client.settings = SimpleNamespace(
        kafka_delivery_timeout_seconds=1.0,
        kafka_flush_timeout_seconds=1.0,
    )
    client.producer = producer

    payload = {
        "data": {
            "lumu": {
                "id": "incident-456",
            }
        }
    }

    asyncio.run(client.send_incident(payload, topic="cli-tenant"))

    assert producer.messages[0]["key"] == "incident-456"
    wrapped = json.loads(producer.messages[0]["value"])
    assert json.loads(wrapped["message"]) == payload
