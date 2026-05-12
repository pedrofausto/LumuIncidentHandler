import dataclasses
import json
from datetime import datetime, timedelta, timezone
from typing import Any
from unittest.mock import AsyncMock, Mock, patch

import pytest

from src.analyzer import Analyzer
from src.config import Settings
from src.kafka_client import KafkaClient
from src.lumu_client import LumuSession
from src.main import (
    get_agent_id,
    get_primary_host_ip,
    monitor_tenant,
    normalize_customer_topic,
    process_and_send_batch,
    severity_to_rule_level,
    _safe_enrichment,
    shape_kafka_payload,
)


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.fixture
def mock_settings():
    return Settings(
        lumu_email="test@example.com",
        lumu_password="password",
        lumu_mssp_uuid="uuid",
        customer_uuid="customer_uuid",
        kafka_bootstrap_servers="localhost:9092",
        kafka_topic="topic-from-settings",
        kafka_client_id="lumu-incident-handler",
        kafka_delivery_timeout_seconds=1.0,
        kafka_flush_timeout_seconds=10.0,
        payload_timezone="America/Sao_Paulo",
        _env_file=None,
    )


@pytest.mark.anyio
async def test_send_incident_success_payload_and_key(mock_settings):
    producer = Mock()
    producer.flush.return_value = 0
    captured: dict[str, Any] = {}

    def produce_side_effect(topic, key=None, value=None, callback=None):
        captured["topic"] = topic
        captured["key"] = key
        captured["value"] = value
        callback(None, Mock(topic=lambda: topic, partition=lambda: 0, offset=lambda: 1))

    producer.produce.side_effect = produce_side_effect

    with patch("src.kafka_client.get_settings", return_value=mock_settings):
        with patch("src.kafka_client.Producer", return_value=producer):
            client = KafkaClient()
            payload = {"lumu": {"id": "inc-123"}, "rule": {"level": 14}}
            await client.send_incident(payload, topic="cli-grupoamil")

    assert captured["topic"] == "cli-grupoamil"
    assert captured["key"] == "inc-123"
    wrapped = json.loads(captured["value"])
    assert isinstance(wrapped["message"], str)
    assert json.loads(wrapped["message"]) == payload
    producer.flush.assert_called()


@pytest.mark.anyio
async def test_send_incident_delivery_failure_raises(mock_settings):
    producer = Mock()

    def produce_side_effect(topic, key=None, value=None, callback=None):
        callback("boom", None)

    producer.produce.side_effect = produce_side_effect

    with patch("src.kafka_client.get_settings", return_value=mock_settings):
        with patch("src.kafka_client.Producer", return_value=producer):
            client = KafkaClient()
            with pytest.raises(RuntimeError, match="Kafka delivery failed"):
                await client.send_incident({"incident_uuid": "inc-123"}, topic="cli-grupoamil")


@pytest.mark.anyio
async def test_send_incident_flush_timeout_raises(mock_settings):
    producer = Mock()
    producer.flush.return_value = 1

    def produce_side_effect(topic, key=None, value=None, callback=None):
        callback(None, Mock(topic=lambda: topic, partition=lambda: 0, offset=lambda: 1))

    producer.produce.side_effect = produce_side_effect

    with patch("src.kafka_client.get_settings", return_value=mock_settings):
        with patch("src.kafka_client.Producer", return_value=producer):
            client = KafkaClient()
            with pytest.raises(RuntimeError, match="Kafka flush timeout"):
                await client.send_incident({"incident_uuid": "inc-123"}, topic="cli-grupoamil")


@pytest.mark.anyio
async def test_send_incident_delivery_timeout_raises():
    settings = Settings(
        lumu_email="test@example.com",
        lumu_password="password",
        lumu_mssp_uuid="uuid",
        customer_uuid="customer_uuid",
        kafka_bootstrap_servers="localhost:9092",
        kafka_topic="topic-from-settings",
        kafka_client_id="lumu-incident-handler",
        kafka_delivery_timeout_seconds=0.01,
        kafka_flush_timeout_seconds=10.0,
        payload_timezone="America/Sao_Paulo",
        _env_file=None,
    )
    producer = Mock()
    producer.flush.return_value = 0
    producer.poll.return_value = 0

    with patch("src.kafka_client.get_settings", return_value=settings):
        with patch("src.kafka_client.Producer", return_value=producer):
            client = KafkaClient()
            with pytest.raises(RuntimeError, match="Kafka delivery timeout"):
                await client.send_incident({"incident_uuid": "inc-timeout"}, topic="cli-grupoamil")


@dataclasses.dataclass
class DummyEndpoint:
    name: str
    srcip: str
    first_contact: str = ""
    last_contact: str = ""


@dataclasses.dataclass
class DummyIncidentEvent:
    incident_uuid: str
    title: str
    adversary_type: str
    adversary_id: str
    severity: str
    status: str
    event_type: str
    first_contact: str
    last_contact: str
    endpoints_affected: int
    affected_endpoints: list[DummyEndpoint]


class DummyAnalyzer:
    def __init__(self):
        self.updated = []

    def evaluate_incidents(self, *_args, **_kwargs):
        return [DummyIncidentEvent(
            incident_uuid="inc-1",
            title="evil.example",
            adversary_type="Malware",
            adversary_id="evil.example",
            severity="High",
            status="open",
            event_type="NewIncidentCreated",
            first_contact="2026-04-10T00:00:00Z",
            last_contact="2026-04-10T00:00:00Z",
            endpoints_affected=8,
            affected_endpoints=[
                DummyEndpoint(
                    name="workstation-1",
                    srcip="10.0.0.10",
                    first_contact="2026-04-10T00:00:00Z",
                    last_contact="2026-04-10T01:00:00Z",
                )
            ],
        )]

    def update_incident_time(self, incident_uuid: str, timestamp: str):
        self.updated.append((incident_uuid, timestamp))


class RecordingAnalyzer(DummyAnalyzer):
    def __init__(self):
        super().__init__()
        self.kwargs = None

    def evaluate_incidents(self, *_args, **kwargs):
        self.kwargs = kwargs
        return super().evaluate_incidents(*_args, **kwargs)


class DummyKafka:
    def __init__(self, should_fail: bool):
        self.should_fail = should_fail
        self.calls = []

    async def send_incident(self, data, topic):
        self.calls.append((data, topic))
        if self.should_fail:
            raise RuntimeError("send failure")


def test_normalize_customer_topic():
    assert normalize_customer_topic("Grupo Amil") == "cli-grupoamil"
    assert normalize_customer_topic("BH Airport") == "cli-bhairport"
    assert normalize_customer_topic("BH-Airport") == "cli-bhairport"
    assert normalize_customer_topic("Acme! SOC #1") == "cli-acmesoc1"
    assert normalize_customer_topic("   ") == ""


def test_severity_to_rule_level_mapping():
    assert severity_to_rule_level("Low") == "3"
    assert severity_to_rule_level("Medium") == "8"
    assert severity_to_rule_level("High") == "16"
    assert severity_to_rule_level(None) == "8"


def test_shape_kafka_payload_moves_lumu_fields_and_preserves_context(mock_settings):
    event_dict = {
        "incident_uuid": "inc-1",
        "title": "evil.example",
        "adversary_type": "Malware",
        "adversary_id": "evil.example",
        "severity": "High",
        "status": "open",
        "event_type": "NewIncidentCreated",
        "first_contact": "2026-04-10T00:00:00Z",
        "last_contact": "2026-04-10T01:00:00Z",
        "endpoints_affected": 8,
        "affected_endpoints": [
            {
                "name": "workstation-1",
                "srcip": "10.0.0.10",
                "first_contact": "2026-04-10T00:00:00Z",
                "last_contact": "2026-04-10T01:00:00Z",
            }
        ],
        "stix_indicators": [{"name": "indicator"}],
        "mitre_techniques": [{"technique": "T1059"}],
        "integration": "legacy",
    }

    payload = shape_kafka_payload(
        event_dict=event_dict,
        tenant_uuid="tenant-1",
        tenant_name="Grupo Amil",
        settings=mock_settings,
        hostname="handler-host",
        agent_id="agent-uuid",
        agent_ip="10.0.0.5",
    )

    assert payload["lumu"]["id"] == "inc-1"
    assert payload["lumu"]["adversaries"] == "evil.example"
    assert payload["lumu"]["adversary_types"] == "Malware"
    assert payload["lumu"]["company_id"] == "tenant-1"
    assert payload["lumu"]["endpoints_affected"] == 8
    assert payload["lumu"]["event_type"] == "NewIncidentCreated"
    assert payload["lumu"]["affected_endpoints"] == [
        {
            "srchost": "workstation-1",
            "srcip": "10.0.0.10",
            "first_contact": "2026-04-10T00:00:00Z",
            "last_contact": "2026-04-10T01:00:00Z",
        }
    ]
    assert payload["agent"] == {"name": "handler-host", "id": "agent-uuid", "ip": "10.0.0.5"}
    assert payload["rule"] == {
        "level": "16",
        "id": "0000",
        "groups": ["lumu"],
        "description": "Lumu integration rule",
    }
    assert payload["decoder"] == {"name": "int-dec-lumu"}
    assert payload["manager"] == {"name": "handler-host"}
    assert "ss_groups" not in payload
    assert "ss_customer" not in payload
    assert payload["product_name"] == "Lumu Defender"
    assert payload["timezone"] == "America/Sao_Paulo"
    assert payload["stix_indicators"] == [{"name": "indicator"}]
    assert "integration" not in payload
    assert "severity" not in payload
    assert "event_type" not in payload
    assert "incident_uuid" not in payload
    assert "@timestamp" not in payload


def test_shape_kafka_payload_defaults_lumu_event_type_for_new_incidents(mock_settings):
    payload = shape_kafka_payload(
        event_dict={
            "incident_uuid": "inc-1",
            "title": "evil.example",
            "adversary_type": "Malware",
            "adversary_id": "evil.example",
            "severity": "High",
            "status": "open",
            "endpoints_affected": 1,
            "affected_endpoints": [],
        },
        tenant_uuid="tenant-1",
        tenant_name="Tenant",
        settings=mock_settings,
        hostname="handler-host",
        agent_id="agent-uuid",
        agent_ip="10.0.0.5",
    )

    assert payload["lumu"]["event_type"] == "NewIncidentCreated"
    assert "event_type" not in payload


def test_shape_kafka_payload_forces_test_event_type_when_enabled(mock_settings):
    test_mode_settings = mock_settings.model_copy(update={"event_type_test_mode": True})
    payload = shape_kafka_payload(
        event_dict={
            "incident_uuid": "inc-1",
            "title": "evil.example",
            "adversary_type": "Malware",
            "adversary_id": "evil.example",
            "severity": "High",
            "status": "open",
            "event_type": "IncidentUpdated",
            "endpoints_affected": 1,
            "affected_endpoints": [],
        },
        tenant_uuid="tenant-1",
        tenant_name="Tenant",
        settings=test_mode_settings,
        hostname="handler-host",
        agent_id="agent-uuid",
        agent_ip="10.0.0.5",
    )

    assert payload["lumu"]["event_type"] == "test"
    assert "event_type" not in payload


def test_analyzer_classifies_state_sync_event_types(tmp_path, mock_settings):
    settings = mock_settings.model_copy(update={"alert_state_file": str(tmp_path / "unit_event_type_state.json")})

    with patch("src.analyzer.get_settings", return_value=settings):
        analyzer = Analyzer()

    assert analyzer.classify_incident_event_type({
        "id": "new-incident",
        "lastContact": "2026-04-10T00:00:00Z",
    }) == "NewIncidentCreated"

    analyzer._incident_times["known-incident"] = "2026-04-10T00:00:00Z"
    assert analyzer.classify_incident_event_type({
        "id": "known-incident",
        "lastContact": "2026-04-10T01:00:00Z",
    }) == "IncidentUpdated"


def test_analyzer_preserves_journal_event_context(tmp_path, mock_settings):
    settings = mock_settings.model_copy(update={"alert_state_file": str(tmp_path / "unit_journal_event_state.json")})

    with patch("src.analyzer.get_settings", return_value=settings):
        analyzer = Analyzer()

    incidents = analyzer.extract_incidents_from_updates([
        {"NewIncidentCreated": {"incident": {"id": "created"}}},
        {"IncidentUpdated": {"incident": {"id": "updated"}}},
        {"IncidentClosed": {"incident": {"id": "closed"}}},
        {"IncidentReopened": {"incident": {"id": "reopened"}}},
    ])

    assert incidents == [
        {"id": "created", "_lumu_event_type": "NewIncidentCreated"},
        {"id": "updated", "_lumu_event_type": "IncidentUpdated"},
        {"id": "closed", "_lumu_event_type": "IncidentUpdated"},
        {"id": "reopened", "_lumu_event_type": "IncidentUpdated"},
    ]


def test_analyzer_prunes_state_older_than_60_days_and_keeps_unparsable(tmp_path, mock_settings):
    settings = mock_settings.model_copy(update={"alert_state_file": str(tmp_path / "unit_state_prune.json")})
    old_ts = (datetime.now(timezone.utc) - timedelta(days=90)).strftime("%Y-%m-%dT%H:%M:%SZ")
    recent_ts = (datetime.now(timezone.utc) - timedelta(days=10)).strftime("%Y-%m-%dT%H:%M:%SZ")

    with patch("src.analyzer.get_settings", return_value=settings):
        analyzer = Analyzer()
        analyzer._incident_times = {
            "old": old_ts,
            "recent": recent_ts,
            "legacy": "not-a-date",
        }
        analyzer._save_state()

    assert "old" not in analyzer._incident_times
    assert analyzer._incident_times["recent"] == recent_ts
    assert analyzer._incident_times["legacy"] == "not-a-date"


def test_analyzer_ip_validation_uses_ipaddress(tmp_path, mock_settings):
    settings = mock_settings.model_copy(update={"alert_state_file": str(tmp_path / "unit_ip_state.json")})
    with patch("src.analyzer.get_settings", return_value=settings):
        analyzer = Analyzer()

    assert analyzer._looks_like_ip("10.0.0.1") is True
    assert analyzer._looks_like_ip("2001:db8::1") is True
    assert analyzer._looks_like_ip("not-an-ip") is False


@pytest.mark.anyio
async def test_safe_enrichment_logs_warning_and_returns_default():
    async def fail():
        raise RuntimeError("boom")

    with patch("src.main.logger.warning") as warning_mock:
        result = await _safe_enrichment("details", "inc-1", fail(), {"fallback": True})

    assert result == {"fallback": True}
    warning_mock.assert_called_once()


def test_get_agent_id_creates_and_reuses_uuid(tmp_path):
    agent_dir = tmp_path / "src"
    agent_dir.mkdir()
    fake_main = agent_dir / "main.py"
    fake_main.write_text("", encoding="utf-8")

    with patch("src.main.__file__", str(fake_main)):
        first = get_agent_id()
        second = get_agent_id()

    assert first == second
    assert len(first) == 36


def test_get_primary_host_ip_uses_udp_route_probe():
    socket_instance = Mock()
    socket_instance.getsockname.return_value = ("10.0.0.5", 49152)

    with patch("src.main.socket.socket", return_value=socket_instance):
        assert get_primary_host_ip() == "10.0.0.5"

    socket_instance.connect.assert_called_once_with(("8.8.8.8", 80))
    socket_instance.close.assert_called_once()


def test_get_primary_host_ip_falls_back_to_loopback():
    socket_instance = Mock()
    socket_instance.connect.side_effect = OSError("network unavailable")

    with patch("src.main.socket.socket", return_value=socket_instance):
        assert get_primary_host_ip() == "127.0.0.1"

    socket_instance.close.assert_called_once()


@pytest.mark.anyio
async def test_process_and_send_batch_updates_state_only_after_success():
    analyzer = DummyAnalyzer()
    kafka = DummyKafka(should_fail=False)
    raw_incidents = [{"id": "inc-1", "lastContact": "2026-04-10T00:00:00Z"}]

    with patch("src.main.get_settings", return_value=Settings(
        lumu_email="test@example.com",
        lumu_password="password",
        lumu_mssp_uuid="uuid",
        customer_uuid="customer_uuid",
        kafka_topic="topic-from-settings",
        payload_timezone="America/Sao_Paulo",
        _env_file=None,
    )):
        with patch("src.main.enrich_incident", return_value={"uuid": "inc-1", "stix": {}, "details": {}, "contacts": [], "summary": {}, "articles": []}):
            with patch("src.main.asyncio.sleep", return_value=None):
                with patch("src.main.get_agent_id", return_value="agent-uuid"):
                    with patch("src.main.socket.gethostname", return_value="handler-host"):
                        with patch("src.main.get_primary_host_ip", return_value="10.0.0.5"):
                            await process_and_send_batch(
                                client=Mock(),
                                analyzer=analyzer,
                                kafka=kafka,
                                raw_incidents=raw_incidents,
                                tenant_uuid="tenant-1",
                                tenant_name="Tenant",
                                company_key="key",
                                kafka_topic="cli-tenant",
                            )

    assert len(kafka.calls) == 1
    payload, topic = kafka.calls[0]
    assert topic == "cli-tenant"
    assert payload["lumu"]["id"] == "inc-1"
    assert payload["lumu"]["event_type"] == "NewIncidentCreated"
    assert payload["lumu"]["affected_endpoints"][0]["srchost"] == "workstation-1"
    assert payload["lumu"]["affected_endpoints"][0]["srcip"] == "10.0.0.10"
    assert payload["agent"] == {"name": "handler-host", "id": "agent-uuid", "ip": "10.0.0.5"}
    assert payload["rule"] == {
        "level": "16",
        "id": "0000",
        "groups": ["lumu"],
        "description": "Lumu integration rule",
    }
    assert payload["manager"] == {"name": "handler-host"}
    assert "ss_groups" not in payload
    assert "ss_customer" not in payload
    assert "integration" not in payload
    assert "severity" not in payload
    assert payload["product_name"] == "Lumu Defender"
    assert payload["timezone"] == "America/Sao_Paulo"
    assert analyzer.updated == [("inc-1", "2026-04-10T00:00:00Z")]


@pytest.mark.anyio
async def test_process_and_send_batch_does_not_update_state_on_send_failure():
    analyzer = DummyAnalyzer()
    kafka = DummyKafka(should_fail=True)
    raw_incidents = [{"id": "inc-1", "lastContact": "2026-04-10T00:00:00Z"}]

    with patch("src.main.get_settings", return_value=Settings(
        lumu_email="test@example.com",
        lumu_password="password",
        lumu_mssp_uuid="uuid",
        customer_uuid="customer_uuid",
        kafka_topic="topic-from-settings",
        payload_timezone="America/Sao_Paulo",
        _env_file=None,
    )):
        with patch("src.main.enrich_incident", return_value={"uuid": "inc-1", "stix": {}, "details": {}, "contacts": [], "summary": {}, "articles": []}):
            with patch("src.main.asyncio.sleep", return_value=None):
                with patch("src.main.get_agent_id", return_value="agent-uuid"):
                    with patch("src.main.socket.gethostname", return_value="handler-host"):
                        with patch("src.main.get_primary_host_ip", return_value="10.0.0.5"):
                            await process_and_send_batch(
                                client=Mock(),
                                analyzer=analyzer,
                                kafka=kafka,
                                raw_incidents=raw_incidents,
                                tenant_uuid="tenant-1",
                                tenant_name="Tenant",
                                company_key="key",
                                kafka_topic="cli-tenant",
                            )

    assert len(kafka.calls) == 1
    payload, topic = kafka.calls[0]
    assert topic == "cli-tenant"
    assert payload["lumu"]["id"] == "inc-1"
    assert "integration" not in payload
    assert "severity" not in payload
    assert payload["product_name"] == "Lumu Defender"
    assert payload["timezone"] == "America/Sao_Paulo"
    assert analyzer.updated == []


@pytest.mark.anyio
async def test_process_and_send_batch_passes_contacts_to_analyzer():
    analyzer = RecordingAnalyzer()
    kafka = DummyKafka(should_fail=False)
    raw_incidents = [{"id": "inc-1", "lastContact": "2026-04-10T00:00:00Z"}]
    contacts = [{"endpointName": "workstation-1", "endpointIp": "10.0.0.10"}]

    with patch("src.main.get_settings", return_value=Settings(
        lumu_email="test@example.com",
        lumu_password="password",
        lumu_mssp_uuid="uuid",
        customer_uuid="customer_uuid",
        kafka_topic="topic-from-settings",
        payload_timezone="America/Sao_Paulo",
        _env_file=None,
    )):
        with patch("src.main.enrich_incident", return_value={"uuid": "inc-1", "stix": {}, "details": {}, "contacts": contacts, "summary": {}, "articles": []}):
            with patch("src.main.asyncio.sleep", return_value=None):
                with patch("src.main.get_agent_id", return_value="agent-uuid"):
                    with patch("src.main.socket.gethostname", return_value="handler-host"):
                        with patch("src.main.get_primary_host_ip", return_value="10.0.0.5"):
                            await process_and_send_batch(
                                client=Mock(),
                                analyzer=analyzer,
                                kafka=kafka,
                                raw_incidents=raw_incidents,
                                tenant_uuid="tenant-1",
                                tenant_name="Tenant",
                                company_key="key",
                                kafka_topic="cli-tenant",
                            )

    assert analyzer.kwargs["contacts_map"] == {"inc-1": contacts}


@pytest.mark.anyio
async def test_monitor_tenant_stops_when_offset_does_not_advance():
    analyzer = Mock()
    analyzer.last_pulled_time = "2026-05-01T00:00:00Z"
    analyzer.offset = 12
    analyzer.should_process_incident.return_value = False

    client = Mock()
    client.rate_limit_hits = 0
    client.get_open_incidents = AsyncMock(return_value=[])
    client.get_incident_updates = AsyncMock(side_effect=[
        {"updates": [{"IncidentUpdated": {"incident": {"id": "inc-1"}}}], "offset": 12}
    ])

    with patch("src.main.process_and_send_batch", new=AsyncMock(return_value=(0, 0))) as batch_mock:
        with patch("src.main.logger.warning") as warning_mock:
            await monitor_tenant(
                client=client,
                analyzer=analyzer,
                kafka=Mock(),
                tenant_uuid="tenant-1",
                tenant_name="Tenant",
                company_key="k",
                kafka_topic="cli-tenant",
            )

    assert batch_mock.call_count == 1
    warning_mock.assert_called()
    analyzer._save_state.assert_not_called()


@pytest.mark.anyio
async def test_get_mssp_activity_uses_settings_timezone_by_default(mock_settings):
    with patch("src.lumu_client.get_settings", return_value=mock_settings.model_copy(update={"payload_timezone": "America/Sao_Paulo"})):
        session = LumuSession()
    session.post_with_auth = AsyncMock(return_value={"ok": True})

    await session.get_mssp_activity("2026-05-01T00:00:00.000", "2026-05-02T00:00:00.000")

    args, kwargs = session.post_with_auth.call_args
    assert args[0] == "/data-api/companies/activity/msp"
    assert kwargs["json_data"]["timezone"] == "America/Sao_Paulo"
    await session.close()


@pytest.mark.anyio
async def test_get_mssp_activity_explicit_timezone_overrides_default(mock_settings):
    with patch("src.lumu_client.get_settings", return_value=mock_settings.model_copy(update={"payload_timezone": "UTC"})):
        session = LumuSession()
    session.post_with_auth = AsyncMock(return_value={"ok": True})

    await session.get_mssp_activity(
        "2026-05-01T00:00:00.000",
        "2026-05-02T00:00:00.000",
        timezone="America/Sao_Paulo",
    )

    _, kwargs = session.post_with_auth.call_args
    assert kwargs["json_data"]["timezone"] == "America/Sao_Paulo"
    await session.close()
