import asyncio
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4

import httpx
import pytest
from pydantic import ValidationError

import src.analyzer as analyzer_module
from src.analyzer import Analyzer
from src.config import Settings
from src.incident_builder import build_incident_event
from src.kafka_client import KafkaClient
from src.main import JournalSyncResult, TenantRuntime, enrich_incident, monitor_tenant, run_journal_sync, run_open_state_reconciliation, run_tenant_batch, should_run_open_state_reconciliation
from src.models import IncidentSourceBundle
from src.payload_serializer import serialize_incident_event


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


class _FakeEnrichmentClient:
    def __init__(self, *, details, secops_details, contacts=None, activity_events=None):
        self._details = details
        self._secops_details = secops_details
        self._contacts = contacts or []
        self._activity_events = activity_events or {}
        self.contact_calls = 0
        self.activity_event_calls = []

    async def get_incident_details(self, _company_key, _incident_uuid):
        return self._details

    async def get_incident_stix(self, _tenant_uuid, _incident_uuid):
        return {}

    async def get_incident_context_summary(self, _tenant_uuid, _incident_uuid):
        return {}

    async def get_secops_incident_details(self, _tenant_uuid, _incident_uuid):
        return self._secops_details

    async def get_incident_external_articles(self, _tenant_uuid, _incident_uuid):
        return []

    async def get_incident_contacts(self, _company_key, _incident_uuid):
        self.contact_calls += 1
        return self._contacts

    async def get_activity_event_details(self, _tenant_uuid, event_uuid):
        self.activity_event_calls.append(event_uuid)
        return self._activity_events.get(event_uuid, {})


def _build_event(
    raw_incident,
    *,
    stix=None,
    details=None,
    contacts=None,
    summary=None,
    articles=None,
    secops_details=None,
    activity_event_details=None,
    event_type="IncidentUpdated",
):
    return build_incident_event(
        raw_incident=raw_incident,
        bundle=IncidentSourceBundle(
            incident_uuid=raw_incident["id"],
            tenant_uuid="tenant-1",
            defender_details=details or {},
            defender_contacts=contacts or [],
            secops_details=secops_details or {},
            activity_event_details=activity_event_details or [],
            stix=stix or {},
            summary=summary or {},
            articles=articles or [],
        ),
        event_type=event_type,
    )


def test_serialize_incident_event_nests_lumu_fields_under_data():
    settings = SimpleNamespace(event_type_test_mode=False, payload_timezone="UTC")
    event_dict = {
        "incident_uuid": "incident-123",
        "title": "Threat title",
        "adversaries": ["example.com"],
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
        "activity_incident_details": {"incident_id": "incident-123"},
        "endpoint_context": [{"endpoint_ip": "10.0.0.1", "users": ["u@example.com"], "emails": ["u@example.com"], "os": "Windows"}],
        "severity": "high",
        "first_contact": "2026-05-12T11:00:00Z",
        "last_contact": "2026-05-12T11:30:00Z",
    }

    payload = serialize_incident_event(
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
    assert payload["data"]["lumu"]["activity_incident_details"] == {"incident_id": "incident-123"}
    assert payload["data"]["lumu"]["endpoint_context"] == [{"endpoint_ip": "10.0.0.1", "users": ["u@example.com"], "emails": ["u@example.com"], "os": "Windows"}]
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
    assert "adversaries" not in payload
    assert "disseminated" not in payload
    assert "extracted_iocs" not in payload


def test_serialize_incident_event_omits_empty_endpoint_context():
    settings = SimpleNamespace(event_type_test_mode=False, payload_timezone="UTC")
    payload = serialize_incident_event(
        event_dict={
            "incident_uuid": "incident-123",
            "title": "Threat title",
            "severity": "medium",
            "endpoint_context": [],
            "activity_incident_details": {},
        },
        tenant_uuid="tenant-fallback",
        tenant_name="Tenant Fallback",
        settings=settings,
        hostname="handler-host",
        agent_id="agent-1",
        agent_ip="10.0.0.5",
    )

    assert "endpoint_context" not in payload["data"]["lumu"]
    assert "activity_incident_details" not in payload["data"]["lumu"]


def test_enrich_incident_fetches_contacts_when_detail_contacts_are_incomplete():
    client = _FakeEnrichmentClient(
        details={
            "contacts": [
                {"endpointIp": "10.0.0.1", "endpointName": "10.0.0.1"},
            ],
        },
        secops_details={
            "counts": {"endpointTargetsCount": 2},
            "targetsSamples": [
                {"endpoint_ip": "10.0.0.1", "name": "10.0.0.1"},
                {"endpoint_ip": "10.0.0.2", "name": "10.0.0.2"},
            ],
            "firstEvent": {"id": "event-1"},
            "relatedEvents": [{"id": "event-2"}],
        },
        contacts=[
            {"endpointIp": "10.0.0.2", "endpointName": "10.0.0.2"},
        ],
        activity_events={
            "event-1": {"uuid": "event-1", "endpointIp": "10.0.0.1"},
            "event-2": {"uuid": "event-2", "endpointIp": "10.0.0.2"},
        },
    )

    result = asyncio.run(
        enrich_incident(
            client=client,
            tenant_uuid="tenant-1",
            company_key="key-1",
            inc_uuid="incident-1",
        )
    )

    assert client.contact_calls == 1
    assert set(client.activity_event_calls) == {"event-1", "event-2"}
    assert result.defender_contacts == [{"endpointIp": "10.0.0.2", "endpointName": "10.0.0.2"}]


def test_enrich_incident_skips_contacts_when_existing_breadth_is_sufficient():
    client = _FakeEnrichmentClient(
        details={
            "contacts": [
                {
                    "endpointIp": "10.0.0.1",
                    "endpointName": "10.0.0.1",
                    "host": "example-1.test",
                    "sourceType": "custom_collector",
                },
                {
                    "endpointIp": "10.0.0.2",
                    "endpointName": "10.0.0.2",
                    "host": "example-2.test",
                    "sourceType": "custom_collector",
                },
            ],
        },
        secops_details={
            "counts": {"endpointTargetsCount": 2},
            "targetsSamples": [
                {"endpoint_ip": "10.0.0.1", "name": "10.0.0.1"},
                {"endpoint_ip": "10.0.0.2", "name": "10.0.0.2"},
            ],
        },
    )

    asyncio.run(
        enrich_incident(
            client=client,
            tenant_uuid="tenant-1",
            company_key="key-1",
            inc_uuid="incident-1",
        )
    )

    assert client.contact_calls == 0


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


def test_builder_builds_bh_airport_style_endpoint_context_from_multiple_sources():
    event = _build_event(
        {
            "id": "incident-1",
            "adversaryId": "embedflix.mom",
            "description": "Malicious behavior",
            "severity": "High",
            "status": "open",
            "timestamp": "2026-05-07T01:55:57.902Z",
            "firstContact": "2026-05-07T01:55:57.902Z",
            "lastContact": "2026-05-07T02:01:15Z",
            "totalEndpoints": 2,
        },
        details={
            "contacts": 20,
            "firstContactDetails": {
                "uuid": "event-1",
                "datetime": "2026-05-07T01:55:57.902Z",
                "host": "embedflix.mom",
                "details": ["Malicious behavior"],
                "types": ["Malware"],
                "endpointIp": "10.144.1.151",
                "endpointName": "10.144.1.151",
                "label": 0,
                "sourceType": "virtual_appliance",
                "sourceId": "src-a",
                "sourceData": {
                    "DNSPacketExtraInfo": {
                        "question": {"type": "HTTPS", "name": "embedflix.mom", "class": "IN"},
                        "responseCode": "NOERROR",
                        "answers": [{"name": "embedflix.mom"}],
                        "opCode": "QUERY",
                    }
                },
                "fromPlayback": False,
            },
            "lastContactDetails": {
                "uuid": "event-2",
                "datetime": "2026-05-07T02:01:15Z",
                "host": "embedflix.mom",
                "path": "/tv/player.php",
                "details": ["Malicious behavior"],
                "types": ["Malware"],
                "endpointIp": "10.144.129.241",
                "endpointName": "10.144.129.241",
                "label": 0,
                "sourceType": "virtual_appliance",
                "sourceId": "src-a",
                "sourceData": {
                    "FirewallEntryExtraInfo": {
                        "source": {"ip": "10.144.129.241", "port": 53758},
                        "destination": {"ip": "172.67.165.10", "port": 443, "name": "embedflix.mom"},
                        "action": "blocked",
                        "protocol": "https",
                        "extraData": {
                            "service": "https",
                            "profile": "GRP_WEB_CORPORATIVO",
                            "devname": "FW01-ADM",
                            "subtype": "webfilter",
                            "msg": "URL belongs to a denied category in policy",
                        },
                    }
                },
                "fromPlayback": False,
            },
        },
        secops_details={
            "id": "incident-1",
            "description": "Malicious behavior",
            "counts": {"endpointTargetsCount": 2, "offendersCount": 1},
            "offendersSamples": [{"value": "embedflix.mom"}],
            "targetsSamples": [
                {"endpoint_ip": "10.144.1.151", "name": "10.144.1.151", "label": "0"},
                {"endpoint_ip": "10.144.129.241", "name": "10.144.129.241", "label": "0"},
            ],
            "firstEvent": {"id": "event-1", "timestamp": "2026-05-07T01:55:57.902Z"},
            "lastEvent": {"id": "event-2", "timestamp": "2026-05-07T02:01:15Z"},
        },
        activity_event_details=[
            {
                "uuid": "event-1",
                "endpointIp": "10.144.1.151",
                "endpointName": "10.144.1.151",
                "host": "embedflix.mom",
                "sourceType": "virtual_appliance",
                "sourceId": "src-a",
                "label": 0,
                "sourceData": {
                    "DNSPacketExtraInfo": {
                        "question": {"type": "HTTPS", "name": "embedflix.mom", "class": "IN"},
                        "responseCode": "NOERROR",
                        "answers": [{"name": "embedflix.mom"}],
                        "opCode": "QUERY",
                    }
                },
                "fromPlayback": False,
            },
            {
                "uuid": "event-2",
                "endpointIp": "10.144.129.241",
                "endpointName": "10.144.129.241",
                "host": "embedflix.mom",
                "path": "/tv/player.php",
                "sourceType": "virtual_appliance",
                "sourceId": "src-a",
                "label": 0,
                "sourceData": {
                    "FirewallEntryExtraInfo": {
                        "source": {"ip": "10.144.129.241", "port": 53758},
                        "destination": {"ip": "172.67.165.10", "port": 443, "name": "embedflix.mom"},
                        "action": "blocked",
                        "protocol": "https",
                    }
                },
                "fromPlayback": False,
            },
        ],
    )

    assert event.activity_incident_details["incident_id"] == "incident-1"
    assert event.activity_incident_details["counts"]["endpointTargetsCount"] == 2
    assert len(event.affected_endpoints) == 2
    assert {endpoint.srcip for endpoint in event.affected_endpoints} == {"10.144.1.151", "10.144.129.241"}
    assert len(event.endpoint_context) == 2

    dns_context = next(context for context in event.endpoint_context if context["endpoint_ip"] == "10.144.1.151")
    assert dns_context["network"]["dns_question_name"] == "embedflix.mom"
    assert "http" not in dns_context
    assert "users" not in dns_context
    assert "emails" not in dns_context

    firewall_context = next(context for context in event.endpoint_context if context["endpoint_ip"] == "10.144.129.241")
    assert firewall_context["http"]["host"] == "embedflix.mom"
    assert firewall_context["http"]["path"] == "/tv/player.php"
    assert firewall_context["network"]["destination_ip"] == "172.67.165.10"
    assert firewall_context["telemetry"]["action"] == "blocked"


def test_builder_extracts_proxy_user_email_and_matching_severity():
    event = _build_event(
        {
            "id": "incident-2",
            "adversaryId": "www.baixesoft.com",
            "description": "Malware family Trojan.generic",
            "severity": "High",
            "status": "closed",
            "timestamp": "2026-05-15T19:11:42.699Z",
            "firstContact": "2026-05-15T19:11:42.699Z",
            "lastContact": "2026-05-15T19:11:53Z",
            "totalEndpoints": 2,
        },
        secops_details={
            "id": "incident-2",
            "counts": {"endpointTargetsCount": 2},
            "targetsSamples": [
                {"endpoint_ip": "10.144.1.151", "name": "10.144.1.151", "label": "0"},
                {"endpoint_ip": "10.144.128.56", "name": "10.144.128.56", "label": "0"},
            ],
        },
        activity_event_details=[
            {
                "uuid": "event-3",
                "endpointIp": "10.144.128.56",
                "endpointName": "10.144.128.56",
                "host": "www.baixesoft.com",
                "path": "/cdn-cgi/rum",
                "sourceType": "custom_collector",
                "sourceId": "src-b",
                "label": 0,
                "sourceData": {
                    "ProxyEntryExtraInfo": {
                        "user": "alan.costa@bh-airport.com.br",
                        "request": {
                            "method": "get",
                            "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Edg/148.0.0.0",
                            "uri": {"scheme": "https", "host": "www.baixesoft.com", "port": 443, "path": "/cdn-cgi/rum"},
                        },
                        "response": {"code": 403, "phrase": "Forbidden"},
                        "remoteIp": "104.26.10.116",
                        "extraData": {
                            "srcip": "201.140.214.35",
                            "traffic_type": "Web",
                            "dst_country": "US",
                            "site": "baixesoft",
                            "src_country": "BR",
                            "severity": "high",
                        },
                    }
                },
                "fromPlayback": False,
            }
        ],
    )

    proxy_context = event.endpoint_context[0]
    assert proxy_context["users"] == ["alan.costa@bh-airport.com.br"]
    assert proxy_context["emails"] == ["alan.costa@bh-airport.com.br"]
    assert proxy_context["os"] == "Windows"
    assert proxy_context["telemetry"]["severity"] == "high"


def test_builder_builds_endpoint_context_from_defender_contacts_when_managed_events_are_missing():
    event = _build_event(
        {
            "id": "incident-contacts",
            "adversaryId": "example.net",
            "description": "Suspicious traffic",
            "severity": "High",
            "status": "open",
            "timestamp": "2026-05-12T12:00:00Z",
            "firstContact": "2026-05-12T12:00:00Z",
            "lastContact": "2026-05-12T12:05:00Z",
            "totalEndpoints": 2,
        },
        contacts=[
            {
                "uuid": "contact-1",
                "endpointIp": "10.0.0.10",
                "endpointName": "10.0.0.10",
                "host": "bad.example.net",
                "path": "/login",
                "sourceType": "custom_collector",
                "sourceId": "src-d",
                "label": 0,
                "sourceData": {
                    "ProxyEntryExtraInfo": {
                        "user": "analyst@example.com",
                        "request": {
                            "method": "get",
                            "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
                            "uri": {"scheme": "https", "host": "bad.example.net", "port": 443, "path": "/login"},
                        },
                        "response": {"code": 403, "phrase": "Forbidden"},
                        "remoteIp": "203.0.113.10",
                        "extraData": {
                            "srcip": "10.0.0.10",
                            "src_country": "BR",
                            "dst_country": "US",
                            "traffic_type": "Web",
                            "site": "bad-example",
                            "severity": "high",
                        },
                    }
                },
            },
            {
                "uuid": "contact-2",
                "endpointIp": "10.0.0.20",
                "endpointName": "10.0.0.20",
                "host": "dns.example.net",
                "sourceType": "virtual_appliance",
                "sourceId": "src-e",
                "label": 0,
                "sourceData": {
                    "DNSPacketExtraInfo": {
                        "question": {"type": "A", "name": "dns.example.net", "class": "IN"},
                        "responseCode": "NOERROR",
                        "answers": [{"name": "dns.example.net"}],
                        "opCode": "QUERY",
                    }
                },
            },
        ],
        secops_details={
            "id": "incident-contacts",
            "counts": {"endpointTargetsCount": 2},
            "targetsSamples": [
                {"endpoint_ip": "10.0.0.10", "name": "10.0.0.10", "label": "0"},
                {"endpoint_ip": "10.0.0.20", "name": "10.0.0.20", "label": "0"},
            ],
        },
    )

    assert len(event.endpoint_context) == 2

    proxy_context = next(context for context in event.endpoint_context if context["endpoint_ip"] == "10.0.0.10")
    assert proxy_context["users"] == ["analyst@example.com"]
    assert proxy_context["emails"] == ["analyst@example.com"]
    assert proxy_context["http"]["host"] == "bad.example.net"
    assert proxy_context["telemetry"]["severity"] == "high"

    dns_context = next(context for context in event.endpoint_context if context["endpoint_ip"] == "10.0.0.20")
    assert dns_context["network"]["dns_question_name"] == "dns.example.net"
    assert "http" not in dns_context
    assert "users" not in dns_context
    assert "emails" not in dns_context


def test_builder_omits_empty_context_and_inconsistent_severity():
    event = _build_event(
        {
            "id": "incident-3",
            "adversaryId": "example.org",
            "severity": "Low",
            "status": "open",
            "timestamp": "2026-05-12T12:00:00Z",
            "firstContact": "2026-05-12T12:00:00Z",
            "lastContact": "2026-05-12T12:00:01Z",
            "totalEndpoints": 1,
        },
        secops_details={
            "id": "incident-3",
            "counts": {"endpointTargetsCount": 1},
            "targetsSamples": [{"endpoint_ip": "10.0.0.2", "name": "10.0.0.2", "label": "0"}],
        },
        activity_event_details=[
            {
                "uuid": "event-4",
                "endpointIp": "10.0.0.2",
                "endpointName": "10.0.0.2",
                "sourceType": "custom_collector",
                "sourceId": "src-c",
                "label": 0,
                "sourceData": {
                    "ProxyEntryExtraInfo": {
                        "extraData": {"severity": "high"},
                    }
                },
            },
            {
                "uuid": "event-5",
                "endpointIp": "10.0.0.3",
                "endpointName": "10.0.0.3",
            },
        ],
    )

    assert len(event.affected_endpoints) == 1
    assert event.endpoint_context == []


class _FakeSchedulerAnalyzer:
    def __init__(self, *, offset=0, next_due="", last_success="", force_reset=False):
        self.offset = offset
        self.open_state_sync_next_due_at = next_due
        self.open_state_sync_last_success_at = last_success
        self.open_state_sync_failure_count = 0
        self.force_offset_reset_applied = force_reset
        self.saved = 0
        self.marked_success = 0
        self.marked_failure = 0

    def _save_state(self):
        self.saved += 1

    def extract_incidents_from_updates(self, updates):
        incidents = []
        for update in updates:
            incident = update.get("IncidentUpdated", {}).get("incident")
            if incident:
                incidents.append(incident)
        return incidents

    def should_process_incident(self, raw_incident):
        return True

    def is_open_state_sync_due(self, now_utc):
        if not self.open_state_sync_next_due_at:
            return True
        parsed = datetime.fromisoformat(self.open_state_sync_next_due_at.replace("Z", "+00:00"))
        return now_utc >= parsed

    def mark_open_state_sync_success(self, now_utc, interval_minutes, jitter_seconds):
        self.marked_success += 1
        self.open_state_sync_last_success_at = now_utc.strftime("%Y-%m-%dT%H:%M:%S.000Z")
        self.open_state_sync_next_due_at = (now_utc + timedelta(minutes=interval_minutes)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
        self.open_state_sync_failure_count = 0

    def mark_open_state_sync_failure(self, now_utc, base_backoff_minutes, max_backoff_minutes):
        self.marked_failure += 1
        self.open_state_sync_failure_count += 1
        self.open_state_sync_next_due_at = (now_utc + timedelta(minutes=base_backoff_minutes)).strftime("%Y-%m-%dT%H:%M:%S.000Z")


class _FakeJournalClient:
    def __init__(
        self,
        updates_response=None,
        *,
        journal_exc=None,
        open_incidents=None,
        open_incidents_exc=None,
        near_daily_cap: bool = False,
    ):
        self.rate_limit_hits = 0
        self._updates_response = updates_response or {"updates": [], "offset": 0}
        self._journal_exc = journal_exc
        self._open_incidents = open_incidents or []
        self._open_incidents_exc = open_incidents_exc
        self._near_daily_cap = near_daily_cap
        self.open_incidents_calls = []
        self.incident_updates_calls = []

    async def get_incident_updates(self, _company_key, offset=0, items=50, delay_time=5):
        self.incident_updates_calls.append({"offset": offset, "items": items, "delay_time": delay_time})
        if self._journal_exc is not None:
            raise self._journal_exc
        return self._updates_response

    async def get_open_incidents(self, _company_key, from_date=None):
        self.open_incidents_calls.append(from_date)
        if self._open_incidents_exc is not None:
            raise self._open_incidents_exc
        return self._open_incidents

    def is_defender_near_daily_cap(self, _company_key, threshold=0.85):
        return self._near_daily_cap

    def get_defender_budget_snapshot(self, _company_key):
        return {
            "minute_count": 35,
            "minute_limit": 35,
            "day_count": 6800,
            "day_limit": 8000,
        }


def _scheduler_settings(**overrides):
    defaults = {
        "lumu_open_state_sync_on_startup": True,
        "lumu_open_state_reconciliation_minutes": 15,
        "lumu_open_state_jitter_seconds": 120,
        "lumu_open_state_failure_backoff_minutes": 30,
        "lumu_open_state_max_backoff_minutes": 360,
        "lumu_journal_items_per_page": 100,
        "lumu_journal_delay_time_seconds": 15,
        "lumu_journal_max_pages_per_cycle": 2,
    }
    defaults.update(overrides)
    return SimpleNamespace(**defaults)


def test_analyzer_open_state_schedule_migrates_missing_fields_and_is_due(monkeypatch):
    state_basename = f"unit_scheduler_{uuid4().hex}.json"
    settings = SimpleNamespace(
        alert_state_file=state_basename,
        lumu_initial_offset=0,
        lumu_initial_time="2026-04-14T00:00:00Z",
        lumu_force_offset=False,
    )
    monkeypatch.setattr(analyzer_module, "get_settings", lambda: settings)

    state_path = Path("data") / f"tenant_a_{state_basename}"
    state_path.write_text(json.dumps({"last_pulled_time": "2026-05-01T00:00:00Z", "offset": 3, "incidents": {}}), encoding="utf-8")
    try:
        analyzer = Analyzer(state_file_key="tenant-a")
        assert analyzer.open_state_sync_last_success_at == ""
        assert analyzer.open_state_sync_next_due_at == ""
        assert analyzer.open_state_sync_failure_count == 0
        assert analyzer.is_open_state_sync_due(datetime(2026, 5, 17, tzinfo=timezone.utc)) is True
    finally:
        if state_path.exists():
            state_path.unlink()


def test_analyzer_open_state_schedule_success_and_failure_backoff(monkeypatch):
    state_basename = f"unit_scheduler_{uuid4().hex}.json"
    settings = SimpleNamespace(
        alert_state_file=state_basename,
        lumu_initial_offset=0,
        lumu_initial_time="2026-04-14T00:00:00Z",
        lumu_force_offset=False,
    )
    monkeypatch.setattr(analyzer_module, "get_settings", lambda: settings)
    monkeypatch.setattr(analyzer_module.random, "randint", lambda _a, _b: 30)

    analyzer = Analyzer(state_file_key=f"tenant-{uuid4().hex}")
    now_utc = datetime(2026, 5, 17, 4, 0, tzinfo=timezone.utc)
    analyzer.mark_open_state_sync_success(now_utc, interval_minutes=15, jitter_seconds=120)
    assert analyzer.open_state_sync_failure_count == 0
    assert analyzer.open_state_sync_next_due_at == "2026-05-17T04:15:30.000Z"

    analyzer.mark_open_state_sync_failure(now_utc, base_backoff_minutes=30, max_backoff_minutes=360)
    analyzer.mark_open_state_sync_failure(now_utc, base_backoff_minutes=30, max_backoff_minutes=360)
    assert analyzer.open_state_sync_failure_count == 2
    assert analyzer.open_state_sync_next_due_at == "2026-05-17T05:00:00.000Z"


def test_should_run_open_state_reconciliation_uses_journal_health_and_schedule():
    now_utc = datetime(2026, 5, 17, 4, 0, tzinfo=timezone.utc)
    analyzer = _FakeSchedulerAnalyzer(
        next_due="2026-05-17T05:00:00Z",
        last_success="2026-05-17T03:00:00Z",
    )

    should_run, reason = should_run_open_state_reconciliation(
        analyzer=analyzer,
        journal_result=JournalSyncResult(),
        now_utc=now_utc,
        settings=_scheduler_settings(),
    )
    assert should_run is False
    assert reason == "not_due"

    should_run, reason = should_run_open_state_reconciliation(
        analyzer=analyzer,
        journal_result=JournalSyncResult(offset_missing=True),
        now_utc=now_utc,
        settings=_scheduler_settings(),
    )
    assert should_run is True
    assert reason == "journal_offset_missing"

    startup_analyzer = _FakeSchedulerAnalyzer()
    should_run, reason = should_run_open_state_reconciliation(
        analyzer=startup_analyzer,
        journal_result=JournalSyncResult(),
        now_utc=now_utc,
        settings=_scheduler_settings(),
    )
    assert should_run is True
    assert reason == "startup"


def test_run_journal_sync_uses_configured_items_delay_and_page_cap(monkeypatch):
    updates_responses = [
        {
            "updates": [
                {"IncidentUpdated": {"incident": {"id": "incident-1", "lastContact": "2026-05-17T04:00:01Z"}}},
                {"IncidentUpdated": {"incident": {"id": "incident-2", "lastContact": "2026-05-17T04:00:02Z"}}},
            ],
            "offset": 11,
        },
        {
            "updates": [
                {"IncidentUpdated": {"incident": {"id": "incident-3", "lastContact": "2026-05-17T04:00:03Z"}}},
                {"IncidentUpdated": {"incident": {"id": "incident-4", "lastContact": "2026-05-17T04:00:04Z"}}},
            ],
            "offset": 12,
        },
    ]

    class _SequencedJournalClient(_FakeJournalClient):
        async def get_incident_updates(self, _company_key, offset=0, items=50, delay_time=5):
            self.incident_updates_calls.append({"offset": offset, "items": items, "delay_time": delay_time})
            return updates_responses.pop(0) if updates_responses else {"updates": [], "offset": offset}

    analyzer = _FakeSchedulerAnalyzer(offset=10, next_due="2099-01-01T00:00:00Z", last_success="2026-05-17T03:00:00Z")
    client = _SequencedJournalClient()

    async def _fake_batch(*_args, **_kwargs):
        return (0, 0)

    monkeypatch.setattr("src.main.process_and_send_batch", _fake_batch)
    monkeypatch.setattr(
        "src.main.get_settings",
        lambda: _scheduler_settings(
            lumu_journal_items_per_page=2,
            lumu_journal_delay_time_seconds=21,
            lumu_journal_max_pages_per_cycle=2,
        ),
    )

    result = asyncio.run(
        run_journal_sync(
            client=client,
            analyzer=analyzer,
            kafka=SimpleNamespace(),
            tenant_uuid="tenant-1",
            tenant_name="Tenant 1",
            company_key="key-1",
            kafka_topic="cli-tenant-1",
        )
    )

    assert len(client.incident_updates_calls) == 2
    assert [call["items"] for call in client.incident_updates_calls] == [2, 2]
    assert [call["delay_time"] for call in client.incident_updates_calls] == [21, 21]
    assert result.processed_count == 4
    assert analyzer.offset == 12


def test_run_journal_sync_slows_down_and_caps_pages_under_daily_budget_pressure(monkeypatch):
    updates_responses = [
        {
            "updates": [
                {"IncidentUpdated": {"incident": {"id": "incident-1", "lastContact": "2026-05-17T04:00:01Z"}}},
                {"IncidentUpdated": {"incident": {"id": "incident-2", "lastContact": "2026-05-17T04:00:02Z"}}},
            ],
            "offset": 11,
        },
        {
            "updates": [
                {"IncidentUpdated": {"incident": {"id": "incident-3", "lastContact": "2026-05-17T04:00:03Z"}}},
                {"IncidentUpdated": {"incident": {"id": "incident-4", "lastContact": "2026-05-17T04:00:04Z"}}},
            ],
            "offset": 12,
        },
    ]

    class _SequencedJournalClient(_FakeJournalClient):
        async def get_incident_updates(self, _company_key, offset=0, items=50, delay_time=5):
            self.incident_updates_calls.append({"offset": offset, "items": items, "delay_time": delay_time})
            return updates_responses.pop(0) if updates_responses else {"updates": [], "offset": offset}

    analyzer = _FakeSchedulerAnalyzer(offset=10, next_due="2099-01-01T00:00:00Z", last_success="2026-05-17T03:00:00Z")
    client = _SequencedJournalClient(near_daily_cap=True)

    async def _fake_batch(*_args, **_kwargs):
        return (0, 0)

    monkeypatch.setattr("src.main.process_and_send_batch", _fake_batch)
    monkeypatch.setattr(
        "src.main.get_settings",
        lambda: _scheduler_settings(
            lumu_journal_items_per_page=2,
            lumu_journal_delay_time_seconds=15,
            lumu_journal_max_pages_per_cycle=2,
        ),
    )

    result = asyncio.run(
        run_journal_sync(
            client=client,
            analyzer=analyzer,
            kafka=SimpleNamespace(),
            tenant_uuid="tenant-1",
            tenant_name="Tenant 1",
            company_key="key-1",
            kafka_topic="cli-tenant-1",
        )
    )

    assert len(client.incident_updates_calls) == 1
    assert client.incident_updates_calls[0]["delay_time"] == 30
    assert result.processed_count == 2
    assert analyzer.offset == 11


def test_run_open_state_reconciliation_uses_full_sweep_and_marks_success(monkeypatch):
    client = _FakeJournalClient(open_incidents=[{"id": "incident-1", "lastContact": "2026-05-17T04:00:00Z"}])
    analyzer = _FakeSchedulerAnalyzer()

    async def _fake_batch(*_args, **kwargs):
        assert kwargs["raw_incidents"][0]["id"] == "incident-1"
        return (1, 0)

    monkeypatch.setattr("src.main.process_and_send_batch", _fake_batch)
    monkeypatch.setattr("src.main.get_settings", lambda: _scheduler_settings())

    success, failed = asyncio.run(
        run_open_state_reconciliation(
            client=client,
            analyzer=analyzer,
            kafka=SimpleNamespace(),
            tenant_uuid="tenant-1",
            tenant_name="Tenant 1",
            company_key="key-1",
            kafka_topic="cli-tenant-1",
            reason="startup",
        )
    )

    assert (success, failed) == (1, 0)
    assert client.open_incidents_calls == [None]
    assert analyzer.marked_success == 1
    assert analyzer.marked_failure == 0


def test_monitor_tenant_skips_open_state_reconciliation_when_journal_is_healthy(monkeypatch):
    future_due = (datetime.now(timezone.utc) + timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
    analyzer = _FakeSchedulerAnalyzer(next_due=future_due, last_success="2026-05-17T03:00:00Z")
    client = _FakeJournalClient(updates_response={"updates": [], "offset": 1})

    asyncio.run(
        monitor_tenant(
            client=client,
            analyzer=analyzer,
            kafka=SimpleNamespace(),
            tenant_uuid="tenant-1",
            tenant_name="Tenant 1",
            company_key="key-1",
            kafka_topic="cli-tenant-1",
        )
    )

    assert client.open_incidents_calls == []


def test_monitor_tenant_runs_open_state_reconciliation_on_startup():
    analyzer = _FakeSchedulerAnalyzer()
    client = _FakeJournalClient(updates_response={"updates": [], "offset": 1}, open_incidents=[])

    asyncio.run(
        monitor_tenant(
            client=client,
            analyzer=analyzer,
            kafka=SimpleNamespace(),
            tenant_uuid="tenant-1",
            tenant_name="Tenant 1",
            company_key="key-1",
            kafka_topic="cli-tenant-1",
        )
    )

    assert client.open_incidents_calls == [None]


def test_monitor_tenant_skips_noncritical_reconciliation_under_budget_pressure(monkeypatch):
    now_utc = datetime(2026, 5, 17, 4, 0, tzinfo=timezone.utc)
    past_due = (now_utc - timedelta(minutes=5)).strftime("%Y-%m-%dT%H:%M:%SZ")
    analyzer = _FakeSchedulerAnalyzer(next_due=past_due, last_success="2026-05-17T03:00:00Z")
    client = _FakeJournalClient(updates_response={"updates": [], "offset": 1}, near_daily_cap=True)

    monkeypatch.setattr("src.main._utc_now", lambda: now_utc)
    monkeypatch.setattr("src.main.get_settings", lambda: _scheduler_settings())

    asyncio.run(
        monitor_tenant(
            client=client,
            analyzer=analyzer,
            kafka=SimpleNamespace(),
            tenant_uuid="tenant-1",
            tenant_name="Tenant 1",
            company_key="key-1",
            kafka_topic="cli-tenant-1",
        )
    )

    assert client.open_incidents_calls == []


def test_run_journal_sync_handles_rate_guard_skip(monkeypatch):
    analyzer = _FakeSchedulerAnalyzer(offset=10)
    client = _FakeJournalClient(
        updates_response={
            "updates": [],
            "offset": 10,
            "_rate_guard_skipped": True,
            "_rate_guard_reason": "journal_circuit_open",
        }
    )
    monkeypatch.setattr("src.main.get_settings", lambda: _scheduler_settings())

    result = asyncio.run(
        run_journal_sync(
            client=client,
            analyzer=analyzer,
            kafka=SimpleNamespace(),
            tenant_uuid="tenant-1",
            tenant_name="Tenant 1",
            company_key="key-1",
            kafka_topic="cli-tenant-1",
        )
    )

    assert result.skipped_by_rate_guard is True
    assert result.skip_reason == "journal_circuit_open"


def test_run_open_state_reconciliation_marks_failure_on_429(monkeypatch):
    request = httpx.Request("POST", "https://defender.lumu.io/api/incidents/all")
    response = httpx.Response(429, request=request)
    client = _FakeJournalClient(open_incidents_exc=httpx.HTTPStatusError("rate limited", request=request, response=response))
    analyzer = _FakeSchedulerAnalyzer()
    monkeypatch.setattr("src.main.get_settings", lambda: _scheduler_settings())

    success, failed = asyncio.run(
        run_open_state_reconciliation(
            client=client,
            analyzer=analyzer,
            kafka=SimpleNamespace(),
            tenant_uuid="tenant-1",
            tenant_name="Tenant 1",
            company_key="key-1",
            kafka_topic="cli-tenant-1",
            reason="periodic_due",
        )
    )

    assert (success, failed) == (0, 0)
    assert analyzer.marked_failure == 1


def test_config_validates_tenant_scheduler_controls():
    with pytest.raises(ValidationError):
        Settings(
            lumu_email="user@example.com",
            lumu_password="secret",
            lumu_mssp_uuid="mssp-uuid",
            lumu_tenant_concurrency_cap=0,
        )

    with pytest.raises(ValidationError):
        Settings(
            lumu_email="user@example.com",
            lumu_password="secret",
            lumu_mssp_uuid="mssp-uuid",
            lumu_tenant_cycle_jitter_max_seconds=-1,
        )

    settings = Settings(
        lumu_email="user@example.com",
        lumu_password="secret",
        lumu_mssp_uuid="mssp-uuid",
        lumu_tenant_concurrency_cap=3,
        lumu_tenant_cycle_jitter_max_seconds=5,
    )
    assert settings.lumu_tenant_concurrency_cap == 3
    assert settings.lumu_tenant_cycle_jitter_max_seconds == 5


def test_run_tenant_batch_enforces_global_concurrency_cap(monkeypatch):
    state = {"active": 0, "max": 0, "calls": 0}

    async def _fake_monitor_tenant(*_args, **_kwargs):
        state["active"] += 1
        state["max"] = max(state["max"], state["active"])
        state["calls"] += 1
        await asyncio.sleep(0.02)
        state["active"] -= 1

    monkeypatch.setattr("src.main.monitor_tenant", _fake_monitor_tenant)
    monkeypatch.setattr("src.main._compute_tenant_cycle_jitter_seconds", lambda _max_seconds: 0.0)

    tenant_registry = {
        f"tenant-{idx}": TenantRuntime(
            tenant_uuid=f"tenant-{idx}",
            tenant_name=f"Tenant {idx}",
            defender_api_key=f"key-{idx}",
            kafka_topic=f"cli-tenant-{idx}",
        )
        for idx in range(7)
    }
    analyzers_by_tenant = {tenant_uuid: SimpleNamespace() for tenant_uuid in tenant_registry.keys()}

    asyncio.run(
        run_tenant_batch(
            client=SimpleNamespace(),
            kafka=SimpleNamespace(),
            analyzers_by_tenant=analyzers_by_tenant,
            tenant_registry=tenant_registry,
            settings=SimpleNamespace(
                lumu_tenant_concurrency_cap=3,
                lumu_tenant_cycle_jitter_max_seconds=5,
            ),
        )
    )

    assert state["calls"] == 7
    assert state["max"] <= 3


def test_run_tenant_batch_applies_per_tenant_jitter(monkeypatch):
    start_times = []
    loop_time_holder = {"start": 0.0}

    async def _fake_monitor_tenant(*_args, **_kwargs):
        start_times.append(asyncio.get_running_loop().time() - loop_time_holder["start"])

    monkeypatch.setattr("src.main.monitor_tenant", _fake_monitor_tenant)
    monkeypatch.setattr("src.main._compute_tenant_cycle_jitter_seconds", lambda _max_seconds: 0.05)

    tenant_registry = {
        "tenant-1": TenantRuntime("tenant-1", "Tenant 1", "key-1", "cli-tenant-1"),
        "tenant-2": TenantRuntime("tenant-2", "Tenant 2", "key-2", "cli-tenant-2"),
    }
    analyzers_by_tenant = {tenant_uuid: SimpleNamespace() for tenant_uuid in tenant_registry.keys()}

    async def _run():
        loop_time_holder["start"] = asyncio.get_running_loop().time()
        await run_tenant_batch(
            client=SimpleNamespace(),
            kafka=SimpleNamespace(),
            analyzers_by_tenant=analyzers_by_tenant,
            tenant_registry=tenant_registry,
            settings=SimpleNamespace(
                lumu_tenant_concurrency_cap=1,
                lumu_tenant_cycle_jitter_max_seconds=5,
            ),
        )

    asyncio.run(_run())

    assert len(start_times) == 2
    assert start_times[0] >= 0.04
    assert (start_times[1] - start_times[0]) >= 0.04


def test_run_tenant_batch_survives_single_tenant_failure(monkeypatch):
    completed = []

    async def _fake_monitor_tenant(*_args, **kwargs):
        tenant_uuid = kwargs["tenant_uuid"]
        if tenant_uuid == "tenant-2":
            raise RuntimeError("boom")
        completed.append(tenant_uuid)

    monkeypatch.setattr("src.main.monitor_tenant", _fake_monitor_tenant)
    monkeypatch.setattr("src.main._compute_tenant_cycle_jitter_seconds", lambda _max_seconds: 0.0)

    tenant_registry = {
        "tenant-1": TenantRuntime("tenant-1", "Tenant 1", "key-1", "cli-tenant-1"),
        "tenant-2": TenantRuntime("tenant-2", "Tenant 2", "key-2", "cli-tenant-2"),
        "tenant-3": TenantRuntime("tenant-3", "Tenant 3", "key-3", "cli-tenant-3"),
    }
    analyzers_by_tenant = {tenant_uuid: SimpleNamespace() for tenant_uuid in tenant_registry.keys()}

    asyncio.run(
        run_tenant_batch(
            client=SimpleNamespace(),
            kafka=SimpleNamespace(),
            analyzers_by_tenant=analyzers_by_tenant,
            tenant_registry=tenant_registry,
            settings=SimpleNamespace(
                lumu_tenant_concurrency_cap=3,
                lumu_tenant_cycle_jitter_max_seconds=5,
            ),
        )
    )

    assert set(completed) == {"tenant-1", "tenant-3"}
