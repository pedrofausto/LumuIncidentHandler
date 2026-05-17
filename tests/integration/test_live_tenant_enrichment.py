import asyncio
from dataclasses import asdict

import pytest

from src.analyzer import Analyzer
from src.config import get_settings
from src.enrichment_fetcher import fetch_incident_bundle
from src.incident_builder import build_incident_event
from src.lumu_client import LumuSession
from src.payload_serializer import serialize_incident_event


SETTINGS = get_settings()

LIVE_CASES = [
    {
        "tenant_name": "Grupo Amil",
        "tenant_uuid": "ff512fd8-5bea-4ba7-96f8-aa6e081a667d",
        "incident_uuid": "a40293d0-4e18-11f1-b8ad-5ba8f2bc806d",
        "from_date": "2026-05-01T00:00:00.000Z",
        "to_date": "2026-05-31T23:59:59.000Z",
        "expected_endpoints": 1,
        "expected_contexts": 1,
        "expect_user_context": False,
    },
    {
        "tenant_name": "BH-Airport",
        "tenant_uuid": "e4d0e75d-a215-46c9-804b-1e569be3369d",
        "incident_uuid": "f4cde410-5091-11f1-ba34-0525377bcc69",
        "from_date": "2026-05-01T00:00:00.000Z",
        "to_date": "2026-05-31T23:59:59.000Z",
        "expected_endpoints": 2,
        "expected_contexts": 2,
        "expect_user_context": True,
    },
]


async def _get_defender_key(client: LumuSession, tenant_uuid: str) -> str:
    endpoint = (
        f"/api/msp/companies/{SETTINGS.lumu_mssp_uuid}/"
        f"supervised_companies/{tenant_uuid}/defender_api_key"
    )
    data = await client.get_with_auth(endpoint)
    key = str(data.get("defender_api_key") or "").strip()
    assert key, f"defender_api_key missing for tenant {tenant_uuid}"
    return key


async def _get_raw_incident(client: LumuSession, defender_key: str, incident_uuid: str, from_date: str, to_date: str) -> dict:
    url = f"{client.settings.lumu_defender_url}/api/incidents/all"
    params = {"key": defender_key}
    page = 1
    while page <= 10:
        payload = {
            "status": ["open", "closed"],
            "fromDate": from_date,
            "toDate": to_date,
            "pagination": {"page": page, "items": 50},
        }
        response = await client._request_with_retry(
            "POST",
            url,
            params=params,
            json_data=payload,
            auth_required=False,
        )
        data = response.json()
        items = data.get("items", []) if isinstance(data, dict) else []
        for item in items:
            if (item.get("id") or item.get("uuid")) == incident_uuid:
                return item
        if len(items) < 50:
            break
        page += 1
    raise AssertionError(f"incident {incident_uuid} not found in Defender history window")


def _assert_context_is_meaningful(context: dict) -> None:
    assert "domains" not in context
    meaningful_keys = set(context.keys()) - {"endpoint_ip", "endpoint_name"}
    assert meaningful_keys, f"null-only endpoint context emitted: {context}"
    for nested_key in ("http", "network", "telemetry"):
        if nested_key in context:
            assert context[nested_key], f"empty nested section emitted for {nested_key}: {context}"


@pytest.mark.integration
@pytest.mark.live
@pytest.mark.parametrize("case", LIVE_CASES, ids=[case["tenant_name"] for case in LIVE_CASES])
def test_live_tenant_enrichment(case):
    async def _run():
        async with LumuSession() as client:
            await client.authenticate()
            defender_key = await _get_defender_key(client, case["tenant_uuid"])
            raw_incident = await _get_raw_incident(
                client,
                defender_key,
                case["incident_uuid"],
                case["from_date"],
                case["to_date"],
            )
            bundle = await fetch_incident_bundle(
                client=client,
                tenant_uuid=case["tenant_uuid"],
                defender_key=defender_key,
                incident_uuid=case["incident_uuid"],
            )
            analyzer = Analyzer(state_file_key=f"live_{case['tenant_uuid']}")
            event = build_incident_event(
                raw_incident=raw_incident,
                bundle=bundle,
                event_type=analyzer.classify_incident_event_type(raw_incident),
            )

            assert len(event.affected_endpoints) == case["expected_endpoints"]
            assert len(event.endpoint_context) == case["expected_contexts"]
            for context in event.endpoint_context:
                _assert_context_is_meaningful(context)

            if case["expect_user_context"]:
                assert any(context.get("users") or context.get("emails") for context in event.endpoint_context)

            payload = serialize_incident_event(
                event_dict={
                    **asdict(event),
                    "customer_name": case["tenant_name"],
                    "customer_uuid": case["tenant_uuid"],
                },
                tenant_uuid=case["tenant_uuid"],
                tenant_name=case["tenant_name"],
                settings=SETTINGS,
                hostname="live-test-host",
                agent_id="live-test-agent",
                agent_ip="127.0.0.1",
            )

            assert payload["data"]["lumu"]["id"] == case["incident_uuid"]
            assert len(payload["data"]["lumu"]["affected_endpoints"]) == case["expected_endpoints"]
            assert len(payload["data"]["lumu"]["endpoint_context"]) == case["expected_contexts"]
            assert "lumu" not in payload

        return True

    assert asyncio.run(_run()) is True
