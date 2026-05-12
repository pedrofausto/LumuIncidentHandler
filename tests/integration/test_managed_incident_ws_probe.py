import asyncio
import json
import os
import ssl
from typing import Any

import pytest
import websockets

from src.lumu_client import LumuSession


REQUIRED_ENV = [
    "LUMU_EMAIL",
    "LUMU_PASSWORD",
    "LUMU_MSSP_UUID",
]


def _missing_required_env() -> list[str]:
    return [name for name in REQUIRED_ENV if not os.getenv(name)]


def _extract_incident_payload(message: Any) -> dict[str, Any]:
    if isinstance(message, dict):
        for key in ("incident", "open", "closed", "payload", "data"):
            value = message.get(key)
            if isinstance(value, dict):
                return value
        for value in message.values():
            if isinstance(value, dict) and (
                "firstEvent" in value
                or "lastEvent" in value
                or "counts" in value
                or "targetsSamples" in value
            ):
                return value
    return {}


@pytest.fixture(scope="module")
def _require_live_env() -> None:
    missing = _missing_required_env()
    if missing:
        pytest.skip(f"Skipping live WS probe: missing env vars {', '.join(missing)}")


@pytest.fixture(scope="module")
def anyio_backend():
    return "asyncio"


@pytest.fixture(scope="module")
async def ws_probe_messages(_require_live_env) -> list[dict[str, Any]]:
    capture_seconds = float(os.getenv("WS_CAPTURE_SECONDS", "20"))
    max_messages = int(os.getenv("WS_MAX_MESSAGES", "15"))

    async with LumuSession() as client:
        await client.authenticate()
        token_header = client.bearer_token or ""
        token = token_header.replace("Bearer ", "").strip()
        if not token:
            pytest.skip("Managed authentication did not return bearer token for WS probe.")

    ws_url = (
        "wss://managed.lumu.io/data-api/secops-incidents/companies/incidents/updates/msp/subscribe"
        f"?access_token={token}"
    )
    captured: list[dict[str, Any]] = []
    end_at = asyncio.get_running_loop().time() + capture_seconds

    verify_ssl = str(os.getenv("VERIFY_SSL", "True")).strip().lower() in {"1", "true", "yes", "on"}
    ssl_context = None
    if not verify_ssl:
        ssl_context = ssl._create_unverified_context()

    async with websockets.connect(ws_url, ping_interval=20, ping_timeout=20, ssl=ssl_context) as ws:
        while asyncio.get_running_loop().time() < end_at and len(captured) < max_messages:
            try:
                raw = await asyncio.wait_for(ws.recv(), timeout=3.0)
            except asyncio.TimeoutError:
                continue

            try:
                parsed = json.loads(raw)
            except json.JSONDecodeError:
                continue

            incident = _extract_incident_payload(parsed)
            if not incident:
                continue

            captured.append(
                {
                    "incident_uuid": incident.get("id") or incident.get("uuid"),
                    "firstEvent": incident.get("firstEvent"),
                    "lastEvent": incident.get("lastEvent"),
                    "counts": incident.get("counts"),
                    "targetsSamples": incident.get("targetsSamples"),
                    "detectorType": incident.get("detectorType"),
                    "raw_event_keys": sorted(parsed.keys()) if isinstance(parsed, dict) else [],
                }
            )

    print("\n=== Managed WS Probe Summary ===")
    print(f"messages_captured={len(captured)} capture_seconds={capture_seconds}")
    for idx, row in enumerate(captured, start=1):
        print(f"msg#{idx} incident_uuid={row.get('incident_uuid')} detectorType={row.get('detectorType')}")
        print(f"  firstEvent={row.get('firstEvent')}")
        print(f"  lastEvent={row.get('lastEvent')}")
        print(f"  counts={row.get('counts')}")
        samples = row.get("targetsSamples")
        sample_preview = samples[:2] if isinstance(samples, list) else samples
        print(f"  targetSamples_preview={sample_preview}")
        print(f"  raw_event_keys={row.get('raw_event_keys')}")

    return captured


@pytest.mark.integration
@pytest.mark.live
@pytest.mark.anyio
async def test_ws_probe_captures_messages(ws_probe_messages: list[dict[str, Any]]):
    assert isinstance(ws_probe_messages, list)


@pytest.mark.integration
@pytest.mark.live
@pytest.mark.anyio
async def test_ws_probe_extracts_incident_fields(ws_probe_messages: list[dict[str, Any]]):
    if not ws_probe_messages:
        pytest.skip("No incident update messages captured in probe window.")

    has_first_or_last = any(m.get("firstEvent") or m.get("lastEvent") for m in ws_probe_messages)
    has_counts_or_samples = any(m.get("counts") or m.get("targetsSamples") for m in ws_probe_messages)

    assert has_first_or_last or has_counts_or_samples
