import asyncio
from types import SimpleNamespace

import httpx

from src.lumu_client import LumuSession


class _Secret:
    def __init__(self, value: str):
        self._value = value

    def get_secret_value(self) -> str:
        return self._value


class _FakeHttpClient:
    def __init__(self, responses):
        self._responses = list(responses)
        self.calls = []

    async def request(self, method, url, headers=None, params=None, json=None):
        self.calls.append(
            {
                "method": method,
                "url": url,
                "headers": headers or {},
                "params": dict(params or {}),
                "json": json,
            }
        )
        status_code, payload = self._responses.pop(0)
        request = httpx.Request(method, url, params=params)
        return httpx.Response(status_code, request=request, json=payload)

    async def aclose(self):
        return None


def _build_settings(**overrides):
    defaults = {
        "lumu_api_base_url": "https://managed.lumu.io",
        "verify_ssl": True,
        "lumu_defender_url": "https://defender.lumu.io",
        "lumu_email": "user@example.com",
        "lumu_password": _Secret("secret"),
        "lumu_defender_budget_enforce": True,
        "lumu_defender_budget_minute_limit": 35,
        "lumu_defender_budget_day_limit": 8000,
        "lumu_defender_use_max_items_param": True,
        "lumu_defender_max_items_param": 500,
        "lumu_max_retries": 2,
        "lumu_initial_backoff": 0.01,
        "lumu_defender_global_min_interval_seconds": 2.5,
        "lumu_defender_journal_min_interval_seconds": 5.0,
        "lumu_defender_journal_retry_after_floor_seconds": 30.0,
        "lumu_defender_endpoint_cooldown_default_seconds": 60,
        "lumu_defender_journal_circuit_breaker_enabled": True,
        "lumu_defender_journal_circuit_breaker_threshold": 3,
        "lumu_defender_journal_circuit_breaker_open_seconds": 600,
        "lumu_defender_journal_circuit_breaker_half_open_probe_seconds": 60,
        "lumu_defender_retry_respect_retry_after": True,
    }
    defaults.update(overrides)
    return SimpleNamespace(**defaults)


def _build_session(monkeypatch, **settings_overrides):
    settings = _build_settings(**settings_overrides)
    monkeypatch.setattr("src.lumu_client.get_settings", lambda: settings)
    session = LumuSession()
    session._min_request_interval = 0.0
    return session


def test_defender_budget_counts_retry_attempts(monkeypatch):
    async def _no_sleep(_seconds):
        return None

    session = _build_session(monkeypatch, lumu_max_retries=1)
    session.client = _FakeHttpClient(
        [
            (429, {"error": "rate_limited"}),
            (200, {"updates": [], "offset": 1}),
        ]
    )
    monkeypatch.setattr("src.lumu_client.asyncio.sleep", _no_sleep)

    response = asyncio.run(
        session._request_with_retry(
            "GET",
            "https://defender.lumu.io/api/incidents/all",
            params={"key": "tenant-key", "offset": 0, "items": 10, "time": 5},
            auth_required=False,
            company_key="tenant-key",
            endpoint_name="open_incidents_state",
        )
    )

    assert response.status_code == 200
    snapshot = session.get_defender_budget_snapshot("tenant-key")
    assert snapshot["minute_count"] >= 1
    assert snapshot["day_count"] >= 1
    assert session.rate_limit_hits == 1


def test_max_items_fallback_is_cached_per_endpoint(monkeypatch):
    session = _build_session(monkeypatch)
    session.client = _FakeHttpClient(
        [
            (400, {"error": "unsupported_param"}),
            (200, {"updates": [], "offset": 100}),
            (200, {"updates": [], "offset": 101}),
        ]
    )

    first = asyncio.run(session.get_incident_updates("tenant-key", offset=100, items=10, delay_time=15))
    second = asyncio.run(session.get_incident_updates("tenant-key", offset=101, items=10, delay_time=15))

    assert first["offset"] == 100
    assert second["offset"] == 101
    assert len(session.client.calls) == 3
    assert session.client.calls[0]["params"]["max-items"] == 500
    assert "max-items" not in session.client.calls[1]["params"]
    assert "max-items" not in session.client.calls[2]["params"]
