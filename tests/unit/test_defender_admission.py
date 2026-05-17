import asyncio
from types import SimpleNamespace

from src.lumu_client import LumuSession


class _Secret:
    def __init__(self, value: str):
        self._value = value

    def get_secret_value(self) -> str:
        return self._value


def _settings(**overrides):
    defaults = {
        "lumu_api_base_url": "https://managed.lumu.io",
        "verify_ssl": True,
        "lumu_defender_url": "https://defender.lumu.io",
        "lumu_email": "user@example.com",
        "lumu_password": _Secret("secret"),
        "lumu_defender_budget_enforce": False,
        "lumu_defender_budget_minute_limit": 35,
        "lumu_defender_budget_day_limit": 8000,
        "lumu_defender_use_max_items_param": True,
        "lumu_defender_max_items_param": 500,
        "lumu_max_retries": 0,
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
    monkeypatch.setattr("src.lumu_client.get_settings", lambda: _settings(**settings_overrides))
    session = LumuSession()
    return session


def test_global_admission_spacing(monkeypatch):
    session = _build_session(monkeypatch, lumu_defender_global_min_interval_seconds=2.5, lumu_defender_journal_min_interval_seconds=5.0)
    now = {"value": 100.0}

    def _now():
        return now["value"]

    async def _no_sleep(seconds):
        now["value"] += seconds

    monkeypatch.setattr(session, "_now_monotonic", _now)
    monkeypatch.setattr("src.lumu_client.asyncio.sleep", _no_sleep)

    asyncio.run(session._admission_wait_and_reserve("open_incidents_state"))
    first = now["value"]
    asyncio.run(session._admission_wait_and_reserve("open_incidents_state"))
    second = now["value"]
    assert (second - first) >= 2.5


def test_journal_admission_spacing(monkeypatch):
    session = _build_session(monkeypatch, lumu_defender_global_min_interval_seconds=1.0, lumu_defender_journal_min_interval_seconds=5.0)
    now = {"value": 100.0}

    def _now():
        return now["value"]

    async def _no_sleep(seconds):
        now["value"] += seconds

    monkeypatch.setattr(session, "_now_monotonic", _now)
    monkeypatch.setattr("src.lumu_client.asyncio.sleep", _no_sleep)

    asyncio.run(session._admission_wait_and_reserve("open_incidents_updates"))
    first = now["value"]
    asyncio.run(session._admission_wait_and_reserve("open_incidents_updates"))
    second = now["value"]
    assert (second - first) >= 5.0


def test_register_429_opens_journal_breaker(monkeypatch):
    session = _build_session(monkeypatch, lumu_defender_journal_circuit_breaker_threshold=2)
    now = {"value": 50.0}
    monkeypatch.setattr(session, "_now_monotonic", lambda: now["value"])

    asyncio.run(session._register_defender_429("open_incidents_updates", 30.0))
    assert session._journal_breaker_state == "closed"
    asyncio.run(session._register_defender_429("open_incidents_updates", 30.0))
    assert session._journal_breaker_state == "open"


def test_journal_breaker_skip_and_half_open(monkeypatch):
    session = _build_session(monkeypatch, lumu_defender_journal_circuit_breaker_threshold=1, lumu_defender_journal_circuit_breaker_open_seconds=10, lumu_defender_journal_circuit_breaker_half_open_probe_seconds=2)
    now = {"value": 100.0}
    monkeypatch.setattr(session, "_now_monotonic", lambda: now["value"])

    asyncio.run(session._register_defender_429("open_incidents_updates", 10.0, "tenant-a"))
    try:
        asyncio.run(session._admission_wait_and_reserve("open_incidents_updates", "tenant-a"))
        assert False
    except RuntimeError as exc:
        assert str(exc) in {"journal_circuit_open", "journal_tenant_cooldown"}

    now["value"] = 111.0
    asyncio.run(session._admission_wait_and_reserve("open_incidents_updates", "tenant-a"))
    assert session._journal_breaker_state == "half_open"
    asyncio.run(session._register_defender_success("open_incidents_updates"))
    assert session._journal_breaker_state == "closed"


def test_journal_cooldown_is_tenant_scoped(monkeypatch):
    session = _build_session(monkeypatch, lumu_defender_journal_circuit_breaker_enabled=False)
    now = {"value": 100.0}
    monkeypatch.setattr(session, "_now_monotonic", lambda: now["value"])

    asyncio.run(session._register_defender_429("open_incidents_updates", 50.0, "tenant-a-key"))
    try:
        asyncio.run(session._admission_wait_and_reserve("open_incidents_updates", "tenant-a-key"))
        assert False
    except RuntimeError as exc:
        assert str(exc) == "journal_tenant_cooldown"

    asyncio.run(session._admission_wait_and_reserve("open_incidents_updates", "tenant-b-key"))
