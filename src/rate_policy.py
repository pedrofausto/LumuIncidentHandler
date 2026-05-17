from dataclasses import dataclass
from typing import Literal, Optional


@dataclass(frozen=True)
class RatePolicy:
    profile: Literal["strict", "balanced", "aggressive"]
    tenant_concurrency_cap: int
    tenant_cycle_jitter_max_seconds: int
    defender_budget_enforce: bool
    defender_budget_minute_limit: int
    defender_budget_day_limit: int
    journal_items_per_page: int
    journal_delay_time_seconds: int
    journal_max_pages_per_cycle: int
    defender_global_min_interval_seconds: float
    defender_journal_min_interval_seconds: float
    defender_journal_retry_after_floor_seconds: float
    defender_endpoint_cooldown_default_seconds: int
    defender_journal_circuit_breaker_enabled: bool
    defender_journal_circuit_breaker_threshold: int
    defender_journal_circuit_breaker_open_seconds: int
    defender_journal_circuit_breaker_half_open_probe_seconds: int
    defender_retry_respect_retry_after: bool
    max_retries: int
    initial_backoff: float
    defender_max_items_param: int
    defender_use_max_items_param: bool


PROFILE_DEFAULTS = {
    "strict": RatePolicy(
        profile="strict",
        tenant_concurrency_cap=1,
        tenant_cycle_jitter_max_seconds=20,
        defender_budget_enforce=True,
        defender_budget_minute_limit=20,
        defender_budget_day_limit=6000,
        journal_items_per_page=50,
        journal_delay_time_seconds=30,
        journal_max_pages_per_cycle=1,
        defender_global_min_interval_seconds=2.5,
        defender_journal_min_interval_seconds=5.0,
        defender_journal_retry_after_floor_seconds=30.0,
        defender_endpoint_cooldown_default_seconds=60,
        defender_journal_circuit_breaker_enabled=True,
        defender_journal_circuit_breaker_threshold=3,
        defender_journal_circuit_breaker_open_seconds=600,
        defender_journal_circuit_breaker_half_open_probe_seconds=60,
        defender_retry_respect_retry_after=True,
        max_retries=2,
        initial_backoff=2.0,
        defender_max_items_param=500,
        defender_use_max_items_param=True,
    ),
    "balanced": RatePolicy(
        profile="balanced",
        tenant_concurrency_cap=2,
        tenant_cycle_jitter_max_seconds=10,
        defender_budget_enforce=True,
        defender_budget_minute_limit=30,
        defender_budget_day_limit=8000,
        journal_items_per_page=75,
        journal_delay_time_seconds=20,
        journal_max_pages_per_cycle=1,
        defender_global_min_interval_seconds=2.5,
        defender_journal_min_interval_seconds=5.0,
        defender_journal_retry_after_floor_seconds=30.0,
        defender_endpoint_cooldown_default_seconds=60,
        defender_journal_circuit_breaker_enabled=True,
        defender_journal_circuit_breaker_threshold=3,
        defender_journal_circuit_breaker_open_seconds=600,
        defender_journal_circuit_breaker_half_open_probe_seconds=60,
        defender_retry_respect_retry_after=True,
        max_retries=3,
        initial_backoff=2.0,
        defender_max_items_param=500,
        defender_use_max_items_param=True,
    ),
    "aggressive": RatePolicy(
        profile="aggressive",
        tenant_concurrency_cap=3,
        tenant_cycle_jitter_max_seconds=5,
        defender_budget_enforce=True,
        defender_budget_minute_limit=35,
        defender_budget_day_limit=9000,
        journal_items_per_page=100,
        journal_delay_time_seconds=15,
        journal_max_pages_per_cycle=2,
        defender_global_min_interval_seconds=2.0,
        defender_journal_min_interval_seconds=4.0,
        defender_journal_retry_after_floor_seconds=20.0,
        defender_endpoint_cooldown_default_seconds=45,
        defender_journal_circuit_breaker_enabled=True,
        defender_journal_circuit_breaker_threshold=4,
        defender_journal_circuit_breaker_open_seconds=300,
        defender_journal_circuit_breaker_half_open_probe_seconds=30,
        defender_retry_respect_retry_after=True,
        max_retries=4,
        initial_backoff=1.5,
        defender_max_items_param=500,
        defender_use_max_items_param=True,
    ),
}


def build_rate_policy(
    *,
    profile: Literal["strict", "balanced", "aggressive"],
    tenant_cap_override: Optional[int],
    advanced: bool,
    expert_values: dict,
) -> RatePolicy:
    base = PROFILE_DEFAULTS[profile]
    values = base.__dict__.copy()
    if tenant_cap_override is not None:
        values["tenant_concurrency_cap"] = int(tenant_cap_override)
    if advanced:
        values.update(expert_values)
    return RatePolicy(**values)


def resolve_rate_policy_from_settings(settings_obj):
    if hasattr(settings_obj, "resolve_rate_policy"):
        return settings_obj.resolve_rate_policy()

    profile = getattr(settings_obj, "lumu_rate_policy_profile", "balanced")
    tenant_cap_override = getattr(settings_obj, "lumu_rate_policy_tenant_cap", None)
    advanced = getattr(settings_obj, "lumu_rate_policy_advanced", True)

    expert_keys = {
        "tenant_concurrency_cap": "lumu_tenant_concurrency_cap",
        "tenant_cycle_jitter_max_seconds": "lumu_tenant_cycle_jitter_max_seconds",
        "defender_budget_enforce": "lumu_defender_budget_enforce",
        "defender_budget_minute_limit": "lumu_defender_budget_minute_limit",
        "defender_budget_day_limit": "lumu_defender_budget_day_limit",
        "journal_items_per_page": "lumu_journal_items_per_page",
        "journal_delay_time_seconds": "lumu_journal_delay_time_seconds",
        "journal_max_pages_per_cycle": "lumu_journal_max_pages_per_cycle",
        "defender_global_min_interval_seconds": "lumu_defender_global_min_interval_seconds",
        "defender_journal_min_interval_seconds": "lumu_defender_journal_min_interval_seconds",
        "defender_journal_retry_after_floor_seconds": "lumu_defender_journal_retry_after_floor_seconds",
        "defender_endpoint_cooldown_default_seconds": "lumu_defender_endpoint_cooldown_default_seconds",
        "defender_journal_circuit_breaker_enabled": "lumu_defender_journal_circuit_breaker_enabled",
        "defender_journal_circuit_breaker_threshold": "lumu_defender_journal_circuit_breaker_threshold",
        "defender_journal_circuit_breaker_open_seconds": "lumu_defender_journal_circuit_breaker_open_seconds",
        "defender_journal_circuit_breaker_half_open_probe_seconds": "lumu_defender_journal_circuit_breaker_half_open_probe_seconds",
        "defender_retry_respect_retry_after": "lumu_defender_retry_respect_retry_after",
        "max_retries": "lumu_max_retries",
        "initial_backoff": "lumu_initial_backoff",
        "defender_max_items_param": "lumu_defender_max_items_param",
        "defender_use_max_items_param": "lumu_defender_use_max_items_param",
    }
    expert_values = {}
    for policy_key, settings_key in expert_keys.items():
        if hasattr(settings_obj, settings_key):
            expert_values[policy_key] = getattr(settings_obj, settings_key)

    return build_rate_policy(
        profile=profile,
        tenant_cap_override=tenant_cap_override,
        advanced=advanced,
        expert_values=expert_values,
    )
