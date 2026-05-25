from functools import lru_cache
import logging
import os
from typing import Literal, Optional

from pydantic import EmailStr, Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    # Lumu Authentication
    lumu_email: EmailStr = Field(..., description="The email address used to authenticate with Lumu MSSP Console")
    lumu_password: SecretStr = Field(..., description="The password for the Lumu MSSP Console account")

    # Lumu API
    lumu_api_base_url: str = Field("https://managed.lumu.io", description="Base URL for Lumu managed console")
    lumu_mssp_uuid: str = Field(..., description="The unique UUID for the MSSP holding supervised companies")

    # Lumu Defender API
    lumu_defender_url: str = Field("https://defender.lumu.io", description="Base URL for Lumu Defender API")
    lumu_defender_key: Optional[SecretStr] = Field(
        None,
        description="Legacy single-tenant Defender API key (unused in multi-tenant mode)",
    )
    customer_uuid: Optional[str] = Field(
        None,
        description="Legacy single-tenant customer UUID (unused in multi-tenant mode)",
    )
    customer_name: Optional[str] = Field(
        None,
        description="Legacy single-tenant customer name (unused in multi-tenant mode)",
    )

    # Orchestration
    polling_interval_minutes: int = Field(5, description="Frequency of Lumu polling in minutes")
    lumu_initial_offset: int = Field(0, description="Initial offset to start fetching updates if no state exists")
    lumu_initial_time: str = Field("2026-04-14T00:00:00Z", description="Initial fromDate timestamp for open incidents sync")
    lumu_force_offset: bool = Field(False, description="If True, overrides the persisted state offset with lumu_initial_offset.")
    verify_ssl: bool = Field(True, description="Enable or disable SSL verification for all API clients")
    lumu_open_state_reconciliation_minutes: int = Field(15, description="How often to run a full open-incidents reconciliation sweep per tenant")
    lumu_open_state_jitter_seconds: int = Field(120, description="Jitter applied to per-tenant open-state reconciliation scheduling")
    lumu_open_state_failure_backoff_minutes: int = Field(30, description="Base backoff in minutes after a failed open-state reconciliation")
    lumu_open_state_max_backoff_minutes: int = Field(360, description="Maximum backoff in minutes after repeated reconciliation failures")
    lumu_open_state_sync_on_startup: bool = Field(True, description="If True, perform an open-state reconciliation before relying solely on journal updates")
    lumu_tenant_concurrency_cap: int = Field(3, description="Maximum number of tenants processed in parallel per polling cycle")
    lumu_tenant_cycle_jitter_max_seconds: int = Field(5, description="Max random delay before each tenant run to reduce synchronized API bursts")
    lumu_defender_budget_minute_limit: int = Field(35, description="Per-tenant Defender request budget per minute")
    lumu_defender_budget_day_limit: int = Field(8000, description="Per-tenant Defender request budget per day (UTC)")
    lumu_defender_budget_enforce: bool = Field(True, description="If True, enforce Defender minute/day budgets before requests")
    lumu_journal_items_per_page: int = Field(100, description="Requested incident updates page size for Defender journal polling")
    lumu_journal_delay_time_seconds: int = Field(15, description="Long-poll delay parameter for Defender updates endpoint")
    lumu_journal_max_pages_per_cycle: int = Field(2, description="Maximum Defender update pages processed per tenant in one cycle")
    lumu_defender_max_items_param: int = Field(500, description="Value used for Defender max-items query parameter when enabled")
    lumu_defender_use_max_items_param: bool = Field(True, description="If True, include max-items on supported Defender list endpoints")
    lumu_defender_global_min_interval_seconds: float = Field(2.5, description="Global minimum spacing between Defender requests")
    lumu_defender_journal_min_interval_seconds: float = Field(5.0, description="Minimum spacing between Defender journal update requests")
    lumu_defender_journal_retry_after_floor_seconds: float = Field(30.0, description="Minimum wait used for Defender journal retries after 429")
    lumu_defender_endpoint_cooldown_default_seconds: int = Field(60, description="Default endpoint cooldown after Defender 429")
    lumu_defender_journal_circuit_breaker_enabled: bool = Field(True, description="Enable circuit breaker for Defender journal endpoint")
    lumu_defender_journal_circuit_breaker_threshold: int = Field(3, description="Consecutive 429 threshold to open journal circuit breaker")
    lumu_defender_journal_circuit_breaker_open_seconds: int = Field(600, description="How long the journal circuit breaker remains open")
    lumu_defender_journal_circuit_breaker_half_open_probe_seconds: int = Field(60, description="Probe interval while journal circuit breaker is half-open")
    lumu_defender_retry_respect_retry_after: bool = Field(True, description="If True, respect Retry-After response headers on Defender 429")
    lumu_rate_policy_profile: Literal["strict", "balanced", "aggressive"] = Field("balanced", description="High-level rate policy profile")
    lumu_rate_policy_tenant_cap: Optional[int] = Field(None, description="Optional tenant concurrency override")
    lumu_rate_policy_advanced: bool = Field(False, description="If True, expert low-level rate vars are honored")

    # Resilience
    lumu_max_retries: int = Field(5, description="Maximum number of retries for Lumu API requests (429/5xx)")
    lumu_initial_backoff: float = Field(2.0, description="Initial backoff delay in seconds for exponential retry")

    # Persistence
    alert_state_file: str = Field("data/sent_incidents.json", description="Path to the local JSON file for tracking notified incidents")

    # Kafka Configuration
    kafka_bootstrap_servers: str = Field("localhost:9092", description="Kafka bootstrap servers list")
    kafka_topic: Optional[str] = Field(
        None,
        description="Legacy static topic (unused in multi-tenant dynamic topic mode)",
    )
    kafka_client_id: str = Field("lumu-incident-handler", description="Kafka producer client id")
    kafka_delivery_timeout_seconds: float = Field(15.0, description="Timeout in seconds waiting for per-message Kafka delivery callback")
    kafka_flush_timeout_seconds: float = Field(10.0, description="Timeout in seconds for producer flush after publish")
    payload_timezone: str = Field("UTC", description="Timezone label of emitted Kafka payload timestamps; must match the serialized timestamp format")
    event_type_test_mode: bool = Field(False, description="If True, forces payload lumu.event_type to 'test'")

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    @field_validator("kafka_topic")
    @classmethod
    def kafka_topic_must_not_be_blank(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return value
        if not value.strip():
            raise ValueError("kafka_topic must be a non-empty string when provided")
        return value

    @field_validator("payload_timezone")
    @classmethod
    def payload_timezone_must_be_utc(cls, value: str) -> str:
        normalized = str(value or "").strip().upper()
        if normalized != "UTC":
            raise ValueError("payload_timezone must be UTC because emitted payload timestamps are serialized in UTC/Z format")
        return "UTC"

    @field_validator(
        "polling_interval_minutes",
        "lumu_open_state_reconciliation_minutes",
        "lumu_open_state_failure_backoff_minutes",
        "lumu_tenant_concurrency_cap",
        "lumu_defender_budget_minute_limit",
        "lumu_defender_budget_day_limit",
        "lumu_journal_items_per_page",
        "lumu_journal_delay_time_seconds",
        "lumu_journal_max_pages_per_cycle",
        "lumu_defender_max_items_param",
        "lumu_defender_endpoint_cooldown_default_seconds",
        "lumu_defender_journal_circuit_breaker_threshold",
        "lumu_defender_journal_circuit_breaker_open_seconds",
        "lumu_defender_journal_circuit_breaker_half_open_probe_seconds",
        mode="after",
    )
    @classmethod
    def positive_ints_must_be_gt_zero(cls, value: int) -> int:
        if value <= 0:
            raise ValueError("value must be greater than zero")
        return value

    @field_validator("lumu_open_state_jitter_seconds", mode="after")
    @classmethod
    def jitter_must_be_non_negative(cls, value: int) -> int:
        if value < 0:
            raise ValueError("lumu_open_state_jitter_seconds must be non-negative")
        return value

    @field_validator("lumu_tenant_cycle_jitter_max_seconds", mode="after")
    @classmethod
    def tenant_jitter_must_be_non_negative(cls, value: int) -> int:
        if value < 0:
            raise ValueError("lumu_tenant_cycle_jitter_max_seconds must be non-negative")
        return value

    @field_validator("lumu_open_state_max_backoff_minutes", mode="after")
    @classmethod
    def max_backoff_must_cover_base_backoff(cls, value: int, info) -> int:
        base_backoff = info.data.get("lumu_open_state_failure_backoff_minutes")
        if value <= 0:
            raise ValueError("lumu_open_state_max_backoff_minutes must be greater than zero")
        if base_backoff is not None and value < base_backoff:
            raise ValueError("lumu_open_state_max_backoff_minutes must be greater than or equal to lumu_open_state_failure_backoff_minutes")
        return value

    @field_validator("lumu_defender_budget_day_limit", mode="after")
    @classmethod
    def defender_day_budget_must_cover_minute_budget(cls, value: int, info) -> int:
        minute_limit = info.data.get("lumu_defender_budget_minute_limit")
        if value <= 0:
            raise ValueError("lumu_defender_budget_day_limit must be greater than zero")
        if minute_limit is not None and value < minute_limit:
            raise ValueError("lumu_defender_budget_day_limit must be greater than or equal to lumu_defender_budget_minute_limit")
        return value

    @field_validator(
        "lumu_defender_global_min_interval_seconds",
        "lumu_defender_journal_min_interval_seconds",
        "lumu_defender_journal_retry_after_floor_seconds",
        mode="after",
    )
    @classmethod
    def positive_floats_must_be_gt_zero(cls, value: float) -> float:
        if value <= 0:
            raise ValueError("value must be greater than zero")
        return value

    @field_validator("lumu_defender_journal_circuit_breaker_threshold", mode="after")
    @classmethod
    def breaker_threshold_must_be_valid(cls, value: int) -> int:
        if value < 1:
            raise ValueError("lumu_defender_journal_circuit_breaker_threshold must be greater than or equal to 1")
        return value

    @field_validator("lumu_defender_journal_circuit_breaker_half_open_probe_seconds", mode="after")
    @classmethod
    def half_open_probe_must_fit_open_window(cls, value: int, info) -> int:
        open_seconds = info.data.get("lumu_defender_journal_circuit_breaker_open_seconds")
        if open_seconds is not None and value > open_seconds:
            raise ValueError("lumu_defender_journal_circuit_breaker_half_open_probe_seconds must be less than or equal to lumu_defender_journal_circuit_breaker_open_seconds")
        return value

    @field_validator("lumu_defender_journal_min_interval_seconds", mode="after")
    @classmethod
    def journal_interval_must_cover_global_interval(cls, value: float, info) -> float:
        global_interval = info.data.get("lumu_defender_global_min_interval_seconds")
        if global_interval is not None and value < global_interval:
            raise ValueError("lumu_defender_journal_min_interval_seconds must be greater than or equal to lumu_defender_global_min_interval_seconds")
        return value

    @field_validator("lumu_rate_policy_tenant_cap", mode="after")
    @classmethod
    def tenant_cap_override_must_be_positive(cls, value: Optional[int]) -> Optional[int]:
        if value is not None and value < 1:
            raise ValueError("lumu_rate_policy_tenant_cap must be greater than or equal to 1")
        return value

    def resolve_rate_policy(self):
        from .rate_policy import build_rate_policy

        expert_values = {
            "tenant_concurrency_cap": self.lumu_tenant_concurrency_cap,
            "tenant_cycle_jitter_max_seconds": self.lumu_tenant_cycle_jitter_max_seconds,
            "defender_budget_enforce": self.lumu_defender_budget_enforce,
            "defender_budget_minute_limit": self.lumu_defender_budget_minute_limit,
            "defender_budget_day_limit": self.lumu_defender_budget_day_limit,
            "journal_items_per_page": self.lumu_journal_items_per_page,
            "journal_delay_time_seconds": self.lumu_journal_delay_time_seconds,
            "journal_max_pages_per_cycle": self.lumu_journal_max_pages_per_cycle,
            "defender_global_min_interval_seconds": self.lumu_defender_global_min_interval_seconds,
            "defender_journal_min_interval_seconds": self.lumu_defender_journal_min_interval_seconds,
            "defender_journal_retry_after_floor_seconds": self.lumu_defender_journal_retry_after_floor_seconds,
            "defender_endpoint_cooldown_default_seconds": self.lumu_defender_endpoint_cooldown_default_seconds,
            "defender_journal_circuit_breaker_enabled": self.lumu_defender_journal_circuit_breaker_enabled,
            "defender_journal_circuit_breaker_threshold": self.lumu_defender_journal_circuit_breaker_threshold,
            "defender_journal_circuit_breaker_open_seconds": self.lumu_defender_journal_circuit_breaker_open_seconds,
            "defender_journal_circuit_breaker_half_open_probe_seconds": self.lumu_defender_journal_circuit_breaker_half_open_probe_seconds,
            "defender_retry_respect_retry_after": self.lumu_defender_retry_respect_retry_after,
            "max_retries": self.lumu_max_retries,
            "initial_backoff": self.lumu_initial_backoff,
            "defender_max_items_param": self.lumu_defender_max_items_param,
            "defender_use_max_items_param": self.lumu_defender_use_max_items_param,
        }

        if not self.lumu_rate_policy_advanced:
            deprecated_env_vars = [
                "LUMU_TENANT_CONCURRENCY_CAP",
                "LUMU_TENANT_CYCLE_JITTER_MAX_SECONDS",
                "LUMU_DEFENDER_BUDGET_ENFORCE",
                "LUMU_DEFENDER_BUDGET_MINUTE_LIMIT",
                "LUMU_DEFENDER_BUDGET_DAY_LIMIT",
                "LUMU_JOURNAL_ITEMS_PER_PAGE",
                "LUMU_JOURNAL_DELAY_TIME_SECONDS",
                "LUMU_JOURNAL_MAX_PAGES_PER_CYCLE",
                "LUMU_DEFENDER_GLOBAL_MIN_INTERVAL_SECONDS",
                "LUMU_DEFENDER_JOURNAL_MIN_INTERVAL_SECONDS",
                "LUMU_DEFENDER_JOURNAL_RETRY_AFTER_FLOOR_SECONDS",
                "LUMU_DEFENDER_ENDPOINT_COOLDOWN_DEFAULT_SECONDS",
                "LUMU_DEFENDER_JOURNAL_CIRCUIT_BREAKER_ENABLED",
                "LUMU_DEFENDER_JOURNAL_CIRCUIT_BREAKER_THRESHOLD",
                "LUMU_DEFENDER_JOURNAL_CIRCUIT_BREAKER_OPEN_SECONDS",
                "LUMU_DEFENDER_JOURNAL_CIRCUIT_BREAKER_HALF_OPEN_PROBE_SECONDS",
                "LUMU_DEFENDER_RETRY_RESPECT_RETRY_AFTER",
                "LUMU_MAX_RETRIES",
                "LUMU_INITIAL_BACKOFF",
                "LUMU_DEFENDER_MAX_ITEMS_PARAM",
                "LUMU_DEFENDER_USE_MAX_ITEMS_PARAM",
            ]
            present = [name for name in deprecated_env_vars if os.getenv(name) is not None]
            if present:
                logger.warning("Deprecated expert rate vars ignored under profile mode (advanced=false): %s", ",".join(present))

        return build_rate_policy(
            profile=self.lumu_rate_policy_profile,
            tenant_cap_override=self.lumu_rate_policy_tenant_cap,
            advanced=self.lumu_rate_policy_advanced,
            expert_values=expert_values,
        )


@lru_cache()
def get_settings() -> Settings:
    return Settings()

