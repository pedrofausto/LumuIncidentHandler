from functools import lru_cache
from typing import Optional

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
    payload_timezone: str = Field("UTC", description="Timezone label added to emitted Kafka payloads")

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


@lru_cache()
def get_settings() -> Settings:
    return Settings()
