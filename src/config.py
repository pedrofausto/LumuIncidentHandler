from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field, SecretStr, EmailStr
from typing import Optional
import os

class Settings(BaseSettings):
    # Lumu Authentication
    lumu_email: EmailStr = Field(..., description="The email address used to authenticate with Lumu MSSP Console")
    lumu_password: SecretStr = Field(..., description="The password for the Lumu MSSP Console account")
    
    # Lumu API
    lumu_api_base_url: str = Field("https://managed.lumu.io", description="Base URL for Lumu managed console")
    lumu_mssp_uuid: str = Field(..., description="The unique UUID for the MSSP holding supervised companies")
    
    # New Lumu API Endpoints
    lumu_defender_url: str = Field("https://defender.lumu.io", description="Base URL for Lumu Defender API")
    lumu_defender_key: Optional[SecretStr] = Field(None, description="Defender API Key used as 'key' query param for incident endpoints")

    # Customer to monitor — single company UUID
    customer_uuid: str = Field(..., description="The UUID of the customer/tenant to monitor for incidents")
    customer_name: str = Field("Unknown Customer", description="Human-readable name for the customer (used in alerts)")

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

    # Wazuh Indexer Configuration
    indexer_url: str = Field(..., description="The Wazuh Indexer endpoint for incident ingestion")
    indexer_username: str = Field("admin", description="The username for Wazuh Indexer authentication")
    indexer_password: SecretStr = Field(..., description="The password for Wazuh Indexer authentication")
    indexer_index_name: str = Field("lumu-incidents-1.x", description="The name of the index in Wazuh Indexer")

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )

def get_settings() -> Settings:
    return Settings()
