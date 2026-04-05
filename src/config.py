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


    # SMTP Configuration
    smtp_host: str = Field(..., description="The SMTP server address")
    smtp_port: int = Field(587, description="The SMTP server port (usually 587 for TLS or 465 for SSL)")
    smtp_user: str = Field(..., description="The SMTP username")
    smtp_pass: SecretStr = Field(..., description="The SMTP password")
    smtp_from_email: EmailStr = Field(..., description="The email address to send alerts from")
    
    # Alerting
    alert_to_email: EmailStr = Field(..., description="The sysadmin email address that receives alerts")
    
    # Orchestration
    polling_interval_minutes: int = Field(5, description="Frequency of Lumu polling in minutes")

    # Persistence
    alert_state_file: str = Field("data/alerts.json", description="Path to the local JSON file for tracking notified incidents")

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )

def get_settings() -> Settings:
    return Settings()
