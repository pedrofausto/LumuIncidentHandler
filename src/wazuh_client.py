import httpx
import logging
from typing import Any
from .config import get_settings

logger = logging.getLogger(__name__)

class WazuhClient:
    def __init__(self):
        self.settings = get_settings()
        self.api_url = f"{self.settings.indexer_url.rstrip('/')}/{self.settings.indexer_index_name}/_doc"
        self.auth = (self.settings.indexer_username, self.settings.indexer_password.get_secret_value())
        self.client = httpx.AsyncClient(timeout=30.0, verify=self.settings.verify_ssl)

    async def send_incident(self, json_data: dict[str, Any]) -> None:
        """
        Sends enriched incident JSON to the Wazuh Indexer via Native Upsert.
        """
        headers = {
            "Content-Type": "application/json"
        }
        
        incident_id = json_data.get('incident_uuid')
        if not incident_id:
            logger.error("Incident payload missing incident_uuid, cannot upsert.")
            return

        update_url = f"{self.settings.indexer_url.rstrip('/')}/{self.settings.indexer_index_name}/_update/{incident_id}"
        payload = {
            "doc": json_data,
            "doc_as_upsert": True
        }
        
        logger.info(f"Upserting incident to Wazuh Indexer: {update_url}")
        try:
            response = await self.client.post(update_url, json=payload, headers=headers, auth=self.auth)
            
            if response.status_code not in (200, 201, 202):
                logger.error(f"Failed to upsert incident to Wazuh Indexer. Status: {response.status_code}, Response: {response.text}")
                response.raise_for_status()
                
            logger.info("Incident successfully upserted to Wazuh Indexer.")
        except httpx.HTTPError as e:
            logger.error(f"HTTP error occurred while sending incident to Wazuh Indexer: {e}")
            raise

    async def close(self):
        await self.client.aclose()

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.close()
