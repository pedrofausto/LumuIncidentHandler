import httpx
import logging
from typing import Dict, Any
from .config import get_settings

logger = logging.getLogger(__name__)

class WazuhClient:
    def __init__(self):
        self.settings = get_settings()
        self.api_url = f"{self.settings.indexer_url.rstrip('/')}/lumu-incidents-1.x/_doc"
        self.auth = (self.settings.indexer_username, self.settings.indexer_password.get_secret_value())
        self.client = httpx.AsyncClient(timeout=30.0, verify=False)

    async def send_incident(self, json_data: Dict[str, Any]) -> None:
        """
        Sends enriched incident JSON to the Wazuh Indexer.
        """
        headers = {
            "Content-Type": "application/json"
        }
        
        logger.info(f"Sending incident to Wazuh Indexer: {self.api_url}")
        try:
            response = await self.client.post(self.api_url, json=json_data, headers=headers, auth=self.auth)
            
            if response.status_code not in (200, 201, 202):
                logger.error(f"Failed to send incident to Wazuh Indexer. Status: {response.status_code}, Response: {response.text}")
                response.raise_for_status()
                
            logger.info("Incident successfully sent to Wazuh Indexer.")
        except httpx.HTTPError as e:
            logger.error(f"HTTP error occurred while sending incident to Wazuh Indexer: {e}")
            raise

    async def close(self):
        await self.client.aclose()
