import httpx
import logging
import time
from typing import Optional, Dict, Any, List
from .config import get_settings

logger = logging.getLogger(__name__)

class LumuSession:
    def __init__(self):
        self.settings = get_settings()
        self.base_url = self.settings.lumu_api_base_url.rstrip("/")
        self.client = httpx.AsyncClient(base_url=self.base_url, timeout=30.0, verify=False)
        self.bearer_token: Optional[str] = None
        self.token_expiry: float = 0
        
    async def authenticate(self) -> None:
        """
        Authenticates against the Lumu API and stores the Bearer token securely in-memory.
        """
        login_url = "/api/msp/users/sign_in"
        payload = {
            "user": {
                "email": self.settings.lumu_email,
                "password": self.settings.lumu_password.get_secret_value()
            }
        }
        
        logger.info("Authenticating with Lumu MSSP Console...")
        response = await self.client.post(login_url, json=payload)
        
        if response.status_code != 200:
            logger.error(f"Authentication failed with status {response.status_code}")
            response.raise_for_status()
            
        # The Bearer token is typically found in the Authorization header of the response
        # Sometimes it's in the body, but standard devise-jwt puts it in headers
        auth_header = response.headers.get("Authorization")
        if not auth_header:
            logger.error("No Authorization header found in the login response.")
            raise ValueError("Authentication successful but no Bearer token received.")
            
        self.bearer_token = auth_header
        # Basic assumption: tokens are valid for at least an hour
        self.token_expiry = time.time() + 3600 
        logger.info("Authentication successful. Token secured in-memory.")

    async def _ensure_authenticated(self) -> None:
        """
        Checks if the token is missing or expired, and re-authenticates if necessary.
        """
        # Buffer of 60 seconds to prevent race conditions during expiry
        if not self.bearer_token or time.time() > (self.token_expiry - 60):
            await self.authenticate()

    async def get_with_auth(self, endpoint: str, params: Optional[Dict[str, Any]] = None) -> Any:
        """
        Wrapper for GET requests that automatically handles authentication and token refreshing.
        """
        await self._ensure_authenticated()
        
        headers = {
            "Authorization": self.bearer_token,
            "Accept": "application/json"
        }
        
        response = await self.client.get(endpoint, headers=headers, params=params)
        
        # Handle auto-reauthentication layer (401 Unauthorized)
        if response.status_code == 401:
            logger.warning("Received 401 Unauthorized. Token might be invalid or revoked. Re-authenticating...")
            await self.authenticate()
            # Retry the exact same request once with the new token
            headers["Authorization"] = self.bearer_token
            response = await self.client.get(endpoint, headers=headers, params=params)
            
        response.raise_for_status()
        return response.json()

    async def post_with_auth(self, endpoint: str, json_data: Dict[str, Any]) -> Any:
        """
        Wrapper for POST requests that automatically handles authentication.
        """
        await self._ensure_authenticated()
        
        headers = {
            "Authorization": self.bearer_token,
            "Accept": "application/json",
            "Content-Type": "application/json"
        }
        
        response = await self.client.post(endpoint, headers=headers, json=json_data)
        
        if response.status_code == 401:
            logger.warning("Received 401 Unauthorized on POST. Re-authenticating...")
            await self.authenticate()
            headers["Authorization"] = self.bearer_token
            response = await self.client.post(endpoint, headers=headers, json=json_data)
            
        response.raise_for_status()
        return response.json()

    async def get_tenants(self, items: int = 500, page: int = 1) -> list:
        """
        Endpoint B: Fetch the list of managed tenants.
        Returns the array of tenant objects from the response.
        """
        endpoint = f"/api/msp/companies/{self.settings.lumu_mssp_uuid}/supervised_companies"
        params = {"items": items, "page": page}
        response_data = await self.get_with_auth(endpoint, params=params)
        
        # The Lumu API paginates items by returning [meta_dict, [item_array]]
        if isinstance(response_data, list) and len(response_data) == 2:
            return response_data[1]
        return []

    async def get_appliances(self, company_uuid: str, items: int = 500, page: int = 1) -> list:
        """
        Endpoint A: Fetch all Virtual Appliances for a specific tenant.
        Returns the array of appliance objects.
        """
        endpoint = f"/api/msp/companies/{self.settings.lumu_mssp_uuid}/supervised_companies/{company_uuid}/appliances"
        params = {"items": items, "page": page}
        response_data = await self.get_with_auth(endpoint, params=params)
        
        if isinstance(response_data, list) and len(response_data) == 2:
            return response_data[1]
        return []

    async def get_mssp_activity(self, from_date: str, to_date: str, timezone: str = "America/Sao_Paulo") -> list:
        """
        Endpoint C: Fetch high-level activity details across the MSSP.
        from_date and to_date format: 'YYYY-MM-DDTHH:MM:SS.MMM'
        """
        endpoint = "/data-api/companies/activity/msp"
        payload = {
            "from": from_date,
            "to": to_date,
            "timezone": timezone
        }
        return await self.post_with_auth(endpoint, json_data=payload)

    async def get_collector_status(self, company_uuid: str, appliance_uuid: str) -> Dict[str, Any]:
        """
        Endpoint D: Fetch traffic and health status for each collector.
        """
        endpoint = f"/data-api/collectors/companies/{company_uuid}/appliances/{appliance_uuid}/status"
        return await self.get_with_auth(endpoint)

    async def get_all_incidents(self, company_key: str, from_date: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Fetch all incidents for a specific company using its key, with time-based pagination support.
        The Lumu API limits queries to a 30-day window. This method iterates backwards in time.
        """
        from datetime import datetime, timedelta, timezone
        
        url = f"{self.settings.lumu_defender_url}/api/incidents/all"
        params = {"key": company_key}
        
        all_items = []
        seen_ids = set()
        
        # Start window from now (or a specific future date if needed)
        end_date = datetime.now(timezone.utc)
        
        # We will iterate backwards in 30-day chunks.
        # A maximum of 24 chunks (2 years) is a safe upper bound to prevent infinite loops.
        for _ in range(24):
            start_date = end_date - timedelta(days=30)
            
            from_str = start_date.strftime("%Y-%m-%dT%H:%M:%S.000Z")
            to_str = end_date.strftime("%Y-%m-%dT%H:%M:%S.000Z")
            
            page = 1
            page_size = 50
            
            # Sub-loop for standard pagination within the 30-day chunk
            while True:
                payload = {
                    "status": ["open"],
                    "fromDate": from_str,
                    "toDate": to_str,
                    "pagination": {
                        "page": page,
                        "items": page_size
                    }
                }
                
                logger.info(f"Fetching incidents window {from_str[:10]} to {to_str[:10]} (Page {page})...")
                response = await self.client.post(url, params=params, json=payload)
                
                # If we hit the retention limit, the API returns a 400 error. Break gracefully.
                if response.status_code == 400:
                    logger.info("Reached the maximum historical retention limit of the API.")
                    return all_items
                
                response.raise_for_status()
                data = response.json()
                
                items = []
                if isinstance(data, dict):
                    items = data.get("items", [])
                elif isinstance(data, list):
                    items = data
                    
                if not items:
                    break
                    
                for item in items:
                    item_id = item.get('id') or item.get('uuid')
                    if item_id not in seen_ids:
                        seen_ids.add(item_id)
                        all_items.append(item)
                
                # Check pagination within the chunk
                if isinstance(data, dict) and "paginationInfo" in data:
                    if len(items) < page_size:
                        break
                    page += 1
                else:
                    break
            
            # Shift the window backwards for the next chunk
            end_date = start_date
                
        return all_items

    async def get_incident_details(self, company_key: str, incident_uuid: str) -> Dict[str, Any]:
        """
        Fetch incident details for a specific incident using its key.
        """
        url = f"{self.settings.lumu_defender_url}/api/incidents/{incident_uuid}/details"
        params = {"key": company_key}
        response = await self.client.get(url, params=params)
        response.raise_for_status()
        return response.json()

    async def get_incident_stix(self, company_id: str, incident_uuid: str) -> Dict[str, Any]:
        """
        Fetch STIX information for an incident.
        Endpoint: GET https://managed.lumu.io/intelligence/stix/companies/{company_id}/secops-incident/{incident_uuid}
        Uses the same MSSP Bearer token obtained at startup.
        """
        endpoint = f"/intelligence/stix/companies/{company_id}/secops-incident/{incident_uuid}"
        return await self.get_with_auth(endpoint)

    async def close(self):
        await self.client.aclose()
