import asyncio
import httpx
import logging
import time
import random
from typing import Optional, Dict, Any, List
from .config import get_settings

logger = logging.getLogger(__name__)

class LumuSession:
    def __init__(self):
        self.settings = get_settings()
        self.base_url = self.settings.lumu_api_base_url.rstrip("/")
        limits = httpx.Limits(max_connections=10, max_keepalive_connections=5)
        self.client = httpx.AsyncClient(base_url=self.base_url, timeout=30.0, verify=self.settings.verify_ssl, limits=limits)
        self.bearer_token: Optional[str] = None
        self.token_expiry: float = 0
        self._auth_lock = asyncio.Lock()
        self._last_request_time: float = 0.0
        self._rate_limit_lock = asyncio.Lock()
        self.rate_limit_hits = 0
        self._min_request_interval = 2.0  # 2 seconds max globally
        
    async def _wait_for_rate_limit(self) -> None:
        """
        Enforce a global minimum interval between requests to prevent hitting 429 limits.
        """
        async with self._rate_limit_lock:
            now = time.time()
            elapsed = now - self._last_request_time
            if elapsed < self._min_request_interval:
                await asyncio.sleep(self._min_request_interval - elapsed)
            self._last_request_time = time.time()

    async def _ensure_authenticated(self) -> None:
        """
        Checks if the token is missing or expired, and re-authenticates if necessary.
        """
        # Buffer of 60 seconds to prevent race conditions during expiry
        if not self.bearer_token or time.time() > (self.token_expiry - 60):
            async with self._auth_lock:
                # Re-check after acquiring lock
                if not self.bearer_token or time.time() > (self.token_expiry - 60):
                    await self.authenticate_locked()

    async def authenticate_locked(self) -> None:
        """
        Internal method to perform authentication. Assumes lock is already held.
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

    async def authenticate(self) -> None:
        """
        Public authentication method.
        """
        async with self._auth_lock:
            await self.authenticate_locked()

    async def _request_with_retry(
        self, 
        method: str, 
        url: str, 
        headers: Optional[Dict[str, str]] = None, 
        params: Optional[Dict[str, Any]] = None, 
        json_data: Optional[Dict[str, Any]] = None,
        auth_required: bool = True,
        _auth_retry_depth: int = 0
    ) -> httpx.Response:
        """
        Generic request wrapper with exponential backoff and authentication handling.
        """
        if auth_required:
            await self._ensure_authenticated()
            if not headers:
                headers = {}
            headers["Authorization"] = self.bearer_token
            headers["Accept"] = "application/json"

        max_retries = self.settings.lumu_max_retries
        initial_backoff = self.settings.lumu_initial_backoff

        for attempt in range(max_retries + 1):
            try:
                # Apply global rate limit throttle before executing any request
                await self._wait_for_rate_limit()

                response = await self.client.request(
                    method=method, 
                    url=url, 
                    headers=headers, 
                    params=params, 
                    json=json_data
                )

                if response.status_code == 429:
                    self.rate_limit_hits += 1
                    if attempt == max_retries:
                        logger.error(f"Max retries reached for 429 error at {url}")
                        response.raise_for_status()
                    
                    backoff = initial_backoff * (2 ** attempt) + random.uniform(0, 0.5)
                    logger.warning(f"Rate limited (429) for {url}. Retrying in {backoff:.2f}s (Attempt {attempt + 1}/{max_retries})")
                    await asyncio.sleep(backoff)
                    continue

                if response.status_code >= 500:
                    if attempt == max_retries:
                        logger.error(f"Max retries reached for server error ({response.status_code}) at {url}")
                        response.raise_for_status()
                    
                    backoff = initial_backoff * (2 ** attempt) + random.uniform(0, 0.5)
                    logger.warning(f"Server error ({response.status_code}) for {url}. Retrying in {backoff:.2f}s (Attempt {attempt + 1}/{max_retries})")
                    await asyncio.sleep(backoff)
                    continue

                if response.status_code == 401 and auth_required:
                    if _auth_retry_depth >= 2:
                        logger.error(f"Max authentication retries reached to refresh 401 error at {url}")
                        response.raise_for_status()
                    logger.warning(f"Received 401 Unauthorized for {url}. Refreshing token and retrying...")
                    await self.authenticate()
                    headers["Authorization"] = self.bearer_token
                    # Direct recursion for 401 retry to avoid complex loop logic
                    return await self._request_with_retry(method, url, headers, params, json_data, auth_required, _auth_retry_depth + 1)

                response.raise_for_status()
                return response
            
            except (httpx.RequestError, httpx.TimeoutException) as e:
                if attempt == max_retries:
                    logger.error(f"Request failed after {max_retries} retries: {e}")
                    raise
                
                backoff = initial_backoff * (2 ** attempt) + random.uniform(0, 0.5)
                logger.warning(f"Request error for {url}: {e}. Retrying in {backoff:.2f}s...")
                await asyncio.sleep(backoff)

        raise RuntimeError("Request failed after retries")

    async def get_with_auth(self, endpoint: str, params: Optional[Dict[str, Any]] = None) -> Any:
        """
        Wrapper for GET requests that automatically handles authentication and retries.
        """
        response = await self._request_with_retry("GET", endpoint, params=params)
        return response.json()

    async def post_with_auth(self, endpoint: str, json_data: Dict[str, Any]) -> Any:
        """
        Wrapper for POST requests that automatically handles authentication and retries.
        """
        response = await self._request_with_retry("POST", endpoint, json_data=json_data)
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

    async def get_incident_updates(self, company_key: str, offset: int = 0, items: int = 50, delay_time: int = 5) -> Dict[str, Any]:
        """
        Fetch incremental incident updates using an offset. 
        Uses the Lumu Defender API.
        """
        url = f"{self.settings.lumu_defender_url.rstrip('/')}/api/incidents/open-incidents/updates"
        params = {
            "key": company_key,
            "offset": offset,
            "items": items,
            "time": delay_time
        }
        
        logger.info(f"Fetching incident updates from offset {offset}...")
        # Note: auth_required=False because this API uses the 'key' query param
        response = await self._request_with_retry("GET", url, params=params, auth_required=False)
        return response.json()

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
        
        parsed_from_date = None
        if from_date:
            try:
                # Handle standard ISO formats, e.g. "2026-04-10T16:07:14Z"
                if from_date.endswith('Z'):
                    parsed_from_date = datetime.fromisoformat(from_date[:-1] + '+00:00')
                else:
                    parsed_from_date = datetime.fromisoformat(from_date)
            except ValueError:
                logger.warning(f"Failed to parse from_date '{from_date}', fetching 2 years of history instead.")

        # We will iterate backwards in 30-day chunks.
        # A maximum of 24 chunks (2 years) is a safe upper bound to prevent infinite loops.
        for _ in range(24):
            start_date = end_date - timedelta(days=30)
            
            # Clamp the window if from_date is provided
            if parsed_from_date:
                if end_date <= parsed_from_date:
                    break  # We have already pulled up to the from_date boundary
                if start_date < parsed_from_date:
                    start_date = parsed_from_date
            
            from_str = start_date.strftime("%Y-%m-%dT%H:%M:%S.000Z")
            to_str = end_date.strftime("%Y-%m-%dT%H:%M:%S.000Z")
            
            page = 1
            page_size = 50
            
            # Sub-loop for standard pagination within the 30-day chunk
            while True:
                payload = {
                    "status": ["open", "closed"],
                    "fromDate": from_str,
                    "toDate": to_str,
                    "pagination": {
                        "page": page,
                        "items": page_size
                    }
                }
                
                logger.info(f"Fetching incidents window {from_str[:10]} to {to_str[:10]} (Page {page})...")
                # Using _request_with_retry for the Defender API (no token auth, key in params)
                response = await self._request_with_retry(
                    "POST", 
                    url, 
                    params=params, 
                    json_data=payload,
                    auth_required=False
                )
                
                # If we hit the retention limit, the API returns a 400 error. Break gracefully.
                if response.status_code == 400:
                    logger.info("Reached the maximum historical retention limit of the API.")
                    return all_items
                
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
                    # Avoid hammering the API in pagination sweeps
                    await asyncio.sleep(0.7)
                else:
                    break
            
            # Shift the window backwards for the next chunk
            end_date = start_date
            # Avoid hammering the API in historical sweeps
            await asyncio.sleep(0.5)
                
        return all_items

    async def get_open_incidents(self, company_key: str, from_date: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Fetch all currently OPEN incidents, optionally bounded by a starting time.
        Used for state-based synchronization to ensure no incident is missed by the journal.
        """
        from datetime import datetime, timezone
        url = f"{self.settings.lumu_defender_url}/api/incidents/all"
        params = {"key": company_key}
        
        all_open = []
        seen_ids = set()
        page = 1
        page_size = 50
        
        while True:
            payload = {
                "status": ["open"],
                "pagination": {
                    "page": page,
                    "items": page_size
                }
            }
            if from_date:
                payload["fromDate"] = from_date
                payload["toDate"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
            
            logger.info(f"Fetching open incidents state (Page {page})...")
            response = await self._request_with_retry(
                "POST", 
                url, 
                params=params, 
                json_data=payload,
                auth_required=False
            )
            
            if response.status_code != 200:
                break
                
            data = response.json()
            items = data.get("items", []) if isinstance(data, dict) else []
            
            if not items:
                break
                
            new_items_this_page = 0
            for item in items:
                item_id = item.get("id") or item.get("uuid")
                if item_id and item_id not in seen_ids:
                    seen_ids.add(item_id)
                    all_open.append(item)
                    new_items_this_page += 1
            
            # If the API returned items, but NONE of them were new to our set, we are stuck in a loop.
            if new_items_this_page == 0:
                logger.warning("API returned duplicate items on a new page. Breaking pagination loop.")
                break

            if len(items) < page_size:
                break
                
            if page >= 200:
                logger.warning("Reached maximum page limit (200) for state sync. Forcing break.")
                break
                
            page += 1
            await asyncio.sleep(0.5)
            
        return all_open

    async def get_incident_details(self, company_key: str, incident_uuid: str) -> Dict[str, Any]:
        """
        Fetch incident details for a specific incident using its key.
        """
        url = f"{self.settings.lumu_defender_url}/api/incidents/{incident_uuid}/details"
        params = {"key": company_key}
        response = await self._request_with_retry("GET", url, params=params, auth_required=False)
        return response.json()

    async def get_incident_contacts(self, company_key: str, incident_uuid: str) -> List[Dict[str, Any]]:
        """
        Fetch all contacts (endpoints) for a specific incident.
        """
        url = f"{self.settings.lumu_defender_url}/api/incidents/{incident_uuid}/contacts"
        params = {"key": company_key}
        response = await self._request_with_retry("GET", url, params=params, auth_required=False)
        data = response.json()
        if isinstance(data, list):
            return data
        if isinstance(data, dict):
            contacts = data.get('contacts') or data.get('items') or data.get('data') or data.get('results') or []
            return contacts if isinstance(contacts, list) else []
        return []

    async def get_secops_incident_details(self, company_uuid: str, incident_uuid: str) -> Dict[str, Any]:
        """
        Fetch rich incident details including all affected workstations.
        Endpoint: GET https://managed.lumu.io/data-api/secops-incidents/companies/{company_uuid}/incidents/{incident_uuid}/details
        """
        endpoint = f"/data-api/secops-incidents/companies/{company_uuid}/incidents/{incident_uuid}/details"
        return await self.get_with_auth(endpoint)

    async def get_incident_stix(self, company_id: str, incident_uuid: str) -> Dict[str, Any]:
        """
        Fetch STIX information for an incident.
        Endpoint: GET https://managed.lumu.io/intelligence/stix/companies/{company_id}/secops-incident/{incident_uuid}
        Uses the same MSSP Bearer token obtained at startup.
        """
        endpoint = f"/intelligence/stix/companies/{company_id}/secops-incident/{incident_uuid}"
        return await self.get_with_auth(endpoint)

    async def get_incident_context_summary(self, company_id: str, incident_uuid: str) -> Dict[str, Any]:
        """
        Fetch a rich Context Summary for a security incident containing malware hashes, MITRE mappings, and detailed indicators.
        """
        endpoint = f"/intelligence/companies/{company_id}/secops-incidents/{incident_uuid}/context/summary"
        return await self.get_with_auth(endpoint)

    async def get_incident_external_articles(self, company_id: str, incident_uuid: str) -> List[Dict[str, Any]]:
        """
        Fetch external threat intelligence articles correlating with the threat actor or malware family in the incident.
        """
        endpoint = f"/intelligence/companies/{company_id}/secops-incidents/{incident_uuid}/context/external-articles"
        return await self.get_with_auth(endpoint)

    async def close(self):
        await self.client.aclose()

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.close()
