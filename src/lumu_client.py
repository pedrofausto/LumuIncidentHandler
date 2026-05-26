import asyncio
import httpx
import logging
import time
import random
import email.utils
from datetime import datetime, timezone, timedelta
from typing import Optional, Dict, Any, List
from .config import get_settings
from .rate_policy import resolve_rate_policy_from_settings

logger = logging.getLogger(__name__)

class LumuEndpointCooldownException(Exception):
    def __init__(self, endpoint_name: str, tenant_key_normalized: str, cooldown_remaining_seconds: float, reason_code: str):
        self.endpoint_name = endpoint_name
        self.tenant_key_normalized = tenant_key_normalized
        self.cooldown_remaining_seconds = float(cooldown_remaining_seconds)
        self.reason_code = reason_code
        super().__init__(
            f"{reason_code} endpoint={endpoint_name} tenant={tenant_key_normalized} cooldown={cooldown_remaining_seconds:.2f}s"
        )

class LumuSession:
    def __init__(self):
        self.settings = get_settings()
        self.rate_policy = resolve_rate_policy_from_settings(self.settings)
        self.base_url = self.settings.lumu_api_base_url.rstrip("/")
        limits = httpx.Limits(max_connections=10, max_keepalive_connections=5)
        self.client = httpx.AsyncClient(base_url=self.base_url, timeout=30.0, verify=self.settings.verify_ssl, limits=limits)
        self.bearer_token: Optional[str] = None
        self.token_expiry: float = 0
        self._auth_lock = asyncio.Lock()
        self._last_request_time: float = 0.0
        self._rate_limit_lock = asyncio.Lock()
        self._defender_budget_lock = asyncio.Lock()
        self.rate_limit_hits = 0
        self._min_request_interval = float(self.rate_policy.defender_global_min_interval_seconds)
        self._defender_budget_by_key: Dict[str, Dict[str, Any]] = {}
        self._defender_max_items_unsupported_endpoints: set[str] = set()
        self._defender_admission_lock = asyncio.Lock()
        self._defender_next_allowed_global_at = 0.0
        self._defender_next_allowed_by_endpoint: Dict[str, float] = {}
        self._journal_next_allowed_by_company: Dict[str, float] = {}
        self._defender_consecutive_429_by_endpoint: Dict[str, int] = {}
        self._journal_breaker_state_by_company: Dict[str, str] = {}
        self._journal_breaker_open_until_by_company: Dict[str, float] = {}
        self._journal_breaker_next_probe_at_by_company: Dict[str, float] = {}
        self._journal_half_open_probe_in_flight_by_company: Dict[str, bool] = {}
        self._details_semaphores_by_company: Dict[str, asyncio.Semaphore] = {}

    @staticmethod
    def _now_monotonic() -> float:
        return time.monotonic()

    @staticmethod
    def _is_journal_endpoint(endpoint_name: Optional[str]) -> bool:
        return endpoint_name == "open_incidents_updates"

    def _admission_endpoint_key(self, endpoint_name: Optional[str], company_key: Optional[str]) -> str:
        endpoint = endpoint_name or "unknown_defender_endpoint"
        return f"{endpoint}:{self._normalize_company_key(company_key)}"

    def _parse_retry_after_seconds(self, response: httpx.Response) -> float:
        raw_retry_after = response.headers.get("Retry-After")
        if not raw_retry_after:
            return 0.0
        raw_retry_after = raw_retry_after.strip()
        if raw_retry_after.isdigit():
            return max(0.0, float(raw_retry_after))
        try:
            dt = email.utils.parsedate_to_datetime(raw_retry_after)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return max(0.0, (dt.astimezone(timezone.utc) - datetime.now(timezone.utc)).total_seconds())
        except (TypeError, ValueError, OverflowError):
            return 0.0

    async def _admission_wait_and_reserve(self, endpoint_name: Optional[str], company_key: Optional[str] = None) -> None:
        endpoint = endpoint_name or "unknown_defender_endpoint"
        admission_key = self._admission_endpoint_key(endpoint_name, company_key)
        while True:
            sleep_for = 0.0
            now = self._now_monotonic()
            async with self._defender_admission_lock:
                if self._is_journal_endpoint(endpoint):
                    company = self._normalize_company_key(company_key)
                    tenant_next_allowed = self._journal_next_allowed_by_company.get(company, 0.0)
                    if now < tenant_next_allowed:
                        raise LumuEndpointCooldownException(endpoint, company, tenant_next_allowed - now, "journal_tenant_cooldown")
                    if self.rate_policy.defender_journal_circuit_breaker_enabled:
                        state = self._journal_breaker_state_by_company.get(company, "closed")
                        open_until = self._journal_breaker_open_until_by_company.get(company, 0.0)
                        next_probe_at = self._journal_breaker_next_probe_at_by_company.get(company, 0.0)
                        probe_in_flight = self._journal_half_open_probe_in_flight_by_company.get(company, False)
                        if state == "open":
                            if now < open_until:
                                raise LumuEndpointCooldownException(endpoint, company, open_until - now, "journal_circuit_open")
                            self._journal_breaker_state_by_company[company] = "half_open"
                            self._journal_breaker_next_probe_at_by_company[company] = now
                            self._journal_half_open_probe_in_flight_by_company[company] = False
                            logger.info("Journal circuit breaker transition open->half_open tenant=%s", company)
                            state = "half_open"
                            next_probe_at = now
                            probe_in_flight = False
                        if state == "half_open":
                            if now < next_probe_at or probe_in_flight:
                                cooldown = max(0.0, next_probe_at - now)
                                raise LumuEndpointCooldownException(endpoint, company, cooldown, "journal_circuit_open")
                            self._journal_half_open_probe_in_flight_by_company[company] = True

                global_wait = max(0.0, self._defender_next_allowed_global_at - now)
                endpoint_next = self._defender_next_allowed_by_endpoint.get(admission_key, 0.0)
                endpoint_wait = max(0.0, endpoint_next - now)
                sleep_for = max(global_wait, endpoint_wait)
                if sleep_for <= 0:
                    global_min = float(self.rate_policy.defender_global_min_interval_seconds)
                    self._defender_next_allowed_global_at = now + global_min
                    if self._is_journal_endpoint(endpoint):
                        journal_min = float(self.rate_policy.defender_journal_min_interval_seconds)
                        self._defender_next_allowed_by_endpoint[admission_key] = max(
                            self._defender_next_allowed_by_endpoint.get(admission_key, 0.0),
                            now + journal_min,
                        )
                    return
                if not self._is_journal_endpoint(endpoint):
                    max_blocking = float(self.rate_policy.non_journal_max_blocking_cooldown_seconds)
                    if sleep_for > max_blocking:
                        raise LumuEndpointCooldownException(
                            endpoint,
                            self._normalize_company_key(company_key),
                            sleep_for,
                            "endpoint_cooldown",
                        )
            logger.info("Defender admission wait endpoint=%s wait=%.2fs", endpoint, sleep_for)
            await asyncio.sleep(sleep_for)

    async def _register_defender_success(self, endpoint_name: Optional[str], company_key: Optional[str]) -> None:
        endpoint = endpoint_name or "unknown_defender_endpoint"
        admission_key = self._admission_endpoint_key(endpoint_name, company_key)
        company = self._normalize_company_key(company_key)
        async with self._defender_admission_lock:
            self._defender_consecutive_429_by_endpoint[admission_key] = 0
            if self._is_journal_endpoint(endpoint) and self._journal_breaker_state_by_company.get(company) == "half_open":
                self._journal_breaker_state_by_company[company] = "closed"
                self._journal_half_open_probe_in_flight_by_company[company] = False
                self._journal_breaker_next_probe_at_by_company[company] = 0.0
                self._journal_breaker_open_until_by_company[company] = 0.0
                logger.info("Journal circuit breaker transition half_open->closed tenant=%s", company)

    async def _register_defender_429(self, endpoint_name: Optional[str], cooldown_seconds: float, company_key: Optional[str] = None) -> None:
        endpoint = endpoint_name or "unknown_defender_endpoint"
        admission_key = self._admission_endpoint_key(endpoint_name, company_key)
        now = self._now_monotonic()
        async with self._defender_admission_lock:
            current = self._defender_consecutive_429_by_endpoint.get(admission_key, 0)
            self._defender_consecutive_429_by_endpoint[admission_key] = current + 1
            next_allowed = now + max(0.0, cooldown_seconds)
            self._defender_next_allowed_by_endpoint[admission_key] = max(
                self._defender_next_allowed_by_endpoint.get(admission_key, 0.0),
                next_allowed,
            )
            if self._is_journal_endpoint(endpoint):
                company = self._normalize_company_key(company_key)
                self._journal_next_allowed_by_company[company] = max(
                    self._journal_next_allowed_by_company.get(company, 0.0),
                    next_allowed,
                )
                threshold = int(self.rate_policy.defender_journal_circuit_breaker_threshold)
                current_state = self._journal_breaker_state_by_company.get(company, "closed")
                if self.rate_policy.defender_journal_circuit_breaker_enabled and self._defender_consecutive_429_by_endpoint[admission_key] >= threshold:
                    open_seconds = float(self.rate_policy.defender_journal_circuit_breaker_open_seconds)
                    self._journal_breaker_state_by_company[company] = "open"
                    self._journal_breaker_open_until_by_company[company] = now + open_seconds
                    self._journal_breaker_next_probe_at_by_company[company] = now + open_seconds
                    self._journal_half_open_probe_in_flight_by_company[company] = False
                    logger.warning(
                        "Journal circuit breaker transition to open tenant=%s consecutive_429=%s open_for=%.2fs",
                        company,
                        self._defender_consecutive_429_by_endpoint[admission_key],
                        open_seconds,
                    )
                elif current_state == "half_open":
                    open_seconds = float(self.rate_policy.defender_journal_circuit_breaker_open_seconds)
                    self._journal_breaker_state_by_company[company] = "open"
                    self._journal_breaker_open_until_by_company[company] = now + open_seconds
                    self._journal_breaker_next_probe_at_by_company[company] = now + open_seconds
                    self._journal_half_open_probe_in_flight_by_company[company] = False
                    logger.warning("Journal circuit breaker half_open probe failed tenant=%s reopened for %.2fs", company, open_seconds)

    def _is_defender_request(self, url: str) -> bool:
        normalized = str(url or "").lower()
        return normalized.startswith(self.settings.lumu_defender_url.lower())

    @staticmethod
    def _normalize_company_key(company_key: Optional[str]) -> str:
        key = str(company_key or "").strip()
        return key if key else "__unknown__"

    def _extract_company_key_from_params(self, params: Optional[Dict[str, Any]]) -> str:
        if not params:
            return "__unknown__"
        return self._normalize_company_key(params.get("key"))

    def _get_defender_budget_state(self, company_key: str) -> Dict[str, Any]:
        key = self._normalize_company_key(company_key)
        state = self._defender_budget_by_key.get(key)
        if state is None:
            now = datetime.now(timezone.utc)
            minute_start = now.replace(second=0, microsecond=0)
            day_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
            state = {
                "minute_start": minute_start,
                "minute_count": 0,
                "day_start": day_start,
                "day_count": 0,
            }
            self._defender_budget_by_key[key] = state
        return state

    @staticmethod
    def _seconds_until_next_minute(now_utc: datetime) -> float:
        next_minute = now_utc.replace(second=0, microsecond=0) + timedelta(minutes=1)
        return max(0.01, (next_minute - now_utc).total_seconds())

    @staticmethod
    def _seconds_until_next_utc_day(now_utc: datetime) -> float:
        next_day = now_utc.replace(hour=0, minute=0, second=0, microsecond=0) + timedelta(days=1)
        return max(0.01, (next_day - now_utc).total_seconds())

    def _refresh_defender_budget_windows(self, state: Dict[str, Any], now_utc: datetime) -> None:
        minute_floor = now_utc.replace(second=0, microsecond=0)
        day_floor = now_utc.replace(hour=0, minute=0, second=0, microsecond=0)
        if state["minute_start"] != minute_floor:
            state["minute_start"] = minute_floor
            state["minute_count"] = 0
        if state["day_start"] != day_floor:
            state["day_start"] = day_floor
            state["day_count"] = 0

    async def _wait_for_defender_budget(self, company_key: str) -> None:
        if not self.rate_policy.defender_budget_enforce:
            return
        while True:
            sleep_for = 0.0
            async with self._defender_budget_lock:
                state = self._get_defender_budget_state(company_key)
                minute_limit = self.rate_policy.defender_budget_minute_limit
                day_limit = self.rate_policy.defender_budget_day_limit
                now_utc = datetime.now(timezone.utc)
                self._refresh_defender_budget_windows(state, now_utc)
                if state["minute_count"] < minute_limit and state["day_count"] < day_limit:
                    state["minute_count"] += 1
                    state["day_count"] += 1
                    return

                sleep_for = self._seconds_until_next_minute(now_utc)
                if state["day_count"] >= day_limit:
                    sleep_for = max(sleep_for, self._seconds_until_next_utc_day(now_utc))
                logger.warning(
                    "Defender request budget exhausted company_key=%s minute=%s/%s day=%s/%s sleeping=%.2fs",
                    company_key,
                    state["minute_count"],
                    minute_limit,
                    state["day_count"],
                    day_limit,
                    sleep_for,
                )
            await asyncio.sleep(sleep_for)

    def is_defender_near_daily_cap(self, company_key: str, threshold: float = 0.85) -> bool:
        normalized = self._normalize_company_key(company_key)
        state = self._defender_budget_by_key.get(normalized)
        if not state:
            return False
        now_utc = datetime.now(timezone.utc)
        self._refresh_defender_budget_windows(state, now_utc)
        day_limit = max(1, self.rate_policy.defender_budget_day_limit)
        return state["day_count"] >= int(day_limit * threshold)

    def get_defender_budget_snapshot(self, company_key: str) -> Dict[str, int]:
        state = self._get_defender_budget_state(company_key)
        now_utc = datetime.now(timezone.utc)
        self._refresh_defender_budget_windows(state, now_utc)
        return {
            "minute_count": int(state["minute_count"]),
            "minute_limit": int(self.rate_policy.defender_budget_minute_limit),
            "day_count": int(state["day_count"]),
            "day_limit": int(self.rate_policy.defender_budget_day_limit),
        }

    def _maybe_attach_max_items(self, params: Optional[Dict[str, Any]], endpoint_name: str) -> Dict[str, Any]:
        merged = dict(params or {})
        if not self.rate_policy.defender_use_max_items_param:
            return merged
        if endpoint_name in self._defender_max_items_unsupported_endpoints:
            return merged
        merged["max-items"] = self.rate_policy.defender_max_items_param
        return merged

    async def _wait_for_rate_limit(self, url: str) -> None:
        """
        Enforce a global minimum interval between requests to prevent hitting 429 limits.
        """
        async with self._rate_limit_lock:
            while True:
                now = time.time()
                sleep_for = max(0.0, self._min_request_interval - (now - self._last_request_time))
                if sleep_for <= 0:
                    break
                await asyncio.sleep(sleep_for)

            current_time = time.time()
            self._last_request_time = current_time

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
        _auth_retry_depth: int = 0,
        company_key: Optional[str] = None,
        endpoint_name: Optional[str] = None,
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

        max_retries = self.rate_policy.max_retries
        initial_backoff = self.rate_policy.initial_backoff
        if endpoint_name and params and endpoint_name in self._defender_max_items_unsupported_endpoints and "max-items" in params:
            params = dict(params)
            params.pop("max-items", None)
        is_defender_request = self._is_defender_request(url)

        for attempt in range(max_retries + 1):
            try:
                # Apply global rate limit throttle before executing any request
                await self._wait_for_rate_limit(url)
                resolved_company_key = self._normalize_company_key(company_key) if company_key else self._extract_company_key_from_params(params)
                if is_defender_request:
                    await self._admission_wait_and_reserve(endpoint_name, resolved_company_key)
                    await self._wait_for_defender_budget(resolved_company_key)

                response = await self.client.request(
                    method=method, 
                    url=url, 
                    headers=headers, 
                    params=params, 
                    json=json_data
                )

                if response.status_code == 429:
                    self.rate_limit_hits += 1
                    retry_after_seconds = self._parse_retry_after_seconds(response) if self.rate_policy.defender_retry_respect_retry_after else 0.0
                    default_cooldown = float(self.rate_policy.defender_endpoint_cooldown_default_seconds)
                    cooldown_seconds = max(default_cooldown, retry_after_seconds)
                    if self._is_journal_endpoint(endpoint_name):
                        cooldown_seconds = max(cooldown_seconds, float(self.rate_policy.defender_journal_retry_after_floor_seconds))
                    await self._register_defender_429(endpoint_name, cooldown_seconds, resolved_company_key)
                    if self._is_journal_endpoint(endpoint_name):
                        logger.warning(
                            "Journal endpoint tenant placed in cooldown company_key=%s cooldown=%.2fs",
                            resolved_company_key,
                            cooldown_seconds,
                        )
                        raise LumuEndpointCooldownException(
                            endpoint_name or "unknown_defender_endpoint",
                            resolved_company_key,
                            cooldown_seconds,
                            "journal_tenant_cooldown",
                        )
                    if attempt == max_retries:
                        logger.error(f"Max retries reached for 429 error at {url}")
                        response.raise_for_status()

                    backoff = max(cooldown_seconds, initial_backoff * (2 ** attempt) + random.uniform(0, 0.5))
                    logger.warning(
                        "Rate limited (429) for %s. retry_after=%.2fs cooldown=%.2fs retry_in=%.2fs (Attempt %s/%s)",
                        url,
                        retry_after_seconds,
                        cooldown_seconds,
                        backoff,
                        attempt + 1,
                        max_retries,
                    )
                    await asyncio.sleep(backoff)
                    continue

                if is_defender_request and response.status_code in (400, 422) and params and "max-items" in params and endpoint_name:
                    self._defender_max_items_unsupported_endpoints.add(endpoint_name)
                    params = dict(params)
                    params.pop("max-items", None)
                    logger.warning(
                        "Defender endpoint does not support max-items endpoint=%s. Retrying without max-items.",
                        endpoint_name,
                    )
                    if attempt == max_retries:
                        response.raise_for_status()
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
                    return await self._request_with_retry(
                        method,
                        url,
                        headers,
                        params,
                        json_data,
                        auth_required,
                        _auth_retry_depth + 1,
                        company_key=company_key,
                        endpoint_name=endpoint_name,
                    )

                response.raise_for_status()
                if is_defender_request:
                    await self._register_defender_success(endpoint_name, resolved_company_key)
                return response
            
            except (httpx.RequestError, httpx.TimeoutException) as e:
                if is_defender_request:
                    await self._register_defender_429(
                        endpoint_name,
                        float(self.rate_policy.defender_endpoint_cooldown_default_seconds),
                        company_key,
                    )
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

    async def get_mssp_activity(self, from_date: str, to_date: str, timezone: Optional[str] = None) -> list:
        """
        Endpoint C: Fetch high-level activity details across the MSSP.
        from_date and to_date format: 'YYYY-MM-DDTHH:MM:SS.MMM'
        """
        endpoint = "/data-api/companies/activity/msp"
        resolved_timezone = timezone or self.settings.payload_timezone
        payload = {
            "from": from_date,
            "to": to_date,
            "timezone": resolved_timezone
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
        params = self._maybe_attach_max_items(params, endpoint_name="open_incidents_updates")
        
        logger.info(f"Fetching incident updates from offset {offset}...")
        # Note: auth_required=False because this API uses the 'key' query param
        try:
            response = await self._request_with_retry(
                "GET",
                url,
                params=params,
                auth_required=False,
                company_key=company_key,
                endpoint_name="open_incidents_updates",
            )
        except LumuEndpointCooldownException as exc:
            if exc.reason_code in {"journal_circuit_open", "journal_tenant_cooldown"}:
                reason = exc.reason_code
                cooldown_seconds = exc.cooldown_remaining_seconds
                logger.info(
                    "Skipping Defender journal request due to rate guard reason=%s company_key=%s cooldown_remaining=%.2fs",
                    reason,
                    self._normalize_company_key(company_key),
                    cooldown_seconds,
                )
                return {
                    "updates": [],
                    "offset": offset,
                    "_rate_guard_skipped": True,
                    "_rate_guard_reason": reason,
                    "_rate_guard_cooldown_seconds": cooldown_seconds,
                }
            raise
        return response.json()

    async def get_all_incidents(self, company_key: str, from_date: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Fetch all incidents for a specific company using its key, with time-based pagination support.
        The Lumu API limits queries to a 30-day window. This method iterates backwards in time.
        """
        from datetime import datetime, timedelta, timezone
        
        url = f"{self.settings.lumu_defender_url}/api/incidents/all"
        params = self._maybe_attach_max_items({"key": company_key}, endpoint_name="all_incidents_history")
        
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
                    auth_required=False,
                    company_key=company_key,
                    endpoint_name="all_incidents_history",
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
        params = self._maybe_attach_max_items({"key": company_key}, endpoint_name="open_incidents_state")
        
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
                auth_required=False,
                company_key=company_key,
                endpoint_name="open_incidents_state",
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

    async def get_open_incidents_lite(self, company_key: str) -> List[Dict[str, Any]]:
        """
        Fetch all currently OPEN incidents using the dedicated open-incidents endpoint.
        This is kept as an optional lighter snapshot path; the runtime still treats
        /api/incidents/all with status=["open"] as the authoritative compatible source.
        """
        url = f"{self.settings.lumu_defender_url}/api/incidents/open"
        params = self._maybe_attach_max_items({"key": company_key}, endpoint_name="open_incidents_lite")
        all_open = []
        seen_ids = set()
        page = 1
        page_size = 50

        while True:
            payload = {
                "adversary-types": [],
                "labels": [],
            }
            response = await self._request_with_retry(
                "POST",
                url,
                params={**params, "page": page, "items": page_size},
                json_data=payload,
                auth_required=False,
                company_key=company_key,
                endpoint_name="open_incidents_lite",
            )
            if response.status_code != 200:
                break
            data = response.json()
            items = data.get("items", []) if isinstance(data, dict) else []
            if not items:
                break
            for item in items:
                item_id = item.get("id") or item.get("uuid")
                if item_id and item_id not in seen_ids:
                    seen_ids.add(item_id)
                    all_open.append(item)
            if len(items) < page_size or page >= 200:
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
        company = self._normalize_company_key(company_key)
        semaphore = self._details_semaphores_by_company.setdefault(
            company,
            asyncio.Semaphore(max(1, int(self.rate_policy.details_per_tenant_concurrency))),
        )
        async with semaphore:
            response = await self._request_with_retry(
                "GET",
                url,
                params=params,
                auth_required=False,
                company_key=company_key,
                endpoint_name="incident_details",
            )
            return response.json()

    async def get_incident_contacts(self, company_key: str, incident_uuid: str) -> List[Dict[str, Any]]:
        """
        Fetch all contacts (endpoints) for a specific incident.
        """
        url = f"{self.settings.lumu_defender_url}/api/incidents/{incident_uuid}/contacts"
        params = {"key": company_key}
        company = self._normalize_company_key(company_key)
        semaphore = self._details_semaphores_by_company.setdefault(
            company,
            asyncio.Semaphore(max(1, int(self.rate_policy.details_per_tenant_concurrency))),
        )
        async with semaphore:
            response = await self._request_with_retry(
                "GET",
                url,
                params=params,
                auth_required=False,
                company_key=company_key,
                endpoint_name="incident_contacts",
            )
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

    async def get_incident_context(self, company_key: str, incident_uuid: str, hash_type: str = "sha256") -> Dict[str, Any]:
        """
        Fetch Defender context for an incident.
        Endpoint: GET /api/incidents/{incident_uuid}/context?key={company-key}&hash={hash-type}
        """
        url = f"{self.settings.lumu_defender_url}/api/incidents/{incident_uuid}/context"
        params = {"key": company_key, "hash": hash_type}
        company = self._normalize_company_key(company_key)
        semaphore = self._details_semaphores_by_company.setdefault(
            company,
            asyncio.Semaphore(max(1, int(self.rate_policy.details_per_tenant_concurrency))),
        )
        async with semaphore:
            response = await self._request_with_retry(
                "GET",
                url,
                params=params,
                auth_required=False,
                company_key=company_key,
                endpoint_name="incident_context",
            )
            return response.json()

    async def get_incident_external_articles(self, company_id: str, incident_uuid: str) -> List[Dict[str, Any]]:
        """
        Fetch external threat intelligence articles correlating with the threat actor or malware family in the incident.
        """
        endpoint = f"/intelligence/companies/{company_id}/secops-incidents/{incident_uuid}/context/external-articles"
        return await self.get_with_auth(endpoint)

    async def get_activity_event_details(self, company_uuid: str, event_uuid: str) -> Dict[str, Any]:
        """
        Fetch managed activity details for a specific activity event.
        Endpoint: GET /data-api/companies/{company_uuid}/activity/incidents/{event_uuid}/details
        """
        endpoint = f"/data-api/companies/{company_uuid}/activity/incidents/{event_uuid}/details"
        return await self.get_with_auth(endpoint)

    async def get_endpoint_contacts_range(
        self,
        company_uuid: str,
        endpoint_ip: str,
        label: str = "0",
        items: int = 5,
        page: int = 1,
    ) -> Dict[str, Any]:
        """
        Fetch managed endpoint contacts/range details for a specific endpoint.
        Endpoint: GET /data-api/companies/{company_uuid}/activity/label/{label}/endpoint/{endpoint_ip}/contacts/range
        """
        endpoint = f"/data-api/companies/{company_uuid}/activity/label/{label}/endpoint/{endpoint_ip}/contacts/range"
        data = await self.get_with_auth(endpoint, params={"items": items, "page": page})
        if isinstance(data, dict):
            contacts = data.get("contacts")
            return {
                "paginationInfo": data.get("paginationInfo", {}),
                "contacts": contacts if isinstance(contacts, list) else [],
            }
        if isinstance(data, list):
            return {"paginationInfo": {}, "contacts": data}
        return {"paginationInfo": {}, "contacts": []}

    async def close(self):
        await self.client.aclose()

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.close()
    def get_journal_next_allowed_seconds(self, company_key: str) -> float:
        company = self._normalize_company_key(company_key)
        next_allowed = self._journal_next_allowed_by_company.get(company, 0.0)
        return max(0.0, next_allowed - self._now_monotonic())
