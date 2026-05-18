# Development & Operations Guide

This guide describes how to deploy, configure, and troubleshoot the LumuIncidentHandler, with a focus on Docker-based operations and Kafka integration.

## Docker Deployment (Recommended)

The application is containerized to ensure consistent operations. It uses a security-hardened Docker configuration.

### Prerequisites

- [Docker](https://docs.docker.com/get-docker/)
- [Docker Compose](https://docs.docker.com/compose/install/)

### Step 1: Configuration

1.  Copy `.env.example` to `.env`.
2.  Provide your Lumu credentials and Kafka settings.

```bash
# Lumu Authentication
LUMU_EMAIL=your_user@example.com
LUMU_PASSWORD=your_password
LUMU_MSSP_UUID=your_mssp_uuid

# Multi-tenant mode
# Tenant UUIDs and Defender keys are discovered dynamically from MSSP endpoints.

# Kafka
KAFKA_BOOTSTRAP_SERVERS=localhost:9092
KAFKA_CLIENT_ID=lumu-incident-handler
KAFKA_DELIVERY_TIMEOUT_SECONDS=15
```

### Step 2: Launch

Start the service in detached mode:

```bash
docker-compose up -d
```

### Security Features

The Docker deployment includes several security-hardening measures:
- **Read-Only Root**: The container's root filesystem is mounted as read-only.
- **Dropped Capabilities**: All non-essential kernel capabilities are dropped (`ALL`).
- **Non-Root User**: The application runs as a dedicated `monitor` user.
- **Volume Persistence**: Only the `/app/data` directory is writable, ensuring persistent state for the `sent_incidents.json` high-water mark file and `agent_id` runtime identity file.
- **Secret Handling**: Sensitive credentials are managed via Pydantic's `SecretStr`, preventing them from being leaked in debug logs.

---

## Configuration Reference

| Variable | Default | Description |
|---|---|---|
| `LUMU_EMAIL` | - | Lumu MSSP Console email address. |
| `LUMU_PASSWORD` | - | Lumu MSSP Console password. |
| `LUMU_MSSP_UUID` | - | Unique UUID for the MSSP holding supervised companies. |
| `LUMU_DEFENDER_KEY` | - | Legacy single-tenant key (unused in multi-tenant runtime). |
| `CUSTOMER_UUID` | - | Legacy single-tenant UUID (unused in multi-tenant runtime). |
| `POLLING_INTERVAL_MINUTES`| `5` | Frequency of Lumu polling in minutes. |
| `LUMU_RATE_POLICY_PROFILE` | `balanced` | High-level rate policy (`strict`, `balanced`, `aggressive`) that controls cooldown/timing defaults. |
| `LUMU_RATE_POLICY_TENANT_CAP` | - | Optional override for tenant concurrency cap on top of profile defaults. |
| `LUMU_RATE_POLICY_ADVANCED` | `False` | When true, low-level expert rate vars are honored; otherwise profile mode is used. |
| `VERIFY_SSL` | `True` | Enable or disable SSL verification for all API clients. |
| `LUMU_OPEN_STATE_RECONCILIATION_MINUTES` | `15` | How often each tenant runs a full open-incident reconciliation sweep. |
| `LUMU_OPEN_STATE_JITTER_SECONDS` | `120` | Per-tenant jitter applied to the reconciliation schedule to avoid burst scans. |
| `LUMU_OPEN_STATE_FAILURE_BACKOFF_MINUTES` | `30` | Base scheduler backoff after a failed reconciliation sweep. |
| `LUMU_OPEN_STATE_MAX_BACKOFF_MINUTES` | `360` | Maximum scheduler backoff after repeated reconciliation failures. |
| `LUMU_OPEN_STATE_SYNC_ON_STARTUP` | `True` | Whether a tenant performs reconciliation before relying on journal-only polling. |
| `LUMU_TENANT_CONCURRENCY_CAP` | `3` | Max number of tenants processed concurrently in a polling cycle. |
| `LUMU_TENANT_CYCLE_JITTER_MAX_SECONDS` | `5` | Max random delay before each tenant run in a cycle to reduce synchronized API bursts. |
| `LUMU_DEFENDER_BUDGET_ENFORCE` | `True` | Enables Defender minute/day budget gating before Defender API requests. |
| `LUMU_DEFENDER_BUDGET_MINUTE_LIMIT` | `35` | Conservative per-tenant Defender budget per minute (published limit is 50/min). |
| `LUMU_DEFENDER_BUDGET_DAY_LIMIT` | `8000` | Conservative per-tenant Defender budget per UTC day (published limit is 10,000/day). |
| `LUMU_JOURNAL_ITEMS_PER_PAGE` | `100` | Requested item count for `open-incidents/updates` journal polling. |
| `LUMU_JOURNAL_DELAY_TIME_SECONDS` | `15` | Long-poll delay (`time`) used on Defender journal calls. |
| `LUMU_JOURNAL_MAX_PAGES_PER_CYCLE` | `2` | Maximum journal pages processed for one tenant in a single cycle. |
| `LUMU_DEFENDER_USE_MAX_ITEMS_PARAM` | `True` | Enables adding `max-items` on supported Defender list endpoints. |
| `LUMU_DEFENDER_MAX_ITEMS_PARAM` | `500` | Value sent as `max-items` when enabled and endpoint supports it. |
| `ALERT_STATE_FILE` | `data/sent_incidents.json` | Path to the high-water mark tracking file. |
| `KAFKA_BOOTSTRAP_SERVERS` | `localhost:9092` | Kafka bootstrap servers. |
| `KAFKA_TOPIC` | - | Legacy static topic (unused in multi-tenant runtime). |
| `KAFKA_CLIENT_ID` | `lumu-incident-handler` | Kafka producer client identifier. |
| `KAFKA_DELIVERY_TIMEOUT_SECONDS` | `15` | Max time to wait for the Kafka delivery callback for one message. |
| `KAFKA_FLUSH_TIMEOUT_SECONDS` | `10` | Max time to wait for producer flush after a successful delivery callback. |

---

## Troubleshooting & Maintenance

### Logs
View the real-time execution logs from the container:

```bash
docker-compose logs -f
```

### State Management
The system tracks incident activity in tenant-scoped files under `data/` using a **per-incident timestamp map**.

The state file schema:
```json
{
  "last_pulled_time": "2026-04-10T16:07:14Z",
  "offset": 123,
  "incidents": {
    "365f7220-34f6-11f1-bbc7-8fba9bac8610": "2026-04-10T16:07:14Z"
  },
  "open_state_sync_last_success_at": "2026-05-17T04:00:00.000Z",
  "open_state_sync_next_due_at": "2026-05-17T04:15:30.000Z",
  "open_state_sync_failure_count": 0
}
```

An incident is re-enriched and re-published to Kafka if:
- Its UUID is **not in the `incidents` map** (new incident), or
- Its `lastContact` is **newer than the stored timestamp** for that UUID (updated incident).

This ensures that incident updates - new endpoints, additional firewall responses, status changes - are always reflected in the Kafka topic payload stream.

The handler updates incident state only after a confirmed Kafka delivery callback. If delivery fails or times out, that incident remains eligible for retry in the next polling cycle.

### Agent Identity

The Kafka payload includes an `agent.id` value that uniquely identifies the running handler instance. The handler stores this UUID in `data/agent_id` and reuses it across restarts. If the file is deleted, the next startup generates a new UUID. `agent.name` and `manager.name` are populated from the hostname where the service runs, and `agent.ip` is detected from the primary outbound host route.

### Payload Shape

Kafka messages keep the outer wrapper:

```json
{
  "message": "<stringified-json-payload>"
}
```

Inside the stringified payload, Lumu-specific fields are grouped under `data.lumu`, affected endpoints use `srchost` and `srcip`, and the emitted payload includes top-level `agent`, `rule`, `decoder`, and `manager`. `data.lumu.event_type` is normalized to `NewIncidentCreated` or `IncidentUpdated`; incidents not already present in local state default to `NewIncidentCreated`. The payload also includes activity enrichments under `data.lumu.activity_incident_details` and `data.lumu.endpoint_context`, with endpoint context sourced from managed event details and any concrete Defender contact/detail rows. Top-level `integration`, `severity`, `event_type`, `ss_groups`, and `ss_customer` are not emitted.

### Rate-Control Behavior

- Defender cooldown/counter keys are canonical and tenant-scoped (`endpoint:tenant`).
- Journal breaker state is tenant-scoped, so one tenant opening the breaker does not suppress other tenants.
- `Retry-After` is honored for cooldown scheduling.
- Long non-journal cooldowns are fail-fast (structured exception) to avoid blocking the cycle.
- Details/contacts enrichment is paced by per-tenant semaphores (profile-driven).

### Rate Control FAQ

**Q: Why does one tenant show cooldown skips while others still process?**  
A: Cooldowns and breaker state are tenant-scoped. A throttled tenant is deferred independently, and other tenants continue polling.

**Q: What happens when Defender returns a very large `Retry-After`?**  
A: The tenant/endpoint is deferred until `next_allowed_at`. The runtime does not busy-retry the same request in a tight loop.

**Q: Will new incidents stop completely during cooldown?**  
A: No. Discovery is still attempted each cycle. What may degrade is deep enrichment (for example details/contacts) when endpoint cooldown is active.

**Q: Why are some incidents published with partial enrichment?**  
A: Long non-journal cooldowns raise a structured cooldown exception and the pipeline continues with available data to avoid cycle stalls.

**Q: How do I tune behavior without adding many env vars?**  
A: Use `LUMU_RATE_POLICY_PROFILE` (`strict`, `balanced`, `aggressive`). Use `LUMU_RATE_POLICY_TENANT_CAP` only when you need a specific tenant concurrency override.

### Internal Pipeline

The runtime is split into explicit stages:
- journal updates are the primary hot path each cycle
- open-state reconciliation is scheduled separately and persisted per tenant
- tenant execution is scheduled with bounded concurrency and per-tenant jitter
- `src/enrichment_fetcher.py`: fetches raw source data and applies source hierarchy/fallback policy
- `src/incident_builder.py`: converts raw source data into one canonical `IncidentEvent`
- `src/payload_serializer.py`: converts `IncidentEvent` into the published Kafka payload
- `src/analyzer.py`: handles tenant-scoped state, event classification, and update extraction only

This separation is intentional: fetch policy, data normalization, payload shape, and state tracking are tested independently.

To re-process all incidents from the last 30 days, clear the state file:
```bash
echo "{}" > data/sent_incidents.json
```

### Connectivity Checks
If incidents are not appearing in Kafka UI:
1. **Kafka Reachability**: Verify the container can reach `KAFKA_BOOTSTRAP_SERVERS` (usually port 9092).
2. **Topic Check**: Ensure tenant topics like `cli-grupoamil` are being created and receiving messages.
3. **Lumu API**: Confirm MSSP credentials are valid and tenant Defender key bootstrap succeeded in logs.
4. **Delivery Timeout**: Check for `Kafka delivery timeout` log lines; those indicate the handler continued the cycle but did not receive a broker ack in time.

The handler now logs:
- A Kafka runtime config summary at startup.
- Per-incident publish success/failure lines including `incident_uuid`.
- A per-cycle summary with success and failure counts.
- Defender budget pressure signals (minute/day usage) and any non-critical reconciliation skips when near daily cap.

## Development Setup (Local)

To run the application locally without Docker:

1.  Create a virtual environment: `python -m venv venv`.
2.  Activate it: `source venv/bin/activate` or `venv\Scripts\activate`.
3.  Install dependencies: `pip install -r requirements.txt`.
4.  Run the main loop: `python -m src.main`. (Note: use module syntax to respect internal imports).
