# LumuIncidentHandler Architecture

The LumuIncidentHandler is an asynchronous, polling-based security monitor designed to identify, enrich, and dispatch security incidents from the Lumu platform to **Kafka**. It automates the extraction of incident data, correlates it with STIX 2.1 threat intelligence/context, and ensures real-time visibility for downstream consumers.

## System Architecture

The application is structured into five main functional blocks: Orchestration, API Integration, Source Fetching, Incident Building, and Ingestion/State.

### Component Diagram (ASCII)

```text
+---------------------------------------------------------------------------------+
|                              LumuIncidentHandler                                |
|                                                                                 |
|   +--------------+         +-----------------+         +---------------------+  |
|   |   Main Loop  |-------->|   LumuSession   |-------->|      Lumu APIs      |  |
|   | (Async Poll) |<--------| (JWT/Defender)  |<--------| (Managed/Defender)  |  |
|   +-------+------+         +-----------------+         +---------------------+  |
|           |                                                                     |
|           v                                                                     |
|   +-------------------+    +-------------------+    +-----------------------+  |
|   | EnrichmentFetcher |--->|  IncidentBuilder  |--->|  PayloadSerializer    |  |
|   |  (source policy)  |    | (normalization)   |    |   (data.lumu shape)   |  |
|   +---------+---------+    +---------+---------+    +-----------+-----------+  |
|             |                          |                          |              |
|             v                          v                          v              |
|   +-------------------+      +-----------------+        +-------------------+  |
|   |     Analyzer      |      | High-Water Mark |        |    Kafka Client   |  |
|   | (state + events)  |      | (sent_incidents)|        |    (Producer)     |  |
|   +-------------------+      +-----------------+        +-------------------+  |
+---------------------------------------------------------------------------------+
```

## Core Components

### 1. Orchestrator (`src/main.py`)
The `main.py` script serves as the entry point, running an `asyncio` loop. It manages tenant discovery, journal-first polling, scheduled open-state reconciliation, bounded tenant concurrency, per-tenant start jitter, concurrent enrichment tasks, event building, Kafka publish orchestration, and graceful shutdown.

### 2. Lumu Session (`src/lumu_client.py`)
Handles all communication with Lumu's Managed and Defender APIs. 
- **Managed API**: Handles JWT authentication and STIX 2.1 bundle retrieval.
- **Tenant Bootstrap**: Discovers supervised tenants and fetches each tenant Defender API key once at bootstrap.
- **Defender API**: Fetches incident lists, endpoint details, and fallback contact records.
- **Budget Governor**: Enforces per-tenant Defender request budgets (minute/day windows) before every Defender call, including retries.
- **Capability Fallback**: Tries `max-items` on list endpoints and auto-disables it per endpoint if Defender rejects the parameter.
- It implements a thread-safe `httpx.AsyncClient` for high-performance concurrent I/O.

### 3. Enrichment Fetcher (`src/enrichment_fetcher.py`)
Owns source hierarchy and fallback behavior:
- Fetches Defender incident details
- Fetches Managed secops incident details
- Discovers Managed activity event IDs
- Fetches Managed activity event details
- Fetches Defender contacts only when breadth or context is incomplete
- Fetches STIX, context summary, and external articles

### 4. Incident Builder (`src/incident_builder.py`)
The normalization engine that converts raw API responses into one canonical `IncidentEvent`:
- Parses STIX objects
- Parses MITRE/context summary enrichments
- Builds `affected_endpoints` from the union of valid endpoint-bearing sources
- Builds `endpoint_context` from Managed activity and Defender contact/detail telemetry
- Calculates dissemination and response metrics

### 5. Analyzer (`src/analyzer.py`)
Now focused on state and event classification:
- **Per-Tenant High-Water Mark Retrieval**: Uses the `lastContact` timestamp of incidents to identify truly new or updated events, comparing them against tenant-scoped state files in `data/`.
- **Reconciliation Scheduler**: Persists per-tenant open-state reconciliation due times and backoff after `/api/incidents/all` failures.
- **Event Classification**: Normalizes incidents to `NewIncidentCreated` or `IncidentUpdated`.
- **Journal Update Extraction**: Unwraps incident objects from Lumu journal/update events.

### 6. Payload Serializer (`src/payload_serializer.py`)
Owns only the final payload contract:
- Shapes the canonical `IncidentEvent` into the published `data.lumu` structure
- Preserves the top-level operational envelope (`agent`, `rule`, `decoder`, `manager`, `product_name`, `timezone`)

### 7. Kafka Client (`src/kafka_client.py`)
Responsible for publishing incidents to Kafka.
- **Dynamic Topic Routing**: Topic is provided at runtime per tenant as `cli-<normalized_customer_name>`.
- **Producer Delivery Guarantees**: Uses Confluent's official Python `Producer` with delivery callbacks, bounded polling until ack or timeout, and flush-based queue drain verification.
- **Payload Contract**: Publishes a JSON value with one field, `message`, containing the stringified reshaped incident JSON payload.
- **Partitioning Key**: Uses `data.lumu.id` as the Kafka message key when available.
- **Failure Semantics**: A timed-out or failed delivery raises an exception for that incident, leaves state unchanged for retry, and does not stall the handler loop.

### 8. Configuration (`src/config.py`)
Uses `pydantic-settings` to manage environment-based configuration with strict type validation, handling secrets securely via `SecretStr`.
- Multi-tenant runtime does not require a static `KAFKA_TOPIC`; topic routing is computed per tenant.
- `KAFKA_DELIVERY_TIMEOUT_SECONDS` bounds how long one publish waits for broker acknowledgement.
