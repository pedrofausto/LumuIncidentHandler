# LumuIncidentHandler Architecture

The LumuIncidentHandler is an asynchronous, polling-based security monitor designed to identify, enrich, and dispatch security incidents from the Lumu platform to **Kafka**. It automates the extraction of incident data, correlates it with STIX 2.1 threat intelligence/context, and ensures real-time visibility for downstream consumers.

## System Architecture

The application is structured into four main functional blocks: Orchestration, API Integration, Analysis, and Ingestion.

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
|   +--------------+         +-----------------+         +---------------------+  |
|   |   Analyzer   |-------->| High-Water Mark |         |       Kafka         |  |
|   | (Enrichment) |         | (sent_incidents)|         |                     |  |
|   +-------+------+         +-----------------+         +----------+----------+  |
|           |                                                       ^             |
|           v                                                       |             |
|   +--------------+                                                |             |
|   | Kafka Client |------------------------------------------------+             |
|   |  (Producer)  |                                                              |
|   +--------------+                                                              |
+---------------------------------------------------------------------------------+
```

## Core Components

### 1. Orchestrator (`src/main.py`)
The `main.py` script serves as the entry point, running an `asyncio` loop. It manages the polling interval, coordinates concurrent enrichment tasks, and handles graceful shutdowns.

### 2. Lumu Session (`src/lumu_client.py`)
Handles all communication with Lumu's Managed and Defender APIs. 
- **Managed API**: Handles JWT authentication and STIX 2.1 bundle retrieval.
- **Defender API**: Fetches incident lists, endpoint details, and context summaries.
- **Contacts API**: Fetches affected endpoint records so payloads can include concrete `srchost` and `srcip` values when Lumu exposes them.
- It implements a thread-safe `httpx.AsyncClient` for high-performance concurrent I/O.

### 3. Analyzer (`src/analyzer.py`)
The logic engine that transforms raw API responses into actionable insights:
- **High-Water Mark Retrieval**: Uses the `lastContact` timestamp of incidents to identify truly new or updated events, comparing them against `data/sent_incidents.json`.
- **Enrichment**: Merges raw incident data with STIX objects (Malware, Indicators) and Lumu Context (MITRE Techniques, Playbooks).
- **Metric Calculation**: Calculates critical KPIs like Mean Time to Disseminate (MTTD), MTTR (Response), and MTTR (Resolution).

### 4. Kafka Client (`src/kafka_client.py`)
Responsible for publishing incidents to Kafka.
- **Producer Delivery Guarantees**: Uses Confluent's official Python `Producer` with delivery callbacks, bounded polling until ack or timeout, and flush-based queue drain verification.
- **Payload Contract**: Publishes a JSON value with one field, `message`, containing the stringified reshaped incident JSON payload.
- **Partitioning Key**: Uses `lumu.id` as the Kafka message key when available.
- **Failure Semantics**: A timed-out or failed delivery raises an exception for that incident, leaves state unchanged for retry, and does not stall the handler loop.

### 5. Configuration (`src/config.py`)
Uses `pydantic-settings` to manage environment-based configuration with strict type validation, handling secrets securely via `SecretStr`.
- `KAFKA_TOPIC` is required at startup.
- `KAFKA_DELIVERY_TIMEOUT_SECONDS` bounds how long one publish waits for broker acknowledgement.
