# LumuIncidentHandler Architecture

The LumuIncidentHandler is an asynchronous, polling-based security monitor designed to identify, enrich, and dispatch security incidents from the Lumu platform to a **Wazuh Indexer (OpenSearch)**. It automates the extraction of incident data, correlates it with STIX 2.1 threat intelligence/context, and ensures real-time visibility in SOC dashboards.

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
|   |   Analyzer   |-------->| High-Water Mark |         |    Wazuh Indexer    |  |
|   | (Enrichment) |         | (sent_incidents)|         |    (OpenSearch)     |  |
|   +-------+------+         +-----------------+         +----------+----------+  |
|           |                                                       ^             |
|           v                                                       |             |
|   +--------------+                                                |             |
|   | Wazuh Client |------------------------------------------------+             |
|   |   (Upsert)   |                                                              |
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
- It implements a thread-safe `httpx.AsyncClient` for high-performance concurrent I/O.

### 3. Analyzer (`src/analyzer.py`)
The logic engine that transforms raw API responses into actionable insights:
- **High-Water Mark Retrieval**: Uses the `lastContact` timestamp of incidents to identify truly new or updated events, comparing them against `data/sent_incidents.json`.
- **Enrichment**: Merges raw incident data with STIX objects (Malware, Indicators) and Lumu Context (MITRE Techniques, Playbooks).
- **Metric Calculation**: Calculates critical KPIs like Mean Time to Disseminate (MTTD), MTTR (Response), and MTTR (Resolution).

### 4. Wazuh Client (`src/wazuh_client.py`)
Responsible for data ingestion into the Wazuh Indexer.
- **Native Upsert**: Uses the OpenSearch `_update` API with `doc_as_upsert: true` to prevent duplicate records and ensure incident updates (e.g., new endpoints detected) are reflected in a single document.
- **Schema Mapping**: Normalizes the internal `IncidentEvent` model into a format optimized for Wazuh/OpenSearch dashboards, including `@timestamp` injection.

### 5. Configuration (`src/config.py`)
Uses `pydantic-settings` to manage environment-based configuration with strict type validation, handling secrets securely via `SecretStr`.
