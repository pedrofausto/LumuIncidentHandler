# Operational Workflows

The LumuIncidentHandler follows a precise, asynchronous lifecycle to process and enrich security incidents. This document details the sequence of events from discovery to Wazuh ingestion.

## The Polling Lifecycle

The application runs in a continuous `asyncio` loop, triggered at intervals defined by `POLLING_INTERVAL_MINUTES`. Each iteration follows this sequence:

1.  **Authentication**: The system ensures a valid JWT for the Lumu Managed API is available.
2.  **Discovery**: It queries the Defender API for all active incidents.
3.  **High-Water Mark Deduplication**: The `Analyzer` compares the `lastContact` timestamp of each incident against the `last_pulled_time` stored in `data/sent_incidents.json`. Only "new" or "updated" incidents proceed.
4.  **Concurrent Enrichment**: For each qualifying incident, the system spawns concurrent tasks to fetch:
    - **STIX 2.1 Intelligence**: Malware and Indicators from the Managed API.
    - **Incident Details**: Detailed asset/contact data from the Defender API.
    - **Context Summary**: MITRE mappings and playbooks.
    - **External Articles**: Curated research articles.
5.  **Transformation**: The `Analyzer` merges these four data sources into a unified `IncidentEvent` model and calculates MTTR/MTTD metrics.
6.  **Ingestion (Upsert)**: The `WazuhClient` transforms the event into a document and performs a **Native Upsert** to the Wazuh Indexer using the incident UUID as the key.
7.  **State Persistence**: Once a cycle completes, the `last_pulled_time` is updated in the state file to the latest activity timestamp seen.

## Request/Response Flow (Detailed)

```text
Time       Main Orchestrator          Lumu APIs (Multiple)                 Wazuh Indexer
 |                |                                |                              |
 | [Interval Start]                                |                              |
 |                |---- Auth (JWT) Request ------->|                              |
 |                |<--- Auth (JWT) Response -------|                              |
 |                |                                |                              |
 |                |---- GET Incidents (All) ------>|                              |
 |                |<--- JSON Incident List --------|                              |
 |                |                                |                              |
 | [Deduplication]| (Internal: High-Water Mark)    |                              |
 |                |                                |                              |
 |                |--+-- GET STIX Bundle --------->|                              |
 |                |  |-- GET Incident Details ---->|                              |
 | [Concurrent]   |  |-- GET Context Summary ---->|                              |
 | [Enrichment]   |  |-- GET External Articles -->|                              |
 |                |  |                             |                              |
 |                |<-+-- Combined Results ---------|                              |
 |                |                                |                              |
 | [Metrics Calc] | (Calculate MTTD/MTTR)          |                              |
 |                |                                |                              |
 |                |------------ NATIVE UPSERT (_update) ------------------------->|
 |                |                                |<--- Document Created/Updated |
 |                |                                |                              |
 | [Persistence]  | (Update last_pulled_time)       |                              |
 |                |                                |                              |
 v [Interval End] |                                |                              |
```

## Error Handling & Resiliency

- **Graceful Enrichment**: If a specific enrichment API (like STIX or Articles) fails or returns 404, the system continues with the remaining data rather than aborting the incident.
- **Wazuh Retries**: If the Wazuh Indexer is temporarily unavailable, the `WazuhClient` raises an exception, the high-water mark is **not** updated, and the system will attempt to process those incidents again in the next cycle.
- **Auth Recovery**: JWT tokens are automatically refreshed upon expiration detected during any Managed API call.
