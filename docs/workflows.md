# Operational Workflows

The LumuIncidentHandler follows a precise, asynchronous lifecycle to process and enrich security incidents. This document details the sequence of events from discovery to Kafka publishing.

## The Polling Lifecycle

The application runs in a continuous `asyncio` loop, triggered at intervals defined by `POLLING_INTERVAL_MINUTES`. Each iteration follows this sequence:

1.  **Authentication**: The system ensures a valid JWT for the Lumu Managed API is available.
2.  **Tenant Bootstrap + Discovery**: It discovers supervised tenants, loads Defender keys for new tenants, then queries the Defender API for active incidents per tenant.
3.  **High-Water Mark Deduplication**: The `Analyzer` compares the `lastContact` timestamp of each incident against the stored timestamp in `data/sent_incidents.json`. Only new incidents (not in the local state) or updated incidents (newer `lastContact` than the stored state) proceed.
4.  **Selective Enrichment**: For each qualifying incident, the system determines the enrichment mode (`minimal_mode`):
    - **Updated Incidents**: Automatically run in **minimal mode** (`minimal_mode=True`) to prevent redundant enrichment queries and preserve Lumu API budget/rate limits.
    - **New Incidents**: Checked against the historical cutoff window configured by `LUMU_HISTORICAL_CUTOFF_DAYS` (default: 14 days), based on the incident creation/grouping `timestamp` in the Lumu console.
      - **New and Within Cutoff**: Runs in **full enrichment mode** (`minimal_mode=False`) to fetch:
        - **STIX 2.1 Intelligence**: Malware and Indicators from the Managed API.
        - **Incident Details**: Detailed asset/contact data from the Defender API.
        - **Incident Contacts**: Full affected endpoint records from the Defender API, used to populate host/IP pairs.
        - **Context Summary**: MITRE mappings and playbooks.
        - **External Articles**: Curated research articles.
      - **New but Historical (Older than Cutoff)**: Runs in **minimal mode** (`minimal_mode=True`), bypassing the deep/STIX details queries.
5.  **Transformation**: The `Analyzer` merges the fetched data sources into a unified `IncidentEvent` model (calculating MTTR/MTTD metrics). The orchestrator reshapes the Kafka payload so Lumu fields live under `data.lumu` and source endpoints expose `srchost`/`srcip`.
6.  **Kafka Publish**: The `KafkaClient` publishes the enriched incident to Kafka as JSON with a single `message` field containing the stringified reshaped payload, to a tenant topic `cli-<normalized_customer_name>`, then waits for a bounded delivery callback confirmation.
7.  **State Persistence**: Each incident timestamp is persisted only after a confirmed Kafka delivery. Failed or timed-out deliveries remain eligible for retry in later cycles.

## Request/Response Flow (Detailed)

```text
Time       Main Orchestrator          Lumu APIs (Multiple)                      Kafka
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
 | [Concurrent]   |  |-- GET Contacts ----------->|                              |
 |                |  |-- GET Context Summary ---->|                              |
 | [Enrichment]   |  |-- GET External Articles -->|                              |
 |                |  |                             |                              |
 |                |<-+-- Combined Results ---------|                              |
 |                |                                |                              |
 | [Metrics Calc] | (Calculate MTTD/MTTR)          |                              |
 |                |                                |                              |
|                |------------ PRODUCE (topic: cli-<tenant>, key: data.lumu.id) ->|
|                |                                |<--- Delivery Confirmation    |
|                |                                |                              |
| [Persistence]  | (Update incident state only on ack) |                          |
 |                |                                |                              |
 v [Interval End] |                                |                              |
```

## Error Handling & Resiliency

- **Graceful Enrichment**: If a specific enrichment API (like STIX, Contacts, or Articles) fails or returns 404, the system continues with the remaining data rather than aborting the incident.
- **Kafka Retries**: If Kafka delivery fails or times out, the `KafkaClient` raises an exception, the per-incident state is **not** updated, and the system will attempt to process those incidents again in the next cycle.
- **Auth Recovery**: JWT tokens are automatically refreshed upon expiration detected during any Managed API call.
- **Cycle Liveness**: A single incident publish failure does not abort the batch; remaining incidents continue processing and the cycle ends with a success/failure summary log.
