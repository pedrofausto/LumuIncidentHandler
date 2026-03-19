# Operational Workflows

The LumuIncidentHandler follows a precise lifecycle to process incidents. This document details the sequence of events from discovery to notification.

## The Polling Lifecycle

The application runs in a continuous loop, triggered at intervals defined by the `POLLING_INTERVAL` environment variable. Each iteration follows this sequence:

1.  **Authentication**: The `LumuClient` checks for a valid JWT. If missing or expired, it initiates a sign-in request to the Lumu Managed API.
2.  **Discovery**: It queries the Defender API for all active incidents within the configured time window (defaulting to the last 30 days if not otherwise specified).
3.  **Deduplication**: The `Analyzer` compares discovered incident UUIDs against the local state file (`data/alerts.json`). Only "new" incidents proceed to the next stage.
4.  **Enrichment**: For each new incident, the system:
    - Fetches the associated **STIX 2.1 intelligence bundle** from the Managed API.
    - Retrieves detailed **endpoint and contact data** from the Defender API.
5.  **Transformation**: The `Analyzer` parses raw JSON and STIX objects into a unified `IncidentEvent` model.
6.  **Notification**: The `Notifier` renders the incident data into an HTML template and dispatches it via the configured SMTP server.
7.  **State Persistence**: Once successfully notified, the incident's UUID is recorded in `data/alerts.json` to prevent duplicate alerts.

## Request/Response Flow (Detailed)

```text
Time       Main Orchestrator          Lumu API (Defender/Managed)          External (SMTP)
 |                |                                |                              |
 | [Interval Start]                                |                              |
 |                |---- Auth (JWT) Request ------->|                              |
 |                |<--- Auth (JWT) Response -------|                              |
 |                |                                |                              |
 |                |---- GET Incidents (All) ------>|                              |
 |                |<--- JSON Incident List --------|                              |
 |                |                                |                              |
 | [Deduplication]| (Internal Logic - Filter)      |                              |
 |                |                                |                              |
 |                |---- GET STIX Bundle ---------->|                              |
 |                |<--- STIX 2.1 JSON -------------|                              |
 |                |                                |                              |
 |                |---- GET Incident Details ----->|                              |
 |                |<--- JSON Endpoint Details -----|                              |
 |                |                                |                              |
 | [Transformation]| (Internal Logic - IncidentEvent)|                             |
 |                |                                |                              |
 |                |------------ SEND HTML Alert --------------------------------->|
 |                |                                |<--- Notification Sent -------|
 |                |                                |                              |
 | [Persistence]  | (Update alerts.json)           |                              |
 |                |                                |                              |
 v [Interval End] |                                |                              |
```

## Error Handling & Retries

- **API Failures**: If the Lumu API returns a transient error (e.g., 5xx), the current polling cycle is aborted, and the system waits for the next interval.
- **Auth Expiry**: The `LumuClient` automatically detects 401 Unauthorized responses, clears the invalid token, and re-authenticates on the next attempt.
- **SMTP Failures**: Notification failures are logged as errors, but the incident UUID is **not** added to the state file, ensuring the system will retry the notification in the next polling cycle.
