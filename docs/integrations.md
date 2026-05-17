# Lumu API & Data Integrations

LumuIncidentHandler acts as an intelligent bridge between the Lumu platform and incident response stacks. It integrates multiple Lumu APIs and Kafka to build rich, actionable context for every detected threat.

## Lumu API Integration

The system communicates with three distinct Lumu API surfaces to build a complete forensic picture.

The runtime applies a fixed source hierarchy:
- Defender `details` for incident-level detail and actions
- Managed `secops-incidents` for endpoint breadth and activity event references
- Managed `activity/incidents/{event_uuid}/details` for per-endpoint telemetry/context
- Defender `contacts` only as fallback when breadth or context is still incomplete

### 1. Authentication & STIX (Managed API)
- **Base URL**: `https://managed.lumu.io`
- **Authentication**: JWT Bearer token obtained via email/password sign-in.
- **STIX Intelligence**: Fetches full STIX 2.1 bundles including Malware families, Indicators of Compromise (IOCs), and Sightings.

### 2. Incident Discovery (Defender API)
- **Base URL**: `https://defender.lumu.io`
- **Mechanism**: Authenticated via a `key` query parameter.
- **Discovery**: Uses `GET /api/incidents/open-incidents/updates` as the primary hot path and runs `POST /api/incidents/all` only as scheduled open-state reconciliation or journal recovery.
- **Tenant Execution Scheduling**: Polling cycles run tenants with bounded parallelism and per-tenant jitter to reduce synchronized request spikes against Defender APIs.
- **Incident Details**: `GET /api/incidents/{incident_uuid}/details?key=...` is the primary incident-detail source.
- **Contacts Fallback**: `GET /api/incidents/{incident_uuid}/contacts?key=...` is used only when Defender details plus Managed secops data do not provide enough endpoint breadth or endpoint context.
- **Reconciliation Strategy**: Full open-incident sweeps are scheduled per tenant with persisted due times and exponential scheduler backoff after `/api/incidents/all` failures.
- **Quota Governance**: Defender requests are budget-gated per tenant key using conservative limits (`35 req/min`, `8000 req/day`) derived from published Defender quotas (`50/min`, `10,000/day`).
- **List Optimization**: Journal/state list endpoints can include `max-items`; if Defender rejects it (`400/422`) the handler disables that parameter for the endpoint for the remainder of the process and retries without it.
- **Near-Daily-Cap Degradation**: When a tenant nears daily budget threshold, non-critical reconciliation sweeps are skipped and journal polling is automatically slowed/capped.
- **Retry-After Cooldown Scheduler**: `429` responses are deferred using `Retry-After` as `next_allowed_at` cooldown, instead of immediate repeated retries.
- **Tenant-Scoped Journal Cooldown**: cooldown for `open-incidents/updates` is keyed by tenant API key + endpoint, so one throttled tenant does not block others.

### 3. Context Enrichment (Defender API)
- **Context Summary**: Fetches high-level summaries, MITRE ATT&CK technique mappings, and recommended playbooks.
- **External Articles**: Retrieves curated intelligence articles from Lumu's researchers associated with the specific threat.

### 4. Activity Enrichment (Managed API)
- **SecOps Incident Summary**: Fetches incident-level managed summary data via `/data-api/secops-incidents/companies/{company_uuid}/incidents/{incident_uuid}/details`.
- **Activity Event Details**: Fetches per-event managed activity details via `/data-api/companies/{company_uuid}/activity/incidents/{event_uuid}/details`.
- **Event ID Rule**: Activity detail requests use activity event IDs discovered inside the secops payload, not the secops incident ID itself.
- **Endpoint Context Output**: Merges real per-endpoint context under `data.lumu.endpoint_context` using managed event details plus any concrete Defender contact/detail rows that carry source telemetry.

### Internal Stages
- **Fetcher**: `src/enrichment_fetcher.py`
- **Builder**: `src/incident_builder.py`
- **Serializer**: `src/payload_serializer.py`
- **State / Event Classification**: `src/analyzer.py`

---

## Kafka Integration

The final stage of the pipeline is publishing to **Kafka**.

- **Topic Name**: computed per tenant as `cli-<normalized_customer_name>`.
- **Ingestion Method**: Official Confluent Python client (`confluent-kafka`) with `Producer`, delivery callback polling, bounded delivery timeout, and final flush confirmation.
- **Message Key**: `data.lumu.id` when available.
- **Data Format**: Kafka message value is JSON with one field, `message`, that contains the stringified enriched incident payload.
- **Failure Behavior**: If a delivery callback is not received before `KAFKA_DELIVERY_TIMEOUT_SECONDS`, the publish fails explicitly and the incident is retried in a later cycle because state is not advanced.

### Kafka Payload Shape

The pre-stringify payload is reshaped before publishing. Lumu-specific identity, enrichment, and endpoint fields are grouped under `data.lumu`; operational routing fields remain at the top level.

```json
{
  "data": {
    "lumu": {
      "id": "incident-uuid",
      "adversaries": "threat title",
      "adversary_id": "indicator-or-adversary-id",
      "adversary_types": "Malware",
      "company_id": "customer-uuid",
      "customer_name": "Customer Name",
      "endpoints_affected": 8,
      "affected_endpoints": [
        {
          "srchost": "source-hostname-or-ip",
          "srcip": "10.0.0.10",
          "first_contact": "2026-05-06T14:50:43.864Z",
          "last_contact": "2026-05-06T15:10:00.000Z"
        }
      ],
      "status": "open",
      "event_type": "NewIncidentCreated",
      "details": "incident description",
      "mitre_techniques": [],
      "related_artifacts": {},
      "recommended_playbooks": [],
      "intelligence_tags": [],
      "intelligence_articles": [],
      "extracted_iocs": [],
      "disseminated": false,
      "dissemination_time": null,
      "dissemination_latency": null,
      "mtt_response": null,
      "mtt_resolution": null,
      "triggered_integrations": [],
      "tlp": "TLP: RED",
      "stix_indicators": [],
      "stix_malware": [],
      "stix_sighting": null,
      "activity_incident_details": {
        "incident_id": "incident-uuid",
        "counts": {},
        "offenders_samples": [],
        "targets_samples": [],
        "first_event": {},
        "last_event": {}
      }
    }
  },
  "agent": {
    "name": "handler-hostname",
    "id": "stable-agent-uuid",
    "ip": "10.0.0.5"
  },
  "rule": {
    "level": "16",
    "id": "0000",
    "groups": ["lumu"],
    "description": "Lumu integration rule"
  },
  "decoder": {
    "name": "int-dec-lumu"
  },
  "manager": {
    "name": "handler-hostname"
  },
  "product_name": "Lumu Defender",
  "timezone": "America/Sao_Paulo"
}
```

Rule level mapping is `Low="3"`, `Medium="8"`, `High="16"`, with unknown values defaulting to `"8"`. `data.lumu.event_type` is normalized to `NewIncidentCreated` or `IncidentUpdated`; new incidents default to `NewIncidentCreated` when they are not already present in local state. When `EVENT_TYPE_TEST_MODE=true`, `data.lumu.event_type` is forced to `"test"` for debugging. The `integration`, top-level `severity`, top-level `event_type`, `ss_groups`, and `ss_customer` fields are not emitted.
`data.lumu.endpoint_context` is emitted only when concrete per-endpoint context exists. Null-only placeholder entries are not emitted. `users` and `emails` are emitted only inside `endpoint_context` and are not duplicated into `affected_endpoints`. Telemetry severity is emitted only when it matches normalized incident severity.

---

## Incident Data Model (`IncidentEvent`)

All raw data is normalized into the `IncidentEvent` model.

| Category | Field | Source | Description |
|---|---|---|---|
| **Identity** | `data.lumu.id` | Defender API | Unique Lumu identifier. |
| | `data.lumu.adversaries` | Defender API | Human-readable threat name. |
| **Status** | `severity` | Defender API | Threat level (High/Medium/Low). |
| | `data.lumu.status` | Defender API | Lifecycle status (open/closed). |
| | `data.lumu.event_type` | Internal/Lumu Journal | Normalized event type: `NewIncidentCreated` or `IncidentUpdated`. |
| **Timelines** | `first_contact` | Defender API | First recorded sighting. |
| | `last_contact` | Defender API | Most recent recorded sighting. |
| **Asset Context**| `data.lumu.endpoints_affected`| Defender API | Total count of impacted devices reported by Lumu. |
| | `data.lumu.affected_endpoints`| Defender API | Concrete endpoint records from contacts/details APIs, including `srchost` and `srcip`. |
| **Intelligence** | `data.lumu.mitre_techniques` | Context API | MITRE ATT&CK Tactic/Technique mapping. |
| | `data.lumu.extracted_iocs` | Context API | Extracted IOCs and parsed domains from summary enrichment. |
| | `data.lumu.stix_indicators` | STIX Bundle | Patterns and IOCs from the STIX bundle. |
| | `data.lumu.tlp` | STIX Bundle | Traffic Light Protocol level. |
| **Activity Context** | `data.lumu.activity_incident_details` | Managed API | Per-incident managed secops summary including offender and target samples. |
| | `data.lumu.endpoint_context` | Managed + Defender APIs | Per-endpoint users/emails/OS plus merged HTTP, network, and telemetry context from managed event details and concrete Defender contact/detail rows. |
| **Response** | `data.lumu.recommended_playbooks`| Context API | Suggested SOPs for remediation. |
| | `data.lumu.triggered_integrations`| Defender Details| Third-party tools already notified by Lumu. |
| | `data.lumu.disseminated`| Defender Details| Whether an automated response action was observed. |
| **Metrics** | `data.lumu.dissemination_latency`| Internal | Time from Detection to Automated Response (MTTD). |
| | `data.lumu.mtt_response` | Internal | Time from Sighting to Automated Response. |
| | `data.lumu.mtt_resolution` | Internal | Time from Sighting to Closure. |
