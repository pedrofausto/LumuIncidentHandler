# Lumu API & Data Integrations

LumuIncidentHandler acts as an intelligent bridge between the Lumu platform and incident response stacks. It integrates multiple Lumu APIs and Kafka to build rich, actionable context for every detected threat.

## Lumu API Integration

The system communicates with three distinct Lumu API surfaces to build a complete forensic picture.

### 1. Authentication & STIX (Managed API)
- **Base URL**: `https://managed.lumu.io`
- **Authentication**: JWT Bearer token obtained via email/password sign-in.
- **STIX Intelligence**: Fetches full STIX 2.1 bundles including Malware families, Indicators of Compromise (IOCs), and Sightings.

### 2. Incident Discovery (Defender API)
- **Base URL**: `https://defender.lumu.io`
- **Mechanism**: Authenticated via a `key` query parameter.
- **Discovery**: Queries all active incidents. The system applies a 30-day sliding window for initial discovery and a high-water mark for subsequent polling cycles.
- **Endpoint Data**: Retrieves specific details and contacts for impacted assets (hostnames, source IPs, and contact timestamps).

### 3. Context Enrichment (Defender API)
- **Context Summary**: Fetches high-level summaries, MITRE ATT&CK technique mappings, and recommended playbooks.
- **External Articles**: Retrieves curated intelligence articles from Lumu's researchers associated with the specific threat.

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
      "stix_sighting": null
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
| **Response** | `data.lumu.recommended_playbooks`| Context API | Suggested SOPs for remediation. |
| | `data.lumu.triggered_integrations`| Defender Details| Third-party tools already notified by Lumu. |
| | `data.lumu.disseminated`| Defender Details| Whether an automated response action was observed. |
| **Metrics** | `data.lumu.dissemination_latency`| Internal | Time from Detection to Automated Response (MTTD). |
| | `data.lumu.mtt_response` | Internal | Time from Sighting to Automated Response. |
| | `data.lumu.mtt_resolution` | Internal | Time from Sighting to Closure. |
