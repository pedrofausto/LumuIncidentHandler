# Lumu API & Data Integrations

LumuIncidentHandler acts as an intelligent bridge between the Lumu platform and incident response stacks. It integrates multiple Lumu APIs and the Wazuh Indexer to build rich, actionable context for every detected threat.

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
- **Endpoint Data**: Retrieves specific details on impacted assets (workstations, IPs).

### 3. Context Enrichment (Defender API)
- **Context Summary**: Fetches high-level summaries, MITRE ATT&CK technique mappings, and recommended playbooks.
- **External Articles**: Retrieves curated intelligence articles from Lumu's researchers associated with the specific threat.

---

## Wazuh Indexer Integration (OpenSearch)

The final stage of the pipeline is the ingestion into the **Wazuh Indexer (OpenSearch)**.

- **Index Name**: `lumu-incidents-1.x`
- **Ingestion Method**: **Native Upsert**. The system uses the incident UUID as the document ID. This ensures that:
    - New incidents are created as new documents.
    - Updated incidents (e.g., more endpoints infected or fresh contact timestamps) update the existing document rather than creating duplicates.
- **Data Format**: Rich JSON with `@timestamp` (ingestion time) and `last_contact` (event time) fields.

---

## Incident Data Model (`IncidentEvent`)

All raw data is normalized into the `IncidentEvent` model.

| Category | Field | Source | Description |
|---|---|---|---|
| **Identity** | `incident_uuid` | Defender API | Unique Lumu identifier. |
| | `title` | Defender API | Human-readable threat name. |
| **Status** | `severity` | Defender API | Threat level (Critical/High/Medium/Low). |
| | `status` | Defender API | Lifecycle status (open/closed). |
| **Timelines** | `first_contact` | Defender API | First recorded sighting. |
| | `last_contact` | Defender API | Most recent recorded sighting. |
| **Asset Context**| `endpoints_affected`| Defender API | Total count of impacted devices. |
| | `affected_endpoints`| Defender API | List of specific hostnames and IPs. |
| **Intelligence** | `mitre_techniques` | Context API | MITRE ATT&CK Tactic/Technique mapping. |
| | `stix_indicators` | STIX Bundle | Patterns and IOCs from the STIX bundle. |
| | `tlp` | STIX Bundle | Traffic Light Protocol level. |
| **Response** | `recommended_playbooks`| Context API | Suggested SOPs for remediation. |
| | `triggered_integrations`| Defender Details| Third-party tools already notified by Lumu. |
| **Metrics** | `dissemination_latency`| Internal | Time from Detection to Automated Response (MTTD). |
| | `mtt_response` | Internal | Time from Sighting to Automated Response. |
| | `mtt_resolution` | Internal | Time from Sighting to Closure. |
