# Lumu API & Data Integrations

LumuIncidentHandler acts as an intelligent bridge between the Lumu platform and incident response teams. It integrates multiple Lumu APIs and data formats to build rich context for every alert.

## Lumu API Integration

The system communicates with two distinct Lumu API surfaces: the Managed API and the Defender API. Both are accessed over HTTPS using a shared authentication session.

### Authentication (Managed API)

- **Endpoint**: `/api/msp/users/sign_in`
- **Method**: POST (with username and password)
- **Mechanism**: The system exchanges credentials for a JWT Bearer token.
- **Session Management**: Tokens are cached in memory and automatically refreshed if the API returns a `401 Unauthorized` status.

### Incident Discovery (Defender API)

- **Endpoints**:
    - `/api/incidents/all` (to fetch a list of open and closed incidents)
    - `/api/incidents/{uuid}/details` (to fetch endpoint and contact details)
- **Time Window**: The system enforces a sliding 30-day window for queries to comply with Lumu's API constraints and ensure performance.

### Intelligence Enrichment (Managed API)

- **Endpoint**: `/intelligence/stix/bundles/{incident_uuid}`
- **Format**: STIX 2.1 JSON Bundle
- **Data Enrichment**: Raw incidents are augmented with intelligence objects, including:
    - **Malware**: Threat actor identification and malware families.
    - **Indicators**: Specific indicators of compromise (IOCs) associated with the threat.
    - **Sightings**: Temporal and spatial data on where and when the threat was seen.
    - **TLP Markings**: Traffic Light Protocol data for information sharing compliance.

## Incident Data Model (`IncidentEvent`)

All raw data is normalized into a standard `IncidentEvent` model by the `Analyzer`. This model serves as the single source of truth for the notification templates.

| Field | Source | Description |
|---|---|---|
| `uuid` | Defender API | Unique identifier for the incident. |
| `threat_name` | Defender API | The name of the detected threat. |
| `malware_name` | STIX Bundle | Specific malware family name if available. |
| `description` | STIX Bundle | Detailed description of the threat actor or technique. |
| `first_seen` | Defender API | Initial timestamp of detection. |
| `last_seen` | Defender API | Most recent timestamp of detection. |
| `endpoints` | Defender API | List of impacted endpoints and associated contact data. |
| `intelligence` | STIX Bundle | Associated indicators, TLP levels, and threat mappings. |

## External Notifications (SMTP)

The `Notifier` component uses standard SMTP protocols for delivery.

- **Protocols**: Supports `STARTTLS` (port 587) and `SSL/TLS` (port 465).
- **Format**: Rich HTML emails rendered from Jinja2 templates.
- **Attachments**: The system supports attaching the raw STIX JSON bundle for integration with other SOC tools or further manual analysis.
