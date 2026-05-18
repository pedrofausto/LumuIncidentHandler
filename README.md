# LumuIncidentHandler

An automated monitor and alert system for the Lumu security platform. It polls for new incidents, enriches them with STIX 2.1 threat intelligence, and publishes them to Kafka for centralized downstream processing.

## Features

- **Automated Polling**: Regularly checks for new incidents across multiple tenants.
- **Rich Enrichment**: Merges raw incident data with STIX 2.1 objects (Indicators, Malware, Sightings) and managed activity endpoint/user context.
- **Explicit Pipeline Stages**: Separates source fetching, incident building, payload serialization, and state tracking into dedicated modules.
- **Journal-First Polling**: Uses the Defender journal as the hot path and schedules full open-state reconciliation instead of sweeping `/api/incidents/all` every cycle.
- **Tenant Scheduler Smoothing**: Applies per-tenant cycle jitter and a global tenant concurrency cap to reduce synchronized Defender API bursts.
- **Defender Budget Governance**: Enforces conservative per-tenant Defender budgets with minute/day windows, request gating, and endpoint capability fallback for `max-items`.
- **Tenant-Isolated Cooldowns**: Applies Defender cooldown/counter keys as `endpoint:tenant`, preventing one tenant's throttle state from affecting others.
- **Structured Cooldown Degrade**: Uses typed cooldown exceptions for non-blocking partial enrichment instead of long blocking waits.
- **Per-Tenant Enrichment Pacing**: Limits details/contacts concurrency per tenant by policy profile.
- **Rate Policy Profiles**: Uses high-level profiles (`strict`, `balanced`, `aggressive`) to keep `.env` simple while preserving safe defaults.
- **Intelligent Deduplication**: Uses a local JSON-based state file to ensure alerts are sent only once.
- **Kafka Integration**: Publishes enriched incident payloads to Kafka using the official Confluent Python client.
- **Structured Payloads**: Emits Lumu fields under `data.lumu`, endpoint host/IP pairs as `srchost`/`srcip`, and stable handler identity via `agent.id` plus detected `agent.ip`.
- **Bounded Delivery Acks**: Waits for per-message Kafka delivery confirmation with an explicit timeout, preventing handler stalls.
- **Confluent Control Center UI**: Includes an official Kafka UI service for local message inspection.
- **Docker-First Deployment**: Hardened Docker configuration with non-root user and persistent data volume.

## Quick Start (Docker)

1.  **Configure**: Copy `.env.example` to `.env` and fill in your Lumu and Kafka settings.
2.  **Launch**: `docker-compose up -d`.
3.  **Inspect**: Open `http://localhost:9021` in Confluent Control Center and review tenant topics such as `cli-grupoamil`.

## Documentation

Comprehensive documentation is available in the `docs/` directory:

- [Architecture](./docs/architecture.md): System design and component diagrams.
- [Workflows](./docs/workflows.md): Operational logic and request/response flows.
- [Integrations](./docs/integrations.md): Lumu APIs, Kafka delivery, and data model details.
- [Development & Operations](./docs/development.md): Setup, configuration, and maintenance guide.

## License

This project is licensed under the terms provided in the `constitution.md` file.
