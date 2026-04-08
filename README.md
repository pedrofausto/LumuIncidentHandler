# LumuIncidentHandler

An automated monitor and alert system for the Lumu security platform. It polls for new incidents, enriches them with STIX 2.1 threat intelligence, and forwards them to Wazuh for centralized security monitoring.

## Features

- **Automated Polling**: Regularly checks for new incidents across multiple tenants.
- **Rich Enrichment**: Merges raw incident data with STIX 2.1 objects (Indicators, Malware, Sightings).
- **Intelligent Deduplication**: Uses a local JSON-based state file to ensure alerts are sent only once.
- **Wazuh Integration**: Forwards enriched incident data as JSON to a Wazuh Manager for alerting and analysis.
- **Docker-First Deployment**: Hardened Docker configuration with non-root user and persistent data volume.

## Quick Start (Docker)

1.  **Configure**: Copy `.env.example` to `.env` and fill in your Lumu and Wazuh credentials.
2.  **Launch**: `docker-compose up -d`.

## Documentation

Comprehensive documentation is available in the `docs/` directory:

- [Architecture](./docs/architecture.md): System design and component diagrams.
- [Workflows](./docs/workflows.md): Operational logic and request/response flows.
- [Integrations](./docs/integrations.md): Lumu and Wazuh API details and data models.
- [Development & Operations](./docs/development.md): Setup, configuration, and maintenance guide.

## License

This project is licensed under the terms provided in the `constitution.md` file.
