# Development & Operations Guide

This guide describes how to deploy, configure, and troubleshoot the LumuIncidentHandler, with a focus on Docker-based operations and Wazuh Indexer integration.

## Docker Deployment (Recommended)

The application is containerized to ensure consistent operations. It uses a security-hardened Docker configuration.

### Prerequisites

- [Docker](https://docs.docker.com/get-docker/)
- [Docker Compose](https://docs.docker.com/compose/install/)

### Step 1: Configuration

1.  Copy `.env.example` to `.env`.
2.  Provide your Lumu credentials and Wazuh Indexer settings.

```bash
# Lumu Authentication
LUMU_EMAIL=your_user@example.com
LUMU_PASSWORD=your_password
LUMU_MSSP_UUID=your_mssp_uuid

# Lumu Defender API
LUMU_DEFENDER_KEY=your_defender_key
CUSTOMER_UUID=target_company_uuid
CUSTOMER_NAME="Target Company Name"

# Wazuh Indexer
INDEXER_URL=https://indexer.example.com:9200
INDEXER_USERNAME=admin
INDEXER_PASSWORD=your_indexer_password
```

### Step 2: Launch

Start the service in detached mode:

```bash
docker-compose up -d
```

### Security Features

The Docker deployment includes several security-hardening measures:
- **Read-Only Root**: The container's root filesystem is mounted as read-only.
- **Dropped Capabilities**: All non-essential kernel capabilities are dropped (`ALL`).
- **Non-Root User**: The application runs as a dedicated `monitor` user.
- **Volume Persistence**: Only the `/app/data` directory is writable, ensuring persistent state for the `sent_incidents.json` high-water mark file.
- **Secret Handling**: Sensitive credentials are managed via Pydantic's `SecretStr`, preventing them from being leaked in debug logs.

---

## Configuration Reference

| Variable | Default | Description |
|---|---|---|
| `LUMU_EMAIL` | - | Lumu MSSP Console email address. |
| `LUMU_PASSWORD` | - | Lumu MSSP Console password. |
| `LUMU_MSSP_UUID` | - | Unique UUID for the MSSP holding supervised companies. |
| `LUMU_DEFENDER_KEY` | - | Defender API Key for incident endpoints. |
| `CUSTOMER_UUID` | - | UUID of the specific tenant/company to monitor. |
| `POLLING_INTERVAL_MINUTES`| `5` | Frequency of Lumu polling in minutes. |
| `VERIFY_SSL` | `True` | Enable or disable SSL verification for all API clients. |
| `ALERT_STATE_FILE` | `data/sent_incidents.json` | Path to the high-water mark tracking file. |
| `INDEXER_URL` | - | The Wazuh Indexer (OpenSearch) endpoint. |
| `INDEXER_USERNAME` | `admin` | Wazuh Indexer authentication username. |
| `INDEXER_PASSWORD` | - | Wazuh Indexer authentication password. |

---

## Troubleshooting & Maintenance

### Logs
View the real-time execution logs from the container:

```bash
docker-compose logs -f
```

### State Management
The system tracks incident activity in `data/sent_incidents.json` using a **per-incident timestamp map**.

The state file schema:
```json
{
  "last_pulled_time": "2026-04-10T16:07:14Z",
  "incidents": {
    "365f7220-34f6-11f1-bbc7-8fba9bac8610": "2026-04-10T16:07:14Z"
  }
}
```

An incident is re-enriched and re-upserted to Wazuh if:
- Its UUID is **not in the `incidents` map** (new incident), or
- Its `lastContact` is **newer than the stored timestamp** for that UUID (updated incident).

This ensures that incident updates — new endpoints, additional firewall responses, status changes — are always reflected in the Wazuh Indexer.

To re-process all incidents from the last 30 days, clear the state file:
```bash
echo "{}" > data/sent_incidents.json
```

### Connectivity Checks
If incidents are not appearing in your dashboard:
1. **Wazuh Indexer**: Verify the container can reach `INDEXER_URL` (usually port 9200). Use `curl -k -u admin:password https://indexer:9200` from within the network.
2. **Index Check**: Ensure the index `lumu-incidents-1.x` exists or is discoverable in Opensearch Dashboards.
3. **Lumu API**: Confirm that `LUMU_DEFENDER_KEY` is valid and the incidents are visible in the Lumu Portal for the specific `CUSTOMER_UUID`.

## Development Setup (Local)

To run the application locally without Docker:

1.  Create a virtual environment: `python -m venv venv`.
2.  Activate it: `source venv/bin/activate` or `venv\Scripts\activate`.
3.  Install dependencies: `pip install -r requirements.txt`.
4.  Run the main loop: `python -m src.main`. (Note: use module syntax to respect internal imports).
