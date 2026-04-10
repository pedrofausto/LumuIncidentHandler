# Deployment Walkthrough: LumuIncidentHandler

This guide provides a step-by-step walkthrough for building and deploying the LumuIncidentHandler. It covers everything from credential setup to multi-container stack orchestration.

---

## 1. Prerequisites

Before starting, ensure you have the following:

- **Docker & Docker Compose**: Installed and running on your host machine.
- **Lumu Managed API Credentials**: Email and Password for an MSSP or Enterprise account.
- **Lumu Defender API Key**: Obtained from the Lumu Portal under the "Integrations" or "Defender API" section.
- **Wazuh/OpenSearch Environment**: Either a standalone instance or the ability to run the provided Docker Compose stack.

---

## 2. Environment Configuration

The application uses an `.env` file for all runtime configurations.

1.  **Clone the repository** and navigate to the project root.
2.  **Create your environment file**:
    ```bash
    cp .env.example .env
    ```
3.  **Configure Lumu Credentials**:
    - `LUMU_EMAIL`: Your Lumu login email.
    - `LUMU_PASSWORD`: Your Lumu login password.
    - `LUMU_MSSP_UUID`: The UUID of your MSSP (visible in the URL or profile).
    - `LUMU_DEFENDER_KEY`: The API key for the company being monitored.
    - `CUSTOMER_UUID`: The specific UUID of the company to monitor.

4.  **Configure Wazuh/Indexer**:
    - `INDEXER_URL`: The full URL (e.g., `https://wazuh.indexer:9200`).
    - `INDEXER_USERNAME`: Usually `admin`.
    - `INDEXER_PASSWORD`: The password for your indexer user.

5.  **Set SSL Policy**:
    - `VERIFY_SSL=True`: **Recommended for Production.** Requires a valid certificate chain.
    - `VERIFY_SSL=False`: Use this if connecting to a local instance with self-signed certificates.

---

## 3. Building the Container

The application is optimized for containerized execution using a security-hardened `python:3.12-slim` base image.

To build the image manually:
```bash
docker build -t lumu-incident-handler .
```

Alternatively, `docker-compose` will handle the build automatically during the first run.

---

## 4. Deployment Modes

### Mode A: Full Stack Deployment (Includes Wazuh)
If you want to deploy the entire stack (Wazuh Manager, Indexer, Dashboard, and the Handler), use the provided `docker-compose.yml`:

```bash
docker-compose up -d
```

> [!NOTE]
> The full stack deployment includes pre-configured SSL certificates and volume persistence for indices.

### Mode B: Standalone Handler Deployment
If you already have a Wazuh/OpenSearch cluster running, you only need to deploy the handler service. 

1. Ensure your `.env` points to your external `INDEXER_URL`.
2. run:
```bash
docker-compose up -d lumu-incident-handler
```

---

## 5. Verification

Once deployed, verify that the system is functioning correctly:

### Check Handler Logs
```bash
docker logs -f lumu-incident-handler
```
You should see messages indicating successful authentication and the start of the "Incident Polling Cycle".

### Verify Ingestion in Wazuh
1. Log in to your Wazuh Dashboard / OpenSearch Dashboards.
2. Navigate to **Dev Tools** and query the index:
   ```http
   GET /lumu-incidents-1.x/_search
   ```
3. Confirm that documents are appearing with `@timestamp` and `incident_uuid` fields.

---

## 6. Troubleshooting

| Issue | Potential Cause | Fix |
|---|---|---|
| `SSL: CERTIFICATE_VERIFY_FAILED` | Internal certs but `VERIFY_SSL=True` | Set `VERIFY_SSL=False` in `.env` |
| `401 Unauthorized` | Invalid Lumu Credentials | Double-check `.env` for typos in email/pass |
| `Connection Refused (9200)` | Indexer not reachable | Check if the `wazuh.indexer` container is healthy |
| No incidents found | High-water mark logic | Check `data/sent_incidents.json`. Clear it to force a full re-scan. |
