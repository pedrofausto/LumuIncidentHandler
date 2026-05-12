# Deployment Walkthrough: LumuIncidentHandler

This guide provides a step-by-step walkthrough for building and deploying the LumuIncidentHandler. It covers everything from credential setup to multi-container stack orchestration.

---

## 1. Prerequisites

Before starting, ensure you have the following:

- **Docker & Docker Compose**: Installed and running on your host machine.
- **Lumu Managed API Credentials**: Email and Password for an MSSP or Enterprise account.
- **Kafka Environment**: The provided Docker Compose stack includes a local Kafka broker and Confluent Control Center UI.

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
    - Tenant Defender keys are fetched dynamically per supervised customer at startup.

4.  **Configure Kafka**:
    - `KAFKA_BOOTSTRAP_SERVERS`: For local host usage, `localhost:9092`.
    - `KAFKA_CLIENT_ID`: Defaults to `lumu-incident-handler`.
    - Topic is computed per tenant as `cli-<normalized_customer_name>`.

5.  **Set SSL Policy**:
    - `VERIFY_SSL=False`: Recommended for SSL-intercepted corporate networks and self-signed local environments.
    - `VERIFY_SSL=True`: Enable only when your environment presents a trusted certificate chain.

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

### Mode A: Full Stack Deployment (Includes Kafka + Control Center)
If you want to deploy the full local development stack (Kafka, Control Center, and the Handler), use the provided `docker-compose.yml`:

```bash
docker-compose up -d
```

> [!NOTE]
> The full stack deployment includes pre-configured SSL certificates and volume persistence for indices.

### Mode B: Standalone Handler Deployment
If you already have a Kafka cluster running, you only need to deploy the handler service.

1. Ensure your `.env` points to your external `KAFKA_BOOTSTRAP_SERVERS`.
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

### Verify Ingestion in Kafka
1. Open Confluent Control Center at `http://localhost:9021`.
2. Select the local cluster and open tenant topics like `cli-grupoamil`.
3. Confirm each record value contains a `message` field with stringified incident JSON.

---

## 6. Troubleshooting

| Issue | Potential Cause | Fix |
|---|---|---|
| `SSL: CERTIFICATE_VERIFY_FAILED` | Internal certs but `VERIFY_SSL=True` | Set `VERIFY_SSL=False` in `.env` |
| `401 Unauthorized` | Invalid Lumu Credentials | Double-check `.env` for typos in email/pass |
| `Connection Refused (9092)` | Kafka not reachable | Check if the `kafka` container is healthy |
| No incidents found | High-water mark logic | Check `data/sent_incidents.json`. Clear it to force a full re-scan. |
