# Development & Operations Guide

This guide describes how to deploy, configure, and troubleshoot the LumuIncidentHandler, with a focus on Docker-based operations.

## Docker Deployment (Recommended)

The application is containerized for consistent deployment across environments. It uses a security-hardened Docker configuration.

### Prerequisites

- [Docker](https://docs.docker.com/get-docker/)
- [Docker Compose](https://docs.docker.com/compose/install/)

### Step 1: Configuration

1.  Copy `.env.example` to `.env`.
2.  Provide your Lumu credentials and SMTP settings.

```bash
# Lumu Credentials
LUMU_USER=your_user
LUMU_PASS=your_password

# SMTP Settings
SMTP_SERVER=smtp.example.com
SMTP_PORT=587
SMTP_USER=user@example.com
SMTP_PASS=password
NOTIFICATION_EMAIL=alerts@example.com
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
- **Volume Persistence**: Only the `/app/data` directory is writable, ensuring persistent state for the `alerts.json` deduplication file.

## Configuration Reference

| Variable | Default | Description |
|---|---|---|
| `LUMU_USER` | - | Lumu Managed API username. |
| `LUMU_PASS` | - | Lumu Managed API password. |
| `POLLING_INTERVAL` | `300` | Frequency (in seconds) to check for new incidents. |
| `SMTP_SERVER` | - | Outgoing mail server address. |
| `SMTP_PORT` | `587` | Outgoing mail server port (usually 587 or 465). |
| `SMTP_USE_TLS` | `True` | Enable STARTTLS (standard for port 587). |
| `SMTP_USE_SSL` | `False` | Enable SSL/TLS (standard for port 465). |
| `DATA_PATH` | `data/alerts.json` | Path to the local state file for deduplication. |

## Troubleshooting & Maintenance

### Logs
View the real-time execution logs from the container:

```bash
docker-compose logs -f
```

### State Management
The system tracks notified incidents in `data/alerts.json`. If you need to re-send all alerts (e.g., after a template change), simply clear this file:

```bash
echo "[]" > data/alerts.json
```

### Connectivity Checks
If the system is not sending alerts:
1. Verify the container can resolve the SMTP and Lumu API hosts.
2. Ensure the `.env` file does not have trailing spaces or special characters in the passwords.
3. Check the Lumu portal to confirm that new incidents have actually been generated within the last 30 days.

## Development Setup (Local)

To run the application locally without Docker:

1.  Create a virtual environment: `python -m venv venv`.
2.  Activate it: `source venv/bin/activate` (Linux/macOS) or `venv\Scripts\activate` (Windows).
3.  Install dependencies: `pip install -r requirements.txt`.
4.  Run the main loop: `python src/main.py`.
