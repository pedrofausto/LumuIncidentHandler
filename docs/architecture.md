# LumuIncidentHandler Architecture

The LumuIncidentHandler is a polling-based security monitor designed to identify, enrich, and alert on security incidents from the Lumu platform. It automates the extraction of incident data, correlates it with STIX 2.1 threat intelligence, and notifies relevant stakeholders via rich HTML emails.

## System Architecture

The application is structured into four main functional blocks: Orchestration, API Integration, Analysis, and Notification.

### Component Diagram (ASCII)

```text
+-------------------------------------------------------------+
|                     LumuIncidentHandler                     |
|                                                             |
|   +--------------+       +--------------+      +---------+  |
|   |   Main Loop  |------>|  LumuClient  |----->| Lumu API|  |
|   | (Async Poll) |<------| (JWT/STIX)   |<-----| (HTTPS) |  |
|   +-------+------+       +--------------+      +---------+  |
|           |                                                 |
|           v                                                 |
|   +--------------+       +--------------+      +---------+  |
|   |   Analyzer   |------>| Local State  |      |   SMTP  |  |
|   | (Enrichment) |       | (alerts.json)|      |  Server |  |
|   +-------+------+       +--------------+      +----+----+  |
|           |                                         ^       |
|           v                                         |       |
|   +--------------+                                  |       |
|   |   Notifier   |----------------------------------+       |
|   | (Jinja2/HTML)|                                           |
|   +--------------+                                           |
+-------------------------------------------------------------+
```

## Core Components

### 1. Orchestrator (`src/main.py`)
The `main.py` script serves as the entry point, running an asynchronous polling loop. It manages the execution interval and coordinates the data flow between the other components.

### 2. Lumu Client (`src/lumu_client.py`)
Handles all external communication with Lumu APIs. It manages JWT authentication sessions, handles token refreshes, and implements time-based pagination for incident retrieval. It interacts with both the **Defender API** (for incidents) and the **Managed API** (for STIX intelligence).

### 3. Analyzer (`src/analyzer.py`)
The logic engine of the application. It performs several critical tasks:
- **Filtering**: Identifies "new" incidents that haven't been alerted yet.
- **Enrichment**: Merges raw incident data with rich STIX objects (Malware, Indicators, Sightings).
- **State Management**: Maintains `data/alerts.json` to ensure deduplication.

### 4. Notifier (`src/notifier.py`)
Constructs and dispatches alerts. It uses Jinja2 to render HTML templates (located in `templates/`) with the enriched incident data and sends them via an SMTP server, supporting secure connections (STARTTLS/SSL).
