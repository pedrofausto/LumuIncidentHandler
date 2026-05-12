import asyncio
import logging
import sys
import dataclasses
import socket
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, List
from .config import get_settings
from .lumu_client import LumuSession
from .analyzer import Analyzer
from .kafka_client import KafkaClient

logging.basicConfig(
    stream=sys.stdout,
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logging.getLogger("httpx").setLevel(logging.WARNING)
logger = logging.getLogger("lumu_monitor")

MOVED_LUMU_FIELDS = {
    "incident_uuid",
    "title",
    "adversary_id",
    "adversary_type",
    "customer_uuid",
    "customer_name",
    "endpoints_affected",
    "affected_endpoints",
    "status",
    "event_type",
}


def get_agent_id() -> str:
    data_dir = Path(__file__).resolve().parent.parent / "data"
    data_dir.mkdir(parents=True, exist_ok=True)
    agent_id_file = data_dir / "agent_id"

    if agent_id_file.exists():
        existing = agent_id_file.read_text(encoding="utf-8").strip()
        if existing:
            return existing

    generated = str(uuid.uuid4())
    agent_id_file.write_text(generated, encoding="utf-8")
    return generated


def get_primary_host_ip() -> str:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect(("8.8.8.8", 80))
        return sock.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        sock.close()


def severity_to_rule_level(severity: str | None) -> str:
    severity_map = {
        "low": "3",
        "medium": "8",
        "high": "16",
    }
    return severity_map.get(str(severity or "").strip().lower(), "8")


def _shape_affected_endpoint(endpoint: Dict[str, Any]) -> Dict[str, Any]:
    srchost = endpoint.get("name") or endpoint.get("srchost") or endpoint.get("srcip") or ""
    srcip = endpoint.get("srcip") or ""
    shaped = {
        "srchost": srchost,
        "srcip": srcip,
    }
    if endpoint.get("first_contact"):
        shaped["first_contact"] = endpoint["first_contact"]
    if endpoint.get("last_contact"):
        shaped["last_contact"] = endpoint["last_contact"]
    return shaped


def shape_kafka_payload(
    event_dict: Dict[str, Any],
    tenant_uuid: str,
    tenant_name: str,
    settings,
    hostname: str,
    agent_id: str,
    agent_ip: str,
) -> Dict[str, Any]:
    payload = {
        key: value
        for key, value in event_dict.items()
        if key not in MOVED_LUMU_FIELDS and key not in {"integration", "severity"}
    }

    affected_endpoints = event_dict.get("affected_endpoints") or []
    payload["lumu"] = {
        "id": event_dict.get("incident_uuid", ""),
        "adversaries": event_dict.get("title", ""),
        "adversary_id": event_dict.get("adversary_id", ""),
        "adversary_types": event_dict.get("adversary_type", ""),
        "company_id": event_dict.get("customer_uuid") or tenant_uuid,
        "customer_name": event_dict.get("customer_name") or tenant_name,
        "endpoints_affected": event_dict.get("endpoints_affected", 0),
        "affected_endpoints": [
            _shape_affected_endpoint(endpoint)
            for endpoint in affected_endpoints
            if isinstance(endpoint, dict)
        ],
        "status": event_dict.get("status", ""),
        "event_type": event_dict.get("event_type") or "NewIncidentCreated",
    }
    payload["agent"] = {
        "name": hostname,
        "id": agent_id,
        "ip": agent_ip,
    }
    payload["rule"] = {
        "level": severity_to_rule_level(event_dict.get("severity")),
        "id": "0000",
        "groups": ["lumu"],
        "description": "Lumu integration Rule",
    }
    payload["decoder"] = {
        "name": "int-dec-lumu",
    }
    payload["manager"] = {
        "name": hostname,
    }
    payload["product_name"] = "Lumu Defender"
    payload["timezone"] = settings.payload_timezone
    return payload


async def _safe_enrichment(label: str, incident_uuid: str, operation, default):
    try:
        return await operation
    except Exception as exc:
        logger.debug("%s enrichment failed for incident %s: %s", label, incident_uuid, exc)
        return default

async def enrich_incident(client: LumuSession, tenant_uuid: str, company_key: str, inc_uuid: str, is_bootstrap_mode: bool = False) -> Dict[str, Any]:
    """
    Fetches STIX, details, contacts, summary context, and external-articles context for a single incident.
    """
    try:
        details_task = client.get_incident_details(company_key, inc_uuid)
        contacts_task = client.get_incident_contacts(company_key, inc_uuid)
        stix_task = client.get_incident_stix(tenant_uuid, inc_uuid)
        summary_task = client.get_incident_context_summary(tenant_uuid, inc_uuid)
        
        # External Articles are the heaviest/slowest, we only skip THESE in bootstrap mode
        articles_task = None
        if not is_bootstrap_mode:
            articles_task = client.get_incident_external_articles(tenant_uuid, inc_uuid)
        
        # Batch fetching with small delays to respect rate limits
        stix = await _safe_enrichment("STIX", inc_uuid, stix_task, {})
        await asyncio.sleep(0.5)
        details = await _safe_enrichment("details", inc_uuid, details_task, {})
        await asyncio.sleep(0.5)
        contacts = await _safe_enrichment("contacts", inc_uuid, contacts_task, [])
        await asyncio.sleep(0.5)
        summary = await _safe_enrichment("summary", inc_uuid, summary_task, {})
        
        articles = []
        if articles_task:
            await asyncio.sleep(0.5)
            articles = await _safe_enrichment("external articles", inc_uuid, articles_task, [])
        
        # Gracefully handle exceptions when specific APIs return 404 or fail
        return {
            'uuid': inc_uuid, 
            'stix': stix if not isinstance(stix, Exception) else {}, 
            'details': details if not isinstance(details, Exception) else {},
            'contacts': contacts if not isinstance(contacts, Exception) else [],
            'summary': summary if not isinstance(summary, Exception) else {},
            'articles': articles if not isinstance(articles, Exception) else []
        }
    except Exception as e:
        logger.debug(f"Intelligence enrichment failed for incident {inc_uuid}: {e}")
        return {'uuid': inc_uuid, 'stix': {}, 'details': {}, 'contacts': [], 'summary': {}, 'articles': []}

async def monitor_tenant(client: LumuSession, analyzer: Analyzer, kafka: KafkaClient, tenant_uuid: str, tenant_name: str, company_key: str):
    """
    Monitors a single tenant for security incidents using a Hybrid Strategy:
    1. State Sync: Fetch all currently OPEN incidents.
    2. Incremental Sync: Fetch journal UPDATES via offset.
    """
    logger.info(f"Scanning security incidents for tenant '{tenant_name}' ({tenant_uuid})...")
    publish_success_count = 0
    publish_failure_count = 0
    try:
        if not company_key:
            logger.warning(f"LUMU_DEFENDER_KEY is not set. Skipping incident scan.")
            return

        # --- 1. State Sync: Fetch and process recently OPEN incidents ---
        logger.info(f"Initializing State Sync for open incidents (since {analyzer.last_pulled_time})...")
        open_incidents = await client.get_open_incidents(company_key, from_date=analyzer.last_pulled_time)
        
        # Filter to only enriched those that actually changed
        to_enrich_state = [inc for inc in open_incidents if analyzer.should_process_incident(inc)]
        
        if to_enrich_state:
            logger.info(f"Detected {len(to_enrich_state)} new or updated open incident(s) in state sync.")
            # Reuse the enrichment and sending logic
            success, failed = await process_and_send_batch(
                client, analyzer, kafka,
                raw_incidents=to_enrich_state, 
                tenant_uuid=tenant_uuid, 
                tenant_name=tenant_name, 
                company_key=company_key,
                is_bootstrap_mode=False # State sync is usually light enough
            )
            publish_success_count += success
            publish_failure_count += failed
        else:
            logger.info("Universal state sync: All open incidents are already up-to-date.")

        # --- 2. Incremental Sync: Process Update Journal via Offset ---
        items_per_page = 50
        while True:
            pre_batch_hits = client.rate_limit_hits
            updates_data = await client.get_incident_updates(company_key, offset=analyzer.offset, items=items_per_page)
            updates_list = updates_data.get("updates", [])
            new_offset = updates_data.get("offset")
            
            if not updates_list:
                logger.info(f"No new incident journal updates for tenant '{tenant_name}'.")
                if new_offset is not None:
                    analyzer.offset = new_offset
                    analyzer._save_state()
                break

            logger.info(f"Retrieved {len(updates_list)} journal update event(s). Processing...")
            
            # Detect Bootstrap / Backlog mode
            is_bootstrap_mode = len(updates_list) >= items_per_page
            if is_bootstrap_mode:
                logger.debug(f"High backlog detected (>= {items_per_page} updates). Deep enrichments will be skipped.")

            raw_incidents = analyzer.extract_incidents_from_updates(updates_list)

            if raw_incidents:
                success, failed = await process_and_send_batch(
                    client, analyzer, kafka,
                    raw_incidents, 
                    tenant_uuid, 
                    tenant_name, 
                    company_key, 
                    is_bootstrap_mode=is_bootstrap_mode
                )
                publish_success_count += success
                publish_failure_count += failed
            else:
                logger.info("No incident-related updates in this journal batch.")

            # Advance Offset and Persist State
            analyzer.offset = new_offset
            analyzer._save_state()
            
            # 5. Evaluate AIMD for next batch
            post_batch_hits = client.rate_limit_hits
            if post_batch_hits > pre_batch_hits:
                items_per_page = max(5, int(items_per_page / 2))
                logger.warning(f"Rate-limit pressure detected. Shrinking batch size to {items_per_page}.")
            else:
                items_per_page = min(50, items_per_page + 5)
            
            if len(updates_list) < items_per_page:
                break

    except Exception as e:
        logger.error(f"Error processing incidents for tenant {tenant_uuid}: {str(e)}")
    finally:
        logger.info(
            "Cycle publish summary tenant=%s success=%s failed=%s",
            tenant_uuid,
            publish_success_count,
            publish_failure_count,
        )

async def process_and_send_batch(
    client: LumuSession, 
    analyzer: Analyzer, 
    kafka: KafkaClient,
    raw_incidents: List[Dict[str, Any]], 
    tenant_uuid: str, 
    tenant_name: str, 
    company_key: str,
    is_bootstrap_mode: bool = False
)-> tuple[int, int]:
    """
    Enriches raw incidents and streams them to Kafka as they complete.
    """
    settings = get_settings()
    hostname = socket.gethostname()
    agent_id = get_agent_id()
    agent_ip = get_primary_host_ip()

    # 1. Map UUIDs to raw objects for reconstruction after streaming
    uuid_to_raw = {}
    for inc in raw_incidents:
        uid = inc.get('uuid') or inc.get('id')
        if uid:
            uuid_to_raw[uid] = inc

    if not uuid_to_raw:
        return (0, 0)

    # 2. Enrichment with Semaphore
    semaphore = asyncio.Semaphore(2)
    
    async def sem_enrich(inc_uuid):
        async with semaphore:
            result = await enrich_incident(client, tenant_uuid, company_key, inc_uuid, is_bootstrap_mode)
            await asyncio.sleep(1.0)
            return result

    unique_uuids = list(uuid_to_raw.keys())
    tasks = [sem_enrich(uuid) for uuid in unique_uuids]
    
    # 3. Stream Results: Process each as it completes
    logger.info(f"Enriching and streaming {len(unique_uuids)} incident(s) for '{tenant_name}'...")
    success_count = 0
    failure_count = 0
    
    for finished_task in asyncio.as_completed(tasks):
        try:
            res = await finished_task
            inc_uuid = res.get('uuid')
            raw_inc = uuid_to_raw.get(inc_uuid)
            
            if not raw_inc:
                continue

            # Map the single incident
            mapped_events = analyzer.evaluate_incidents(
                [raw_inc],
                stix_data_map={inc_uuid: res['stix']},
                details_map={inc_uuid: res['details']},
                contacts_map={inc_uuid: res.get('contacts', [])},
                summary_map={inc_uuid: res['summary']},
                articles_map={inc_uuid: res['articles']}
            )

            # Send to Kafka
            for event in mapped_events:
                try:
                    event_dict = dataclasses.asdict(event)
                    event_dict["@timestamp"] = datetime.now(timezone.utc).isoformat()
                    event_dict["customer_name"] = tenant_name
                    event_dict["customer_uuid"] = tenant_uuid
                    event_dict = shape_kafka_payload(
                        event_dict=event_dict,
                        tenant_uuid=tenant_uuid,
                        tenant_name=tenant_name,
                        settings=settings,
                        hostname=hostname,
                        agent_id=agent_id,
                        agent_ip=agent_ip,
                    )
                    
                    await kafka.send_incident(event_dict)
                    success_count += 1
                    logger.info(
                        "Incident publish success incident_uuid=%s topic=%s",
                        event.incident_uuid,
                        settings.kafka_topic,
                    )
                    
                    # Update state immediately
                    analyzer.update_incident_time(event.incident_uuid, event.last_contact)
                except Exception as e:
                    failure_count += 1
                    logger.error(
                        "Failed to send incident incident_uuid=%s topic=%s reason=%s delivery_timeout=%ss",
                        event.incident_uuid,
                        settings.kafka_topic,
                        e,
                        settings.kafka_delivery_timeout_seconds,
                    )

        except Exception as e:
            logger.error(f"Streaming error for an incident task: {e}")
            failure_count += 1
    return (success_count, failure_count)

async def run_loop():
    settings = get_settings()
    interval_seconds = settings.polling_interval_minutes * 60

    logger.info(f"Lumu Incident Handler started.")
    logger.info(f"Monitoring customer: '{settings.customer_name}' ({settings.customer_uuid})")
    logger.info(
        "Kafka runtime config bootstrap=%s topic=%s delivery_timeout=%ss flush_timeout=%ss",
        settings.kafka_bootstrap_servers,
        settings.kafka_topic,
        settings.kafka_delivery_timeout_seconds,
        settings.kafka_flush_timeout_seconds,
    )

    try:
        async with LumuSession() as client, KafkaClient() as kafka:
            analyzer = Analyzer()
            await client.authenticate()

            while True:
                logger.info("--- Starting Incident Polling Cycle ---")
                try:
                    await monitor_tenant(
                        client=client,
                        analyzer=analyzer,
                        kafka=kafka,
                        tenant_uuid=settings.customer_uuid,
                        tenant_name=settings.customer_name,
                        company_key=settings.lumu_defender_key.get_secret_value() if settings.lumu_defender_key else None,
                    )
                except Exception as e:
                    logger.error(f"Critical error during polling cycle: {str(e)}")

                logger.info(f"Cycle complete. Waiting {settings.polling_interval_minutes} minutes for next check.")
                await asyncio.sleep(interval_seconds)

    except asyncio.CancelledError:
        logger.info("Monitor interrupted. Shutting down gracefully...")



if __name__ == "__main__":
    try:
        asyncio.run(run_loop())
    except KeyboardInterrupt:
        pass
