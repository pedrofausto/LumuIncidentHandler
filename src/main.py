import asyncio
import logging
import sys
import dataclasses
import re
import socket
import uuid
from pathlib import Path
from typing import Dict, Any, List, Optional
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
    "details",
    "mitre_techniques",
    "recommended_playbooks",
    "intelligence_tags",
    "intelligence_articles",
    "disseminated",
    "dissemination_time",
    "dissemination_latency",
    "mtt_response",
    "mtt_resolution",
    "triggered_integrations",
    "tlp",
    "related_artifacts",
    "extracted_iocs",
    "stix_indicators",
    "stix_malware",
    "stix_sighting",
}


@dataclasses.dataclass
class TenantRuntime:
    tenant_uuid: str
    tenant_name: str
    defender_api_key: str
    kafka_topic: str


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


def normalize_customer_topic(customer_name: str) -> str:
    normalized = re.sub(r"[^a-z0-9]", "", (customer_name or "").lower())
    return f"cli-{normalized}" if normalized else ""


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
    payload["data"] = {
        "lumu": {
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
            "event_type": (
                "test"
                if settings.event_type_test_mode
                else (event_dict.get("event_type") or "NewIncidentCreated")
            ),
            "details": event_dict.get("details", ""),
            "mitre_techniques": event_dict.get("mitre_techniques", []),
            "related_artifacts": event_dict.get("related_artifacts", {}),
            "recommended_playbooks": event_dict.get("recommended_playbooks", []),
            "intelligence_tags": event_dict.get("intelligence_tags", []),
            "intelligence_articles": event_dict.get("intelligence_articles", []),
            "extracted_iocs": event_dict.get("extracted_iocs", []),
            "disseminated": event_dict.get("disseminated", False),
            "dissemination_time": event_dict.get("dissemination_time"),
            "dissemination_latency": event_dict.get("dissemination_latency"),
            "mtt_response": event_dict.get("mtt_response"),
            "mtt_resolution": event_dict.get("mtt_resolution"),
            "triggered_integrations": event_dict.get("triggered_integrations", []),
            "tlp": event_dict.get("tlp", "TLP: RED"),
            "stix_indicators": event_dict.get("stix_indicators", []),
            "stix_malware": event_dict.get("stix_malware", []),
            "stix_sighting": event_dict.get("stix_sighting"),
        }
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
        "description": "Lumu integration rule",
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
        logger.warning("%s enrichment failed for incident %s: %s", label, incident_uuid, exc)
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

async def monitor_tenant(
    client: LumuSession,
    analyzer: Analyzer,
    kafka: KafkaClient,
    tenant_uuid: str,
    tenant_name: str,
    company_key: str,
    kafka_topic: str,
):
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
                kafka_topic=kafka_topic,
                is_bootstrap_mode=False # State sync is usually light enough
            )
            publish_success_count += success
            publish_failure_count += failed
        else:
            logger.info("Universal state sync: All open incidents are already up-to-date.")

        # --- 2. Incremental Sync: Process Update Journal via Offset ---
        items_per_page = 50
        while True:
            previous_offset = analyzer.offset
            pre_batch_hits = client.rate_limit_hits
            updates_data = await client.get_incident_updates(company_key, offset=analyzer.offset, items=items_per_page)
            updates_list = updates_data.get("updates", [])
            new_offset = updates_data.get("offset")
            
            if not updates_list:
                logger.info(f"No new incident journal updates for tenant '{tenant_name}'.")
                if new_offset is not None:
                    analyzer.offset = new_offset
                    analyzer._save_state()
                else:
                    logger.warning(
                        "Journal updates returned no offset tenant=%s previous_offset=%s; stopping cycle",
                        tenant_uuid,
                        previous_offset,
                    )
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
                    kafka_topic,
                    is_bootstrap_mode=is_bootstrap_mode
                )
                publish_success_count += success
                publish_failure_count += failed
            else:
                logger.info("No incident-related updates in this journal batch.")

            # Advance Offset and Persist State
            if new_offset is None:
                logger.warning(
                    "Journal updates returned null offset tenant=%s previous_offset=%s; stopping cycle",
                    tenant_uuid,
                    previous_offset,
                )
                break
            if new_offset == previous_offset:
                logger.warning(
                    "Journal offset did not advance tenant=%s offset=%s; stopping cycle to prevent infinite loop",
                    tenant_uuid,
                    previous_offset,
                )
                break

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
    kafka_topic: str,
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
                    
                    await kafka.send_incident(event_dict, topic=kafka_topic)
                    success_count += 1
                    logger.info(
                        "Incident publish success tenant_uuid=%s tenant_name=%s incident_uuid=%s topic=%s",
                        tenant_uuid,
                        tenant_name,
                        event.incident_uuid,
                        kafka_topic,
                    )
                    
                    # Update state immediately
                    analyzer.update_incident_time(event.incident_uuid, event.last_contact)
                except Exception as e:
                    failure_count += 1
                    logger.error(
                        "Failed to send incident incident_uuid=%s topic=%s reason=%s delivery_timeout=%ss",
                        event.incident_uuid,
                        kafka_topic,
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
    analyzers_by_tenant: Dict[str, Analyzer] = {}
    tenant_registry: Dict[str, TenantRuntime] = {}

    logger.info(f"Lumu Incident Handler started.")
    logger.info(
        "Kafka runtime config bootstrap=%s delivery_timeout=%ss flush_timeout=%ss",
        settings.kafka_bootstrap_servers,
        settings.kafka_delivery_timeout_seconds,
        settings.kafka_flush_timeout_seconds,
    )

    try:
        async with LumuSession() as client, KafkaClient() as kafka:
            await client.authenticate()
            logger.info("Bootstrapping multi-tenant Defender key cache...")

            async def refresh_tenant_registry(force_full: bool = False) -> None:
                tenants = await client.get_tenants(items=500, page=1)
                logger.info("Discovered %s supervised tenant(s).", len(tenants))
                discovered_uuids: set[str] = set()
                key_fetch_success = 0
                key_fetch_failed = 0

                for tenant in tenants:
                    tenant_uuid = str(tenant.get("uuid") or "").strip()
                    tenant_name = str(tenant.get("name") or "").strip() or "unknown"
                    if not tenant_uuid:
                        continue
                    discovered_uuids.add(tenant_uuid)

                    topic = normalize_customer_topic(tenant_name)
                    if not topic:
                        key_fetch_failed += 1
                        logger.error(
                            "Skipping tenant due to invalid normalized topic tenant_uuid=%s tenant_name=%s",
                            tenant_uuid,
                            tenant_name,
                        )
                        continue

                    if not force_full and tenant_uuid in tenant_registry:
                        existing = tenant_registry[tenant_uuid]
                        if existing.tenant_name != tenant_name or existing.kafka_topic != topic:
                            tenant_registry[tenant_uuid] = TenantRuntime(
                                tenant_uuid=tenant_uuid,
                                tenant_name=tenant_name,
                                defender_api_key=existing.defender_api_key,
                                kafka_topic=topic,
                            )
                            logger.info(
                                "Tenant metadata refreshed tenant_uuid=%s tenant_name=%s topic=%s",
                                tenant_uuid,
                                tenant_name,
                                topic,
                            )
                        continue

                    endpoint = (
                        f"/api/msp/companies/{settings.lumu_mssp_uuid}/"
                        f"supervised_companies/{tenant_uuid}/defender_api_key"
                    )
                    try:
                        key_response = await client.get_with_auth(endpoint)
                        defender_api_key = ""
                        if isinstance(key_response, dict):
                            defender_api_key = str(key_response.get("defender_api_key") or "").strip()
                        if not defender_api_key:
                            raise RuntimeError("defender_api_key missing")

                        tenant_registry[tenant_uuid] = TenantRuntime(
                            tenant_uuid=tenant_uuid,
                            tenant_name=tenant_name,
                            defender_api_key=defender_api_key,
                            kafka_topic=topic,
                        )
                        analyzers_by_tenant.setdefault(tenant_uuid, Analyzer(state_file_key=tenant_uuid))
                        key_fetch_success += 1
                        logger.info(
                            "Tenant key bootstrap success tenant_uuid=%s tenant_name=%s topic=%s",
                            tenant_uuid,
                            tenant_name,
                            topic,
                        )
                    except Exception as exc:
                        key_fetch_failed += 1
                        logger.error(
                            "Tenant key bootstrap failed tenant_uuid=%s tenant_name=%s reason=%s",
                            tenant_uuid,
                            tenant_name,
                            exc,
                        )

                stale = set(tenant_registry.keys()) - discovered_uuids
                for tenant_uuid in stale:
                    tenant_registry.pop(tenant_uuid, None)
                    analyzers_by_tenant.pop(tenant_uuid, None)
                    logger.warning("Tenant removed from registry tenant_uuid=%s", tenant_uuid)

                logger.info(
                    "Tenant key bootstrap summary discovered=%s loaded=%s failed=%s active_registry=%s",
                    len(discovered_uuids),
                    key_fetch_success,
                    key_fetch_failed,
                    len(tenant_registry),
                )

            await refresh_tenant_registry(force_full=True)

            while True:
                logger.info("--- Starting Incident Polling Cycle ---")
                try:
                    await refresh_tenant_registry(force_full=False)
                    for tenant_uuid, runtime in list(tenant_registry.items()):
                        analyzer = analyzers_by_tenant.setdefault(tenant_uuid, Analyzer(state_file_key=tenant_uuid))
                        await monitor_tenant(
                            client=client,
                            analyzer=analyzer,
                            kafka=kafka,
                            tenant_uuid=runtime.tenant_uuid,
                            tenant_name=runtime.tenant_name,
                            company_key=runtime.defender_api_key,
                            kafka_topic=runtime.kafka_topic,
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
