import asyncio
import logging
import sys
import dataclasses
from datetime import datetime, timezone
from typing import Dict, Any, List
from .config import get_settings
from .lumu_client import LumuSession
from .analyzer import Analyzer
from .wazuh_client import WazuhClient

logging.basicConfig(
    stream=sys.stdout,
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("lumu_monitor")

async def enrich_incident(client: LumuSession, tenant_uuid: str, company_key: str, inc_uuid: str, is_bootstrap_mode: bool = False) -> Dict[str, Any]:
    """
    Fetches STIX, details, summary context, and external-articles context for a single incident concurrently.
    """
    try:
        details_task = client.get_incident_details(company_key, inc_uuid)
        stix_task = client.get_incident_stix(tenant_uuid, inc_uuid)
        summary_task = client.get_incident_context_summary(tenant_uuid, inc_uuid)
        
        # External Articles are the heaviest/slowest, we only skip THESE in bootstrap mode
        articles_task = None
        if not is_bootstrap_mode:
            articles_task = client.get_incident_external_articles(tenant_uuid, inc_uuid)
        
        # Batch fetching with small delays to respect rate limits
        stix = await stix_task
        await asyncio.sleep(0.5)
        details = await details_task
        await asyncio.sleep(0.5)
        summary = await summary_task
        
        articles = []
        if articles_task:
            await asyncio.sleep(0.5)
            articles = await articles_task
        
        # Gracefully handle exceptions when specific APIs return 404 or fail
        return {
            'uuid': inc_uuid, 
            'stix': stix if not isinstance(stix, Exception) else {}, 
            'details': details if not isinstance(details, Exception) else {},
            'summary': summary if not isinstance(summary, Exception) else {},
            'articles': articles if not isinstance(articles, Exception) else []
        }
    except Exception as e:
        logger.debug(f"Intelligence enrichment failed for incident {inc_uuid}: {e}")
        return {'uuid': inc_uuid, 'stix': {}, 'details': {}, 'summary': {}, 'articles': []}

async def monitor_tenant(client: LumuSession, analyzer: Analyzer, wazuh: WazuhClient, tenant_uuid: str, tenant_name: str, company_key: str):
    """
    Monitors a single tenant for security incidents using a Hybrid Strategy:
    1. State Sync: Fetch all currently OPEN incidents.
    2. Incremental Sync: Fetch journal UPDATES via offset.
    """
    logger.info(f"Scanning security incidents for tenant '{tenant_name}' ({tenant_uuid})...")
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
            await process_and_send_batch(
                client, analyzer, wazuh, 
                raw_incidents=to_enrich_state, 
                tenant_uuid=tenant_uuid, 
                tenant_name=tenant_name, 
                company_key=company_key,
                is_bootstrap_mode=False # State sync is usually light enough
            )
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
                await process_and_send_batch(
                    client, analyzer, wazuh, 
                    raw_incidents, 
                    tenant_uuid, 
                    tenant_name, 
                    company_key, 
                    is_bootstrap_mode=is_bootstrap_mode
                )
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

async def process_and_send_batch(
    client: LumuSession, 
    analyzer: Analyzer, 
    wazuh: WazuhClient, 
    raw_incidents: List[Dict[str, Any]], 
    tenant_uuid: str, 
    tenant_name: str, 
    company_key: str,
    is_bootstrap_mode: bool = False
):
    """
    Enriches raw incidents and streams them to Wazuh as they complete.
    """
    # 1. Map UUIDs to raw objects for reconstruction after streaming
    uuid_to_raw = {}
    for inc in raw_incidents:
        uid = inc.get('uuid') or inc.get('id')
        if uid:
            uuid_to_raw[uid] = inc

    if not uuid_to_raw:
        return

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
                summary_map={inc_uuid: res['summary']},
                articles_map={inc_uuid: res['articles']}
            )

            # Send to Wazuh
            for event in mapped_events:
                try:
                    event_dict = dataclasses.asdict(event)
                    event_dict["@timestamp"] = datetime.now(timezone.utc).isoformat()
                    event_dict["customer_name"] = tenant_name
                    event_dict["customer_uuid"] = tenant_uuid
                    
                    await wazuh.send_incident(event_dict)
                    
                    # Update state immediately
                    analyzer.update_incident_time(event.incident_uuid, event.last_contact)
                except Exception as e:
                    logger.error(f"Failed to send incident {event.incident_uuid} to Wazuh: {e}")

        except Exception as e:
            logger.error(f"Streaming error for an incident task: {e}")

async def run_loop():
    settings = get_settings()
    client = LumuSession()
    analyzer = Analyzer()
    wazuh = WazuhClient()

    interval_seconds = settings.polling_interval_minutes * 60

    logger.info(f"Lumu Incident Handler started.")
    logger.info(f"Monitoring customer: '{settings.customer_name}' ({settings.customer_uuid})")

    try:
        await client.authenticate()

        while True:
            logger.info("--- Starting Incident Polling Cycle ---")
            try:
                await monitor_tenant(
                    client=client,
                    analyzer=analyzer,
                    wazuh=wazuh,
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
    finally:
        await client.close()
        await wazuh.close()



if __name__ == "__main__":
    try:
        asyncio.run(run_loop())
    except KeyboardInterrupt:
        pass
