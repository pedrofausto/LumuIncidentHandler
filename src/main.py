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

async def enrich_incident(client: LumuSession, tenant_uuid: str, company_key: str, inc_uuid: str) -> Dict[str, Any]:
    """
    Fetches STIX, details, summary context, and external-articles context for a single incident concurrently.
    """
    try:
        stix_task = client.get_incident_stix(tenant_uuid, inc_uuid)
        details_task = client.get_incident_details(company_key, inc_uuid)
        summary_task = client.get_incident_context_summary(tenant_uuid, inc_uuid)
        articles_task = client.get_incident_external_articles(tenant_uuid, inc_uuid)
        
        stix, details, summary, articles = await asyncio.gather(
            stix_task, details_task, summary_task, articles_task, return_exceptions=True
        )
        
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
    Monitors a single tenant for security incidents and fetches STIX intelligence.
    """
    logger.info(f"Scanning security incidents for tenant '{tenant_name}' ({tenant_uuid})...")
    try:
        if not company_key:
            logger.warning(f"LUMU_DEFENDER_KEY is not set. Skipping incident scan.")
            return

        # 1. Fetch active incidents from Defender API
        raw_incidents = await client.get_all_incidents(company_key)

        if not raw_incidents:
            logger.info(f"No active incidents found for tenant '{tenant_name}'.")
            return

        # 2. Deduplication: only process incidents that are new or updated
        new_raw_incidents = []
        for inc in raw_incidents:
            uuid = inc.get('uuid') or inc.get('id')
            if not uuid: continue
            
            # Use Lumu's last activity time to track updates
            last_activity = inc.get('lastContact') or inc.get('statusTimestamp') or inc.get('timestamp') or ''
            
            # Process if Lumu's timestamp for the event is strictly newer than our global high-water mark
            if not analyzer.last_pulled_time or last_activity > analyzer.last_pulled_time:
                new_raw_incidents.append(inc)

        if not new_raw_incidents:
            logger.info(f"All {len(raw_incidents)} active incident(s) for '{tenant_name}' have already been alerted.")
            return

        logger.info(f"Found {len(new_raw_incidents)} new incident(s). Fetching intelligence concurrently...")

        # 3. Concurrent Enrichment
        tasks = [enrich_incident(client, tenant_uuid, company_key, inc.get('uuid') or inc.get('id')) for inc in new_raw_incidents]
        enrichment_results = await asyncio.gather(*tasks)

        stix_data_map = {res['uuid']: res['stix'] for res in enrichment_results}
        details_map = {res['uuid']: res['details'] for res in enrichment_results}
        summary_map = {res['uuid']: res['summary'] for res in enrichment_results}
        articles_map = {res['uuid']: res['articles'] for res in enrichment_results}

        # 4. Evaluate and filter
        all_incident_events = analyzer.evaluate_incidents(
            new_raw_incidents, 
            stix_data_map=stix_data_map, 
            details_map=details_map,
            summary_map=summary_map,
            articles_map=articles_map
        )
        new_events = analyzer.filter_new_incidents(all_incident_events)

        if new_events:
            logger.warning(f"Alerting on {len(new_events)} new incident(s) for '{tenant_name}'.")
            
            # 5. Dispatch to Wazuh
            for event in new_events:
                try:
                    event_dict = dataclasses.asdict(event)
                    # OpenSearch TSDB heavily relies on @timestamp reflecting ingestion time natively
                    event_dict["@timestamp"] = datetime.now(timezone.utc).isoformat()
                    # Inject generic tenant context
                    event_dict["customer_name"] = tenant_name
                    event_dict["customer_uuid"] = tenant_uuid
                    await wazuh.send_incident(event_dict)
                except Exception as e:
                    logger.error(f"Failed to send incident {event.incident_uuid} to Wazuh: {e}")
        else:
            logger.info(f"No new incidents to alert for '{tenant_name}' after filtering.")

    except Exception as e:
        logger.error(f"Error processing incidents for tenant {tenant_uuid}: {str(e)}")


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
