import asyncio
import logging
import sys
from .config import get_settings
from .lumu_client import LumuSession
from .analyzer import Analyzer
from .notifier import Notifier

logging.basicConfig(
    stream=sys.stdout,
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("lumu_monitor")

async def monitor_tenant(client: LumuSession, analyzer: Analyzer, notifier: Notifier, tenant_uuid: str, tenant_name: str, company_key: str):
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

        logger.info(f"Found {len(raw_incidents)} active incident(s). Fetching intelligence...")

        stix_data_map = {}
        details_map = {}
        for inc in raw_incidents:
            inc_uuid = inc.get('uuid') or inc.get('id')
            if inc_uuid:
                try:
                    # Fetch STIX
                    stix_data = await client.get_incident_stix(tenant_uuid, inc_uuid)
                    stix_data_map[inc_uuid] = stix_data

                    # Fetch Details (for endpoint names)
                    details = await client.get_incident_details(company_key, inc_uuid)
                    details_map[inc_uuid] = details
                except Exception as e:
                    logger.debug(f"Intelligence enrichment failed for incident {inc_uuid}: {e}")

        all_incident_events = analyzer.evaluate_incidents(raw_incidents, stix_data_map, details_map)

        # 4. Filter for new (not yet alerted) incidents only
        new_events = analyzer.filter_new_incidents(all_incident_events)

        # 5. Fire notification if new incidents detected
        if new_events:
            logger.warning(f"Alerting on {len(new_events)} new incident(s) for '{tenant_name}'.")
            notifier.send_incident_alert(new_events, tenant_uuid, tenant_name)
        else:
            logger.info(f"All {len(all_incident_events)} active incident(s) for '{tenant_name}' have already been alerted.")

    except Exception as e:
        logger.error(f"Error processing incidents for tenant {tenant_uuid}: {str(e)}")


async def run_loop():
    settings = get_settings()
    client = LumuSession()
    analyzer = Analyzer()
    notifier = Notifier()

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
                    notifier=notifier,
                    tenant_uuid=settings.customer_uuid,
                    tenant_name=settings.customer_name,
                    company_key=settings.lumu_defender_key,
                )
            except Exception as e:
                logger.error(f"Critical error during polling cycle: {str(e)}")

            logger.info(f"Cycle complete. Waiting {settings.polling_interval_minutes} minutes for next check.")
            await asyncio.sleep(interval_seconds)

    except asyncio.CancelledError:
        logger.info("Monitor interrupted. Shutting down gracefully...")
    finally:
        await client.close()


if __name__ == "__main__":
    try:
        asyncio.run(run_loop())
    except KeyboardInterrupt:
        pass
