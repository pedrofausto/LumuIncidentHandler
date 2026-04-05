import asyncio
import logging
import sys
import os
import json
from src.config import get_settings
from src.lumu_client import LumuSession
from src.analyzer import Analyzer
from src.notifier import Notifier

# Set level to DEBUG for granular SMTP troubleshooting
logging.basicConfig(
    stream=sys.stdout,
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("manual_test")

async def run_manual_test():
    settings = get_settings()
    client = LumuSession()
    analyzer = Analyzer()
    notifier = Notifier()

    company_key = settings.lumu_defender_key.get_secret_value() if settings.lumu_defender_key else None
    customer_uuid = settings.customer_uuid
    tenant_name = settings.customer_name

    logger.info(f"Starting manual test for tenant '{tenant_name}'...")

    try:
        await client.authenticate()

        # 1. Fetch all incidents
        raw_incidents = await client.get_all_incidents(company_key)

        if not raw_incidents:
            logger.info("No incidents found to test.")
            return

        # 2. Extract the last 5 incidents
        test_incidents = raw_incidents[-5:]
        logger.info(f"Testing with the last {len(test_incidents)} incident(s).")

        stix_data_map = {}
        details_map = {}
        for inc in test_incidents:
            inc_uuid = inc.get('uuid') or inc.get('id')
            if inc_uuid:
                try:
                    logger.debug(f"Fetching enrichment for incident {inc_uuid}...")
                    # Fetch STIX
                    stix_data = await client.get_incident_stix(tenant_uuid, inc_uuid)
                    stix_data_map[inc_uuid] = stix_data

                    # Fetch Details (for dissemination info)
                    details = await client.get_incident_details(company_key, inc_uuid)
                    details_map[inc_uuid] = details
                    
                    # ── Raw Inspection ──────────────────────────────────────────
                    logger.info(f"RAW DETAILS for {inc_uuid}: {json.dumps(details, indent=2)}")
                except Exception as e:
                    logger.warning(f"Enrichment failed for {inc_uuid}: {e}")

        # 3. Evaluate incidents (Parsing logic from Phase 2)
        incident_events = analyzer.evaluate_incidents(test_incidents, stix_data_map, details_map)

        # 4. Trigger notification (Bypassing filter_new_incidents to force alert)
        if incident_events:
            logger.info(f"Dispatching manual alerts for {len(incident_events)} incident(s)...")
            
            # ── Visual Verification: Save to disk ──────────────────────────
            os.makedirs("debug_alerts", exist_ok=True)
            for i, event in enumerate(incident_events):
                try:
                    # Capture what Notifier would render (internal access for testing)
                    # We'll just run the actual notifier and check the logs
                    pass
                except Exception: pass

            success = notifier.send_incident_alert(incident_events, tenant_uuid, tenant_name)
            if success:
                logger.info("Manual test alerts sent successfully.")
            else:
                logger.error("Some or all manual test alerts failed to send.")
        else:
            logger.info("No incident events generated for testing.")

    except Exception as e:
        logger.error(f"Manual test failed: {str(e)}")
    finally:
        await client.close()

if __name__ == "__main__":
    asyncio.run(run_manual_test())
