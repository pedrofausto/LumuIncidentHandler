import asyncio
import logging
import sys
import random
from src.config import get_settings
from src.lumu_client import LumuSession
from src.analyzer import Analyzer
from src.notifier import Notifier

logging.basicConfig(
    stream=sys.stdout,
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("final_test")

async def run_final_test():
    settings = get_settings()
    client = LumuSession()
    analyzer = Analyzer()
    notifier = Notifier()

    company_key = settings.lumu_defender_key.get_secret_value() if settings.lumu_defender_key else None
    customer_uuid = settings.customer_uuid
    tenant_name = settings.customer_name

    logger.info(f"Starting final validation test for tenant '{tenant_name}'...")

    try:
        await client.authenticate()

        # 1. Fetch all open incidents
        raw_incidents = await client.get_all_incidents(company_key)
        if not raw_incidents:
            logger.info("No open incidents found to test.")
            return

        # Use the last 5 for processing
        test_incidents = raw_incidents[-5:]
        logger.info(f"Processing the last {len(test_incidents)} incidents...")

        stix_data_map = {}
        details_map = {}
        contacts_map = {}
        
        for inc in test_incidents:
            inc_uuid = inc.get('uuid') or inc.get('id')
            if inc_uuid:
                try:
                    logger.info(f"Fetching enrichment for incident {inc_uuid}...")
                    stix_data_map[inc_uuid] = await client.get_incident_stix(customer_uuid, inc_uuid)
                    details_map[inc_uuid] = await client.get_incident_details(company_key, inc_uuid)
                    
                    # Fetching contacts explicitly now
                    contacts_map[inc_uuid] = await client.get_incident_contacts(company_key, inc_uuid)
                    logger.info(f"Found {len(contacts_map[inc_uuid])} contacts for {inc_uuid}")
                except Exception as e:
                    logger.warning(f"Enrichment failed for {inc_uuid}: {e}")

        # 1.1 Inject Mock Data for Validation (Phase 4)
        mock_uuid = "373c4cd0-a136-11f0-b8ca-25032e085319"
        logger.info(f"Injecting mock data for incident {mock_uuid}...")
        
        # Find and update or add the mock incident
        mock_inc = next((inc for inc in test_incidents if inc.get('id') == mock_uuid or inc.get('uuid') == mock_uuid), None)
        
        # 11 distinct workstations
        mock_contacts = [
            {'endpointName': f'WS-{i:02d}', 'timestamp': f'2025-10-01T10:{i:02d}:00Z'}
            for i in range(1, 12)
        ]

        if mock_inc:
            mock_inc.update({
                'title': 'Phase 4 Validation: Multi-Integration & TTR',
                'timestamp': '2025-10-01T10:00:00Z',
                'firstContact': '2025-10-01T10:01:00Z',
                'lastContact': '2025-10-01T10:11:00Z',
                'status': 'closed',
                'totalEndpoints': 11
            })
        else:
            test_incidents.append({
                'id': mock_uuid,
                'title': 'Phase 4 Validation: Multi-Integration & TTR',
                'severity': 'Critical',
                'adversaryTypes': ['Malware', 'C2'],
                'adversaryId': 'MockAdversary-001',
                'timestamp': '2025-10-01T10:00:00Z', # Open Since
                'firstContact': '2025-10-01T10:01:00Z',
                'lastContact': '2025-10-01T10:11:00Z',
                'status': 'closed',
                'totalEndpoints': 11
            })

        details_map[mock_uuid] = {
            'actions': [
                {'action': 'response', 'data': {'integrationType': 'crowdstrike_falcon', 'timestamp': '2025-10-01T10:15:00Z'}},
                {'action': 'response', 'data': {'integrationType': 'palo_alto_ngfw', 'timestamp': '2025-10-01T10:16:00Z'}},
                {'action': 'response', 'data': {'integrationType': 'check_point_ngfw', 'timestamp': '2025-10-01T10:17:00Z'}},
                {'action': 'response', 'data': {'integrationType': 'netskope_ngswg', 'timestamp': '2025-10-01T10:18:00Z'}},
                {'action': 'close', 'datetime': '2025-10-01T10:44:34Z'}
            ],
            'contacts': mock_contacts
        }
        
        contacts_map[mock_uuid] = mock_contacts
        
        stix_data_map[mock_uuid] = {
            'objects': [
                {'type': 'indicator', 'name': 'Mock C2 Indicator', 'pattern': "[domain-name:value = 'mock-c2.com']"},
                {'type': 'marking-definition', 'definition_type': 'tlp', 'definition': {'tlp': 'red'}}
            ]
        }

        # 2. Evaluate incidents with the refined logic
        incident_events = analyzer.evaluate_incidents(test_incidents, stix_data_map, details_map, contacts_map)

        if not incident_events:
            logger.info("No incident events generated.")
            return

        # 3. Select the mock incident for validation
        target_event = next((e for e in incident_events if e.incident_uuid == mock_uuid), random.choice(incident_events))
        logger.info(f"SELECTED INCIDENT FOR EMAIL: {target_event.incident_uuid} ({target_event.title})")
        
        # Log metrics for debugging
        logger.info(f"Metrics: MTTD={target_event.dissemination_latency}, MTTR={target_event.mtt_response}, Resolution={target_event.mtt_resolution}")
        logger.info(f"Workstations found: {len(target_event.affected_endpoints)}")

        success = notifier.send_incident_alert([target_event], customer_uuid, tenant_name)
        if success:
            logger.info("Final test alert sent successfully.")
        else:
            logger.error("Final test alert failed to send.")

    except Exception as e:
        logger.error(f"Final test failed: {str(e)}")
    finally:
        await client.close()

if __name__ == "__main__":
    asyncio.run(run_final_test())
