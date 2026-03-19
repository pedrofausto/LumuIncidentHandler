import time
import logging
import json
import os
from typing import Dict, Optional, List, Any
from dataclasses import dataclass, field
from datetime import datetime, timezone
from src.config import get_settings

logger = logging.getLogger(__name__)

@dataclass
class StixIndicator:
    name: str
    description: str
    pattern: str
    indicator_types: List[str]
    valid_from: str

@dataclass
class StixMalware:
    name: str
    is_family: bool

@dataclass
class StixSighting:
    first_seen: str
    last_seen: str
    count: int

@dataclass
class IncidentEvent:
    incident_uuid: str
    title: str
    adversary_type: str
    adversary_id: str
    severity: str
    status: str
    first_contact: str
    last_contact: str
    endpoints_affected: int
    # Parsed STIX objects
    stix_indicators: List[StixIndicator] = field(default_factory=list)
    stix_malware: List[StixMalware] = field(default_factory=list)
    stix_sighting: Optional[StixSighting] = None
    # Fallback: raw adversary hostnames/IPs
    adversaries: List[str] = field(default_factory=list)
    details: str = ""
    affected_endpoints: List[str] = field(default_factory=list)
    tlp: str = "TLP: RED"


class Analyzer:
    def __init__(self):
        self._state_file = get_settings().alert_state_file
        self._alerted_incidents: Dict[str, float] = self._load_state()

    def _load_state(self) -> Dict[str, float]:
        """Loads the alerted incidents from the JSON state file."""
        # Ensure the base directory is absolute and established at the root
        base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "data"))
        abs_path = os.path.abspath(os.path.join(base_dir, os.path.basename(self._state_file)))

        # Path traversal protection: Ensure the state file is strictly within the data directory
        if not abs_path.startswith(base_dir + os.sep):
            logger.error(f"Security Alert: Path traversal attempt blocked for state file: {self._state_file}")
            return {}

        if not os.path.exists(abs_path):
            return {}
        try:
            with open(abs_path, 'r') as f:
                content = f.read()
                if not content:
                    return {}
                return json.loads(content)
        except (json.JSONDecodeError, IOError) as e:
            logger.error(f"Failed to load state file {self._state_file}: {e}")
            return {}

    def _save_state(self):
        """Atomically saves the alerted incidents to the JSON state file."""
        try:
            # Ensure the base directory is absolute and established at the root
            base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "data"))
            abs_path = os.path.abspath(os.path.join(base_dir, os.path.basename(self._state_file)))

            # Path traversal protection
            if not abs_path.startswith(base_dir + os.sep):
                logger.error(f"Security Alert: Path traversal attempt blocked for state file: {self._state_file}")
                return

            parent_dir = os.path.dirname(abs_path)
            if parent_dir:
                os.makedirs(parent_dir, exist_ok=True)
            
            temp_file = abs_path + ".tmp"
            # Secure file permissions (0o600)
            fd = os.open(temp_file, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, 'w') as f:
                json.dump(self._alerted_incidents, f, indent=2)
                f.flush()
                os.fsync(f.fileno())
                
            os.replace(temp_file, abs_path)
        except (IOError, OSError) as e:
            logger.error(f"Failed to save state file {self._state_file}: {e}")

    def evaluate_incidents(self,
                           raw_incidents: List[Dict[str, Any]],
                           stix_data_map: Dict[str, Dict[str, Any]] = None,
                           details_map: Dict[str, Dict[str, Any]] = None) -> List[IncidentEvent]:
        stix_data_map = stix_data_map or {}
        details_map = details_map or {}
        incident_events: List[IncidentEvent] = []

        for inc in raw_incidents:
            uuid = inc.get('id') or inc.get('uuid')
            if not uuid:
                continue

            title = inc.get('adversaryId') or inc.get('description') or inc.get('title') or 'Untitled Incident'
            if len(title) > 120:
                title = title[:117] + '...'

            adv_types = inc.get('adversaryTypes') or []
            adv_type  = ', '.join(adv_types) if adv_types else 'Unknown'
            adv_id    = inc.get('adversaryId', '')
            adversaries = inc.get('adversaries') or []

            severity   = inc.get('severity', 'High')
            status     = inc.get('status', 'open')

            first_contact = inc.get('firstContact') or inc.get('timestamp', '')
            last_contact  = inc.get('lastContact')  or inc.get('statusTimestamp', '')
            endpoints     = inc.get('totalEndpoints') or inc.get('contacts', 0)

            # ── Parse STIX bundle ─────────────────────────────────────────
            stix = stix_data_map.get(uuid, {})
            objects = stix.get('objects', [])

            # Build lookup by id so relationships can be resolved
            obj_by_id: Dict[str, Dict] = {o['id']: o for o in objects if 'id' in o}

            stix_indicators: List[StixIndicator] = []
            stix_malware:    List[StixMalware]   = []
            stix_sighting:   Optional[StixSighting] = None
            tlp_value = "TLP: RED"

            for obj in objects:
                t = obj.get('type')

                if t == 'marking-definition' and obj.get('definition_type') == 'tlp':
                    tlp_def = obj.get('definition', {}).get('tlp', '').upper()
                    if tlp_def:
                        tlp_value = f"TLP: {tlp_def}"

                elif t == 'indicator':
                    stix_indicators.append(StixIndicator(
                        name=obj.get('name', ''),
                        description=obj.get('description', ''),
                        pattern=obj.get('pattern', ''),
                        indicator_types=obj.get('indicator_types', []),
                        valid_from=obj.get('valid_from', '')
                    ))

                elif t == 'malware':
                    stix_malware.append(StixMalware(
                        name=obj.get('name', ''),
                        is_family=obj.get('is_family', False)
                    ))

                elif t == 'sighting' and stix_sighting is None:
                    stix_sighting = StixSighting(
                        first_seen=obj.get('first_seen', ''),
                        last_seen=obj.get('last_seen', ''),
                        count=obj.get('count', 1)
                    )

            # ── Parse Incident Details (Endpoints) ────────────────────────
            affected_endpoints = []
            det = details_map.get(uuid, {})
            if det:
                # Collect from first and last contact as a minimum
                f_det = det.get('firstContactDetails', {})
                l_det = det.get('lastContactDetails', {})
                
                names = set()
                for d in [f_det, l_det]:
                    name = d.get('endpointName') or d.get('endpointIp')
                    if name:
                        names.add(name)
                affected_endpoints = sorted(list(names))

            event = IncidentEvent(
                incident_uuid=uuid,
                title=title,
                adversary_type=adv_type,
                adversary_id=adv_id,
                severity=severity,
                status=status,
                first_contact=first_contact,
                last_contact=last_contact,
                endpoints_affected=endpoints,
                stix_indicators=stix_indicators,
                stix_malware=stix_malware,
                stix_sighting=stix_sighting,
                adversaries=adversaries,
                details=inc.get('description', title),
                affected_endpoints=affected_endpoints,
                tlp=tlp_value
            )

            incident_events.append(event)

        return incident_events

    def filter_new_incidents(self, events: List[IncidentEvent]) -> List[IncidentEvent]:
        new_events = []
        current_time = time.time()
        updated = False
        for e in events:
            if e.incident_uuid not in self._alerted_incidents:
                new_events.append(e)
                self._alerted_incidents[e.incident_uuid] = current_time
                updated = True
        
        if updated:
            self._save_state()
            
        return new_events
