import logging
import json
import os
import ipaddress
from pathlib import Path
from typing import Dict, Optional, List, Any
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from dateutil import parser
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
class AffectedEndpoint:
    name: str
    srcip: str = ""
    first_contact: str = ""
    last_contact: str = ""

@dataclass
class ThreatIntelArticle:
    title: str
    url: str
    description: str
    author: str

@dataclass
class MitreTechnique:
    technique: str
    description: str
    tactics: List[str]
    platforms: List[str]
    url: str

@dataclass
class ContextPlaybook:
    name: str
    description: str
    url: str

@dataclass
class ContextIOC:
    parsed_domain: str
    url: str
    feed_name: str
    threat_detail: str

@dataclass
class IncidentEvent:
    incident_uuid: str
    title: str
    adversary_type: str
    adversary_id: str
    severity: str
    status: str
    event_type: str
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
    affected_endpoints: List[AffectedEndpoint] = field(default_factory=list)
    # Context Enrichment 
    mitre_techniques: List[MitreTechnique] = field(default_factory=list)
    related_artifacts: Dict[str, List[str]] = field(default_factory=dict)
    extracted_iocs: List[ContextIOC] = field(default_factory=list)
    recommended_playbooks: List[ContextPlaybook] = field(default_factory=list)
    intelligence_tags: List[str] = field(default_factory=list)
    intelligence_articles: List[ThreatIntelArticle] = field(default_factory=list)
    tlp: str = "TLP: RED"
    disseminated: bool = False
    triggered_integrations: List[str] = field(default_factory=list)
    dissemination_time: Optional[str] = None
    dissemination_latency: Optional[str] = None
    mtt_response: Optional[str] = None
    mtt_resolution: Optional[str] = None


class Analyzer:
    def __init__(self, state_file_key: str = "default"):
        base_state_file = Path(get_settings().alert_state_file).name
        key = "".join(ch if ch.isalnum() else "_" for ch in state_file_key).strip("_") or "default"
        self._state_file = f"{key}_{base_state_file}"
        state_data = self._load_state()
        
        # Schema Migration: If state_data lacks 'incidents' but has items, it's the old schema
        if state_data and "incidents" not in state_data and "last_pulled_time" not in state_data:
            logger.info("Migrating legacy state schema to new per-incident schema...")
            self._incident_times = {str(k): str(v) for k, v in state_data.items()}
            # Synthesize last_pulled_time from the newest incident
            if self._incident_times:
                max_val = max(self._incident_times.values())
                # Handle old float timestamps vs new isoformat strings
                try:
                    # check if it's a float
                    float_ts = float(max_val)
                    from datetime import datetime, timezone
                    self.last_pulled_time = datetime.fromtimestamp(float_ts, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
                except ValueError:
                    self.last_pulled_time = max_val
            else:
                self.last_pulled_time = ""
            self.offset = get_settings().lumu_initial_offset
        else:
            self.last_pulled_time: str = state_data.get('last_pulled_time', '')
            if not self.last_pulled_time:
                self.last_pulled_time = get_settings().lumu_initial_time
            self._incident_times: Dict[str, str] = state_data.get('incidents', {})
            
            persisted_offset = state_data.get('offset', 0)
            env_offset = get_settings().lumu_initial_offset
            force_offset = get_settings().lumu_force_offset
            
            if force_offset:
                logger.info(f"LUMU_FORCE_OFFSET is enabled. Overriding persisted offset ({persisted_offset}) with LUMU_INITIAL_OFFSET ({env_offset}).")
                self.offset = env_offset
                self._incident_times = {} # Wipe tracked state times to allow a clean sync from new offset
                self._save_state()
            else:
                self.offset = persisted_offset

    def should_process_incident(self, raw_incident: Dict[str, Any]) -> bool:
        """
        Determines if an incident has changed since the last time it was seen.
        Checks for new UUIDs or updated lastContact timestamps.
        """
        uuid = raw_incident.get('id') or raw_incident.get('uuid')
        if not uuid:
            return False
            
        last_contact = raw_incident.get('lastContact') or raw_incident.get('timestamp') or ''
        stored_ts = self._incident_times.get(uuid, '')
        
        return not stored_ts or (last_contact > stored_ts)

    def classify_incident_event_type(self, raw_incident: Dict[str, Any]) -> str:
        """
        Normalizes Lumu event context to the two event types emitted downstream.
        New incidents default to NewIncidentCreated when no journal context exists.
        """
        explicit_event_type = raw_incident.get("_lumu_event_type")
        if explicit_event_type in {"NewIncidentCreated", "IncidentUpdated"}:
            return explicit_event_type

        uuid = raw_incident.get('id') or raw_incident.get('uuid')
        if uuid and uuid not in self._incident_times:
            return "NewIncidentCreated"

        return "IncidentUpdated"

    def update_incident_time(self, uuid: str, timestamp: str):
        """Manually update the last seen time for a specific incident."""
        if uuid and timestamp:
            self._incident_times[uuid] = timestamp
            if not self.last_pulled_time or timestamp > self.last_pulled_time:
                self.last_pulled_time = timestamp
            self._save_state()


    def _load_state(self) -> Dict[str, Any]:
        """Loads the alerted incidents from the JSON state file."""
        # Ensure the base directory is absolute and established at the root
        base_dir = Path(__file__).resolve().parent.parent / "data"
        abs_path = (base_dir / Path(self._state_file).name).resolve()

        # Path traversal protection: Ensure the state file is strictly within the data directory
        if not abs_path.is_relative_to(base_dir):
            logger.error(f"Security Alert: Path traversal attempt blocked for state file: {self._state_file}")
            return {}

        if not abs_path.exists():
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
            # Retain only recent incident timestamps to prevent unbounded state growth.
            cutoff = datetime.now(timezone.utc) - timedelta(days=60)
            pruned_incidents: Dict[str, str] = {}
            for incident_uuid, raw_ts in self._incident_times.items():
                try:
                    parsed = parser.parse(str(raw_ts))
                    if parsed.tzinfo is None:
                        parsed = parsed.replace(tzinfo=timezone.utc)
                    else:
                        parsed = parsed.astimezone(timezone.utc)
                    if parsed >= cutoff:
                        pruned_incidents[incident_uuid] = raw_ts
                except (ValueError, TypeError, OverflowError):
                    # Keep unparsable legacy entries to avoid accidental data loss.
                    pruned_incidents[incident_uuid] = raw_ts
            self._incident_times = pruned_incidents

            # Ensure the base directory is absolute and established at the root
            base_dir = Path(__file__).resolve().parent.parent / "data"
            abs_path = (base_dir / Path(self._state_file).name).resolve()

            # Path traversal protection
            if not abs_path.is_relative_to(base_dir):
                logger.error(f"Security Alert: Path traversal attempt blocked for state file: {self._state_file}")
                return

            parent_dir = abs_path.parent
            parent_dir.mkdir(parents=True, exist_ok=True)
            
            temp_file = str(abs_path) + ".tmp"
            # Secure file permissions (0o600)
            fd = os.open(temp_file, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, 'w') as f:
                json.dump({
                    "last_pulled_time": self.last_pulled_time,
                    "offset": self.offset,
                    "incidents": self._incident_times
                }, f, indent=2)
                f.flush()
                os.fsync(f.fileno())

            os.replace(temp_file, str(abs_path))
        except (IOError, OSError) as e:
            logger.error(f"Failed to save state file {self._state_file}: {e}")

    def _calculate_latency(self, start_iso: str, end_iso: str) -> Optional[str]:
        if not start_iso or not end_iso: return None
        try:
            s_ts = parser.parse(start_iso)
            e_ts = parser.parse(end_iso)
            
            # Ensure both are timezone aware for comparison
            if s_ts.tzinfo is None:
                s_ts = s_ts.replace(tzinfo=timezone.utc)
            if e_ts.tzinfo is None:
                e_ts = e_ts.replace(tzinfo=timezone.utc)
                
            diff = e_ts - s_ts
            seconds = int(diff.total_seconds())
            if seconds < 0: return "0s"
            h, r = divmod(seconds, 3600)
            m, s = divmod(r, 60)
            if h > 0: return f"{h}h {m}m {s}s"
            if m > 0: return f"{m}m {s}s"
            return f"{s}s"
        except Exception: return None

    def _merge_workstations(self, sources: List[List[Dict[str, Any]]]) -> List[AffectedEndpoint]:
        """
        Deduplicates and merges assets from multiple sources.
        Uses a tiered deduplication key: source IP (if present) OR hostname.
        Merges timelines: first_contact = min, last_contact = max.
        """
        merged: Dict[str, AffectedEndpoint] = {}
        merged_dts: Dict[str, Dict[str, Any]] = {}
        
        for source in sources:
            if not source:
                continue
            for item in source:
                if not isinstance(item, dict):
                    continue
                
                hostname = (
                    item.get('endpointName')
                    or item.get('hostname')
                    or item.get('hostName')
                    or item.get('name')
                    or item.get('host')
                    or item.get('deviceName')
                    or ''
                )
                srcip = (
                    item.get('endpointIp')
                    or item.get('ip')
                    or item.get('ipAddress')
                    or item.get('srcip')
                    or item.get('sourceIp')
                    or item.get('sourceIP')
                    or item.get('address')
                    or ''
                )
                name = str(hostname or srcip).strip()
                srcip = str(srcip or '').strip()
                if not srcip and name and self._looks_like_ip(name):
                    srcip = name
                if not name:
                    continue
                key = srcip or name
                
                # Try various timestamp fields
                raw_ts = item.get('datetime') or item.get('timestamp') or item.get('firstContact') or item.get('lastContact')
                ts_dt = None
                if raw_ts:
                    try:
                        ts_dt = parser.parse(raw_ts)
                        if ts_dt.tzinfo is None:
                            ts_dt = ts_dt.replace(tzinfo=timezone.utc)
                    except (ValueError, TypeError):
                        ts_dt = None

                if key not in merged:
                    merged[key] = AffectedEndpoint(
                        name=name,
                        srcip=srcip,
                        first_contact=raw_ts or '',
                        last_contact=raw_ts or ''
                    )
                    # Store parsed objects for comparison in a temporary dict
                    merged_dts[key] = {'first': ts_dt, 'last': ts_dt}
                else:
                    if srcip and not merged[key].srcip:
                        merged[key].srcip = srcip
                    if name and not merged[key].name:
                        merged[key].name = name
                if key in merged and ts_dt:
                    # Update first_contact if ts_dt is earlier
                    if not merged_dts[key]['first'] or (ts_dt < merged_dts[key]['first']):
                        merged_dts[key]['first'] = ts_dt
                        merged[key].first_contact = raw_ts
                    # Update last_contact if ts_dt is later
                    if not merged_dts[key]['last'] or (ts_dt > merged_dts[key]['last']):
                        merged_dts[key]['last'] = ts_dt
                        merged[key].last_contact = raw_ts        
        return sorted(list(merged.values()), key=lambda x: x.name)

    def _looks_like_ip(self, value: str) -> bool:
        try:
            ipaddress.ip_address(value)
            return True
        except ValueError:
            return False

    def evaluate_incidents(self,
                           raw_incidents: List[Dict[str, Any]],
                           stix_data_map: Dict[str, Dict[str, Any]] = None,
                           details_map: Dict[str, Dict[str, Any]] = None,
                           contacts_map: Dict[str, List[Dict[str, Any]]] = None,
                           summary_map: Dict[str, Dict[str, Any]] = None,
                           articles_map: Dict[str, List[Dict[str, Any]]] = None) -> List[IncidentEvent]:
        stix_data_map = stix_data_map or {}
        details_map = details_map or {}
        contacts_map = contacts_map or {}
        summary_map = summary_map or {}
        articles_map = articles_map or {}
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
            event_type = self.classify_incident_event_type(inc)

            # Metric Base Timestamps
            # Open Since (Incident Creation in Lumu)
            open_since = inc.get('timestamp', '') 
            # First Threat Contact (Actual sighting)
            first_contact = inc.get('firstContact') or open_since
            last_contact  = inc.get('lastContact')  or inc.get('statusTimestamp', '')
            
            # API reported count
            endpoints_count = inc.get('totalEndpoints') or inc.get('contacts', 0)

            # ── Parse STIX bundle ─────────────────────────────────────────
            stix = stix_data_map.get(uuid, {})
            objects = stix.get('objects', [])

            stix_indicators: List[StixIndicator] = []
            stix_malware:    List[StixMalware]   = []
            stix_sighting:   Optional[StixSighting] = None
            tlp_value = "TLP: RED"

            for obj in objects:
                t = obj.get('type')
                if t == 'marking-definition' and obj.get('definition_type') == 'tlp':
                    tlp_def = obj.get('definition', {}).get('tlp', '').upper()
                    if tlp_def: tlp_value = f"TLP: {tlp_def}"
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

            # ── Parse Context Summary ─────────────────────────────────────
            mitre_techniques: List[MitreTechnique] = []
            extracted_iocs: List[ContextIOC] = []
            recommended_playbooks: List[ContextPlaybook] = []
            intelligence_tags: List[str] = []
            related_artifacts: Dict[str, List[str]] = {}

            summary = summary_map.get(uuid, {})
            if summary:
                add = summary.get('additional', {})
                for mt in add.get('mitre', []):
                    mitre_techniques.append(MitreTechnique(
                        technique=mt.get('technique', ''),
                        description=mt.get('description', ''),
                        tactics=mt.get('tactics', []),
                        platforms=mt.get('platforms', []),
                        url=mt.get('references', [''])[0] if mt.get('references') else ''
                    ))
                
                related_artifacts = add.get('related_artifacts', {})
                intelligence_tags = add.get('tags', [])

                for pb in summary.get('playbooks', []):
                    recommended_playbooks.append(ContextPlaybook(
                        name=pb.get('name', ''),
                        description=pb.get('description', ''),
                        url=pb.get('url', '')
                    ))

                for ioc in summary.get('iocs', []):
                    extracted_iocs.append(ContextIOC(
                        parsed_domain=ioc.get('parsed_domain', ''),
                        url=ioc.get('url', ''),
                        feed_name=ioc.get('feed_name', ''),
                        threat_detail=ioc.get('threat_detail', '')
                    ))

            # ── Parse Context Articles ────────────────────────────────────
            intelligence_articles: List[ThreatIntelArticle] = []
            articles = articles_map.get(uuid, [])
            if isinstance(articles, list):
                for art in articles:
                    intelligence_articles.append(ThreatIntelArticle(
                        title=art.get('title', ''),
                        url=art.get('url', ''),
                        description=art.get('description', ''),
                        author=art.get('author', '')
                    ))

            # ── Parse Incident Details (Endpoints & Metrics) ──────────────
            affected_endpoints: List[AffectedEndpoint] = []
            disseminated = False
            triggered_integrations = []
            dissemination_time = None
            
            # User Definitions:
            # MTTD (Mean Time to Disseminate): Open Since (Creation) -> Automated Response
            # Time to Respond: First Threat Contact -> Automated Response
            # Time to Resolution: First Threat Contact -> Closed
            mtt_dissemination = None
            mtt_response = None
            mtt_resolution = None

            det = details_map.get(uuid, {})
            api_contacts_data = contacts_map.get(uuid, [])
            api_contacts_list = []
            if isinstance(api_contacts_data, dict):
                api_contacts_list = api_contacts_data.get('contacts') or api_contacts_data.get('items') or []
            elif isinstance(api_contacts_data, list):
                api_contacts_list = api_contacts_data

            det_contacts = det.get('contacts', []) if det else []
            first_contact_details = det.get('firstContactDetails', {}) if det else {}
            last_contact_details = det.get('lastContactDetails', {}) if det else {}

            sources = [
                api_contacts_list if isinstance(api_contacts_list, list) else [],
                det_contacts if isinstance(det_contacts, list) else [],
                [first_contact_details] if first_contact_details else [],
                [last_contact_details] if last_contact_details else []
            ]
            
            affected_endpoints = self._merge_workstations(sources)

            if det:

                # 2. Parse Metrics from Actions
                actions = det.get('actions', [])
                
                # Automated Response (Dissemination)
                response_actions = [a for a in actions if a.get('action') == 'response']
                if response_actions:
                    disseminated = True
                    unique_integrations = set()
                    first_resp_time = None
                    
                    for ra in response_actions:
                        data = ra.get('data', {})
                        ts = data.get('timestamp')
                        if ts:
                            if first_resp_time is None or ts < first_resp_time:
                                first_resp_time = ts
                        
                        int_type = data.get('integrationType')
                        if int_type:
                            # Format: replace _ with space, capitalize
                            formatted_int = int_type.replace('_', ' ').title()
                            unique_integrations.add(formatted_int)
                    
                    triggered_integrations = sorted(list(unique_integrations))
                    dissemination_time = first_resp_time
                    
                    # MTTD (Mean Time to Disseminate): Open Since (Creation) -> Response
                    mtt_dissemination = self._calculate_latency(open_since, dissemination_time)
                    # Time to Respond: First Threat Contact (Sighting) -> Response
                    mtt_response = self._calculate_latency(first_contact, dissemination_time)

                # Closed (Resolution)
                close_action = next((a for a in actions if a.get('action') == 'close'), None)
                if close_action:
                    # Time to Resolution: First Threat Contact -> Close
                    mtt_resolution = self._calculate_latency(first_contact, close_action.get('datetime', ''))
                else:
                    mtt_resolution = None

            event = IncidentEvent(
                incident_uuid=uuid,
                title=title,
                adversary_type=adv_type,
                adversary_id=adv_id,
                severity=severity,
                status=status,
                event_type=event_type,
                first_contact=first_contact,
                last_contact=last_contact,
                endpoints_affected=endpoints_count,
                stix_indicators=stix_indicators,
                stix_malware=stix_malware,
                stix_sighting=stix_sighting,
                adversaries=adversaries,
                details=inc.get('description', title),
                affected_endpoints=affected_endpoints,
                mitre_techniques=mitre_techniques,
                related_artifacts=related_artifacts,
                extracted_iocs=extracted_iocs,
                recommended_playbooks=recommended_playbooks,
                intelligence_tags=intelligence_tags,
                intelligence_articles=intelligence_articles,
                tlp=tlp_value,
                disseminated=disseminated,
                triggered_integrations=triggered_integrations,
                dissemination_time=dissemination_time,
                dissemination_latency=mtt_dissemination,
                mtt_response=mtt_response,
                mtt_resolution=mtt_resolution
            )

            incident_events.append(event)

        return incident_events

    def extract_incidents_from_updates(self, updates_data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Processes a list of updates from the /api/incidents/open-incidents/updates endpoint.
        Unwraps incident data from: NewIncidentCreated, IncidentClosed, IncidentUnmuted, etc.
        Returns a list of raw incident objects suitable for evaluate_incidents.
        """
        incidents = []
        for update in updates_data:
            # The structure is: { "EventType": { "incident": { ... }, "companyId": "..." } }
            # Or: { "OpenIncidentsStatusUpdated": { ... } } (ignored for now)
            
            event_type = next(iter(update.keys()))
            event_data = update[event_type]
            
            if event_type in ["NewIncidentCreated", "IncidentUpdated", "IncidentClosed", "IncidentUnmuted", "IncidentMuted", "IncidentReopened"]:
                incident_data = event_data.get("incident")
                if incident_data:
                    normalized_event_type = "NewIncidentCreated" if event_type == "NewIncidentCreated" else "IncidentUpdated"
                    incident_with_context = dict(incident_data)
                    incident_with_context["_lumu_event_type"] = normalized_event_type
                    incidents.append(incident_with_context)
                else:
                    logger.warning(f"Update event {event_type} missing incident data.")
            elif event_type == "OpenIncidentsStatusUpdated":
                logger.debug(f"Received status update: {event_data}")
            else:
                logger.debug(f"Ignoring update event type: {event_type}")
                
        return incidents

    def filter_changed_incidents(self, events: List[IncidentEvent]) -> List[IncidentEvent]:
        """
        Returns incidents that are either:
        - New (UUID never seen before), or
        - Updated (event.last_contact is strictly newer than the stored per-incident timestamp).

        Updates the per-incident map and global high-water mark for every event that passes.
        """
        changed_events = []
        state_updated = False
        new_max_time = self.last_pulled_time

        for e in events:
            stored_ts = self._incident_times.get(e.incident_uuid, '')

            is_new = not stored_ts
            is_updated = bool(e.last_contact and e.last_contact > stored_ts)

            if is_new or is_updated:
                changed_events.append(e)
                # Update stored timestamp for this specific incident
                if e.last_contact:
                    self._incident_times[e.incident_uuid] = e.last_contact
                    state_updated = True

            # Advance global high-water mark regardless (controls outer polling window)
            if e.last_contact and e.last_contact > new_max_time:
                new_max_time = e.last_contact
                state_updated = True

        if state_updated:
            self.last_pulled_time = new_max_time
            self._save_state()

        return changed_events
