from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


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
    stix_indicators: List[StixIndicator] = field(default_factory=list)
    stix_malware: List[StixMalware] = field(default_factory=list)
    stix_sighting: Optional[StixSighting] = None
    adversaries: List[str] = field(default_factory=list)
    details: str = ""
    affected_endpoints: List[AffectedEndpoint] = field(default_factory=list)
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
    activity_incident_details: Dict[str, Any] = field(default_factory=dict)
    endpoint_context: List[Dict[str, Any]] = field(default_factory=list)


@dataclass
class IncidentSourceBundle:
    incident_uuid: str
    tenant_uuid: str
    defender_details: Dict[str, Any] = field(default_factory=dict)
    defender_contacts: List[Dict[str, Any]] = field(default_factory=list)
    secops_details: Dict[str, Any] = field(default_factory=dict)
    activity_event_details: List[Dict[str, Any]] = field(default_factory=list)
    endpoint_contacts_range: Dict[str, List[Dict[str, Any]]] = field(default_factory=dict)
    stix: Dict[str, Any] = field(default_factory=dict)
    summary: Dict[str, Any] = field(default_factory=dict)
    articles: List[Dict[str, Any]] = field(default_factory=list)
