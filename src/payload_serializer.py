import re
from typing import Any, Dict


MOVED_LUMU_FIELDS = {
    "incident_uuid",
    "title",
    "adversaries",
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
    "activity_incident_details",
    "endpoint_context",
}


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


def serialize_incident_event(
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
    lumu_payload = {
        "id": event_dict.get("incident_uuid", ""),
        "malicious_destination": event_dict.get("title", ""),
        "malicious_destination_id": event_dict.get("adversary_id", ""),
        "malicious_destination_types": event_dict.get("adversary_type", ""),
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
    activity_incident_details = event_dict.get("activity_incident_details")
    if isinstance(activity_incident_details, dict) and activity_incident_details:
        lumu_payload["activity_incident_details"] = activity_incident_details
    endpoint_context = event_dict.get("endpoint_context")
    if isinstance(endpoint_context, list) and endpoint_context:
        lumu_payload["endpoint_context"] = endpoint_context

    payload["data"] = {"lumu": lumu_payload}
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
    payload["decoder"] = {"name": "int-dec-lumu"}
    payload["manager"] = {"name": hostname}
    payload["product_name"] = "Lumu Defender"
    payload["timezone"] = settings.payload_timezone
    return payload
