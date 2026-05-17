import ipaddress
import logging
import re
from datetime import timezone
from typing import Any, Dict, List, Optional

from dateutil import parser

from .models import (
    AffectedEndpoint,
    ContextIOC,
    ContextPlaybook,
    IncidentEvent,
    IncidentSourceBundle,
    MitreTechnique,
    StixIndicator,
    StixMalware,
    StixSighting,
    ThreatIntelArticle,
)

logger = logging.getLogger(__name__)


def _calculate_latency(start_iso: str, end_iso: str) -> Optional[str]:
    if not start_iso or not end_iso:
        return None
    try:
        s_ts = parser.parse(start_iso)
        e_ts = parser.parse(end_iso)
        if s_ts.tzinfo is None:
            s_ts = s_ts.replace(tzinfo=timezone.utc)
        if e_ts.tzinfo is None:
            e_ts = e_ts.replace(tzinfo=timezone.utc)
        diff = e_ts - s_ts
        seconds = int(diff.total_seconds())
        if seconds < 0:
            return "0s"
        h, r = divmod(seconds, 3600)
        m, s = divmod(r, 60)
        if h > 0:
            return f"{h}h {m}m {s}s"
        if m > 0:
            return f"{m}m {s}s"
        return f"{s}s"
    except Exception:
        return None


def _looks_like_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _merge_workstations(sources: List[List[Dict[str, Any]]]) -> List[AffectedEndpoint]:
    merged: Dict[str, AffectedEndpoint] = {}
    merged_dts: Dict[str, Dict[str, Any]] = {}

    for source in sources:
        if not source:
            continue
        for item in source:
            if not isinstance(item, dict):
                continue

            hostname = (
                item.get("endpointName")
                or item.get("hostname")
                or item.get("hostName")
                or item.get("name")
                or item.get("host")
                or item.get("deviceName")
                or ""
            )
            srcip = (
                item.get("endpointIp")
                or item.get("endpoint_ip")
                or item.get("ip")
                or item.get("ipAddress")
                or item.get("srcip")
                or item.get("sourceIp")
                or item.get("sourceIP")
                or item.get("address")
                or ""
            )
            name = str(hostname or srcip).strip()
            srcip = str(srcip or "").strip()
            if not srcip and name and _looks_like_ip(name):
                srcip = name
            if not name:
                continue
            key = srcip or name

            raw_ts = item.get("datetime") or item.get("timestamp") or item.get("firstContact") or item.get("lastContact")
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
                    first_contact=raw_ts or "",
                    last_contact=raw_ts or "",
                )
                merged_dts[key] = {"first": ts_dt, "last": ts_dt}
            else:
                if srcip and not merged[key].srcip:
                    merged[key].srcip = srcip
                if name and not merged[key].name:
                    merged[key].name = name
            if key in merged and ts_dt:
                if not merged_dts[key]["first"] or (ts_dt < merged_dts[key]["first"]):
                    merged_dts[key]["first"] = ts_dt
                    merged[key].first_contact = raw_ts
                if not merged_dts[key]["last"] or (ts_dt > merged_dts[key]["last"]):
                    merged_dts[key]["last"] = ts_dt
                    merged[key].last_contact = raw_ts
    return sorted(list(merged.values()), key=lambda x: x.name)


def _compact_structure(value: Any) -> Any:
    if isinstance(value, dict):
        compacted: Dict[str, Any] = {}
        for key, nested_value in value.items():
            nested_compacted = _compact_structure(nested_value)
            if nested_compacted in (None, {}, [], ""):
                continue
            compacted[key] = nested_compacted
        return compacted
    if isinstance(value, list):
        compacted_list = [_compact_structure(item) for item in value]
        return [item for item in compacted_list if item not in (None, {}, [], "")]
    if isinstance(value, str) and not value.strip():
        return None
    return value


def _normalize_activity_incident_details(secops_details: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(secops_details, dict):
        return {}
    return _compact_structure(
        {
            "incident_id": secops_details.get("id"),
            "description": secops_details.get("description"),
            "counts": secops_details.get("counts"),
            "offenders_samples": secops_details.get("offendersSamples"),
            "targets_samples": secops_details.get("targetsSamples"),
            "first_event": secops_details.get("firstEvent"),
            "last_event": secops_details.get("lastEvent"),
        }
    )


def _infer_os_from_user_agent(user_agent: str) -> Optional[str]:
    if not isinstance(user_agent, str) or not user_agent:
        return None
    if re.search(r"Windows NT", user_agent, re.IGNORECASE):
        return "Windows"
    if re.search(r"Mac OS X|Macintosh", user_agent, re.IGNORECASE):
        return "macOS"
    if re.search(r"Android", user_agent, re.IGNORECASE):
        return "Android"
    if re.search(r"iPhone|iPad|iOS", user_agent, re.IGNORECASE):
        return "iOS"
    if re.search(r"Linux", user_agent, re.IGNORECASE):
        return "Linux"
    return None


def _normalize_severity(value: str) -> Optional[str]:
    normalized = str(value or "").strip().lower()
    if normalized in {"low", "medium", "high"}:
        return normalized
    return None


def _coerce_count(value: Any) -> int:
    try:
        coerced = int(value)
        return coerced if coerced > 0 else 0
    except (TypeError, ValueError):
        return 0


def _merge_context_dicts(base: Dict[str, Any], incoming: Dict[str, Any]) -> Dict[str, Any]:
    merged = dict(base)
    for key, value in incoming.items():
        if key not in merged:
            merged[key] = value
            continue
        existing = merged[key]
        if isinstance(existing, dict) and isinstance(value, dict):
            merged[key] = _merge_context_dicts(existing, value)
        elif isinstance(existing, list) and isinstance(value, list):
            merged[key] = existing + [item for item in value if item not in existing]
        elif existing in (None, "", [], {}):
            merged[key] = value
    return merged


def _build_users_and_emails(raw_user: Any) -> tuple[List[str], List[str]]:
    users: List[str] = []
    emails: List[str] = []
    if isinstance(raw_user, str) and raw_user.strip():
        cleaned_user = raw_user.strip()
        users.append(cleaned_user)
        if re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", cleaned_user):
            emails.append(cleaned_user.lower())
    return (sorted(set(users)), sorted(set(emails)))


def _build_base_telemetry(event_detail: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "source_type": event_detail.get("sourceType"),
        "source_id": event_detail.get("sourceId"),
        "label": event_detail.get("label"),
        "from_playback": event_detail.get("fromPlayback"),
    }


def _event_detail_to_endpoint_context(event_detail: Dict[str, Any], incident_severity: str) -> Optional[Dict[str, Any]]:
    if not isinstance(event_detail, dict):
        return None

    endpoint_ip = event_detail.get("endpointIp") or event_detail.get("endpoint_ip")
    endpoint_name = event_detail.get("endpointName") or event_detail.get("endpoint_name") or endpoint_ip
    if not endpoint_ip and not endpoint_name:
        return None

    source_data = event_detail.get("sourceData") if isinstance(event_detail.get("sourceData"), dict) else {}
    incident_sev = _normalize_severity(incident_severity)
    context: Dict[str, Any] = {
        "endpoint_ip": endpoint_ip,
        "endpoint_name": endpoint_name,
    }

    proxy_info = source_data.get("ProxyEntryExtraInfo") if isinstance(source_data.get("ProxyEntryExtraInfo"), dict) else {}
    if proxy_info:
        request_data = proxy_info.get("request") if isinstance(proxy_info.get("request"), dict) else {}
        uri_data = request_data.get("uri") if isinstance(request_data.get("uri"), dict) else {}
        response_data = proxy_info.get("response") if isinstance(proxy_info.get("response"), dict) else {}
        extra_data = proxy_info.get("extraData") if isinstance(proxy_info.get("extraData"), dict) else {}
        users, emails = _build_users_and_emails(proxy_info.get("user"))
        if users:
            context["users"] = users
        if emails:
            context["emails"] = emails
        inferred_os = _infer_os_from_user_agent(request_data.get("user_agent", ""))
        if inferred_os:
            context["os"] = inferred_os

        http_data = _compact_structure(
            {
                "scheme": uri_data.get("scheme"),
                "host": uri_data.get("host") or event_detail.get("host"),
                "port": uri_data.get("port"),
                "path": uri_data.get("path") or event_detail.get("path"),
                "method": request_data.get("method"),
                "status_code": response_data.get("code"),
                "status_phrase": response_data.get("phrase"),
                "user_agent": request_data.get("user_agent"),
            }
        )
        if http_data:
            context["http"] = http_data

        network_data = _compact_structure(
            {
                "remote_ip": proxy_info.get("remoteIp"),
                "srcip": extra_data.get("srcip"),
                "src_country": extra_data.get("src_country"),
                "dst_country": extra_data.get("dst_country"),
            }
        )
        if network_data:
            context["network"] = network_data

        telemetry = _build_base_telemetry(event_detail)
        telemetry.update(
            {
                "traffic_type": extra_data.get("traffic_type"),
                "site": extra_data.get("site"),
                "app": extra_data.get("app"),
            }
        )
        activity_sev = _normalize_severity(extra_data.get("severity"))
        if incident_sev and activity_sev and incident_sev == activity_sev:
            telemetry["severity"] = activity_sev
        telemetry = _compact_structure(telemetry)
        if telemetry:
            context["telemetry"] = telemetry

    firewall_info = source_data.get("FirewallEntryExtraInfo") if isinstance(source_data.get("FirewallEntryExtraInfo"), dict) else {}
    if firewall_info:
        source_info = firewall_info.get("source") if isinstance(firewall_info.get("source"), dict) else {}
        destination_info = firewall_info.get("destination") if isinstance(firewall_info.get("destination"), dict) else {}
        extra_data = firewall_info.get("extraData") if isinstance(firewall_info.get("extraData"), dict) else {}

        http_data = _compact_structure(
            {
                "host": destination_info.get("name") or event_detail.get("host"),
                "path": event_detail.get("path"),
                "arguments": event_detail.get("arguments"),
            }
        )
        if http_data:
            context["http"] = _merge_context_dicts(context.get("http", {}), http_data)

        network_data = _compact_structure(
            {
                "source_ip": source_info.get("ip"),
                "source_port": source_info.get("port"),
                "destination_ip": destination_info.get("ip"),
                "destination_port": destination_info.get("port"),
                "destination_name": destination_info.get("name"),
            }
        )
        if network_data:
            context["network"] = _merge_context_dicts(context.get("network", {}), network_data)

        telemetry = _build_base_telemetry(event_detail)
        telemetry.update(
            {
                "action": firewall_info.get("action"),
                "protocol": firewall_info.get("protocol"),
                "service": extra_data.get("service"),
                "profile": extra_data.get("profile"),
                "device_name": extra_data.get("devname"),
                "subtype": extra_data.get("subtype"),
                "message": extra_data.get("msg"),
            }
        )
        telemetry = _compact_structure(telemetry)
        if telemetry:
            context["telemetry"] = _merge_context_dicts(context.get("telemetry", {}), telemetry)

    dns_info = source_data.get("DNSPacketExtraInfo") if isinstance(source_data.get("DNSPacketExtraInfo"), dict) else {}
    if dns_info:
        question = dns_info.get("question") if isinstance(dns_info.get("question"), dict) else {}
        network_data = _compact_structure(
            {
                "dns_question_name": question.get("name") or event_detail.get("host"),
                "dns_question_type": question.get("type"),
                "dns_question_class": question.get("class"),
                "dns_response_code": dns_info.get("responseCode"),
                "dns_answer_count": len(dns_info.get("answers", [])) if isinstance(dns_info.get("answers"), list) else None,
                "dns_op_code": dns_info.get("opCode"),
            }
        )
        if network_data:
            context["network"] = _merge_context_dicts(context.get("network", {}), network_data)

        telemetry = _compact_structure(_build_base_telemetry(event_detail))
        if telemetry:
            context["telemetry"] = _merge_context_dicts(context.get("telemetry", {}), telemetry)

    compact_context = _compact_structure(context)
    if set(compact_context.keys()).issubset({"endpoint_ip", "endpoint_name"}):
        return None
    meaningful_context_keys = set(compact_context.keys()) - {"endpoint_ip", "endpoint_name"}
    if meaningful_context_keys == {"telemetry"}:
        telemetry_keys = set(compact_context.get("telemetry", {}).keys())
        if telemetry_keys.issubset({"source_type", "source_id", "label", "from_playback"}):
            return None
    if not meaningful_context_keys:
        return None
    return compact_context


def _build_endpoint_context(event_details: List[Dict[str, Any]], incident_severity: str) -> List[Dict[str, Any]]:
    merged_contexts: Dict[str, Dict[str, Any]] = {}
    for event_detail in event_details:
        context = _event_detail_to_endpoint_context(event_detail, incident_severity)
        if not context:
            continue
        endpoint_key = str(context.get("endpoint_ip") or context.get("endpoint_name") or "").strip()
        if not endpoint_key:
            continue
        if endpoint_key not in merged_contexts:
            merged_contexts[endpoint_key] = context
        else:
            merged_contexts[endpoint_key] = _merge_context_dicts(merged_contexts[endpoint_key], context)
    return [_compact_structure(context) for context in merged_contexts.values()]


def build_incident_event(
    raw_incident: Dict[str, Any],
    bundle: IncidentSourceBundle,
    event_type: str,
) -> IncidentEvent:
    uuid = raw_incident.get("id") or raw_incident.get("uuid") or bundle.incident_uuid
    title = raw_incident.get("adversaryId") or raw_incident.get("description") or raw_incident.get("title") or "Untitled Incident"
    if len(title) > 120:
        title = title[:117] + "..."

    adv_types = raw_incident.get("adversaryTypes") or []
    adv_type = ", ".join(adv_types) if adv_types else "Unknown"
    adv_id = raw_incident.get("adversaryId", "")
    adversaries = raw_incident.get("adversaries") or []
    severity = raw_incident.get("severity", "High")
    status = raw_incident.get("status", "open")
    open_since = raw_incident.get("timestamp", "")
    first_contact = raw_incident.get("firstContact") or open_since
    last_contact = raw_incident.get("lastContact") or raw_incident.get("statusTimestamp", "")

    raw_contacts_count = raw_incident.get("contacts", 0)
    endpoints_count = _coerce_count(raw_incident.get("totalEndpoints"))
    if not endpoints_count:
        if isinstance(raw_contacts_count, list):
            endpoints_count = len(raw_contacts_count)
        else:
            endpoints_count = _coerce_count(raw_contacts_count)

    secops_details = bundle.secops_details or {}
    if not endpoints_count and isinstance(secops_details, dict):
        counts = secops_details.get("counts")
        if isinstance(counts, dict):
            endpoints_count = _coerce_count(counts.get("endpointTargetsCount"))

    stix = bundle.stix or {}
    objects = stix.get("objects", [])
    stix_indicators: List[StixIndicator] = []
    stix_malware: List[StixMalware] = []
    stix_sighting: Optional[StixSighting] = None
    tlp_value = "TLP: RED"
    for obj in objects:
        t = obj.get("type")
        if t == "marking-definition" and obj.get("definition_type") == "tlp":
            tlp_def = obj.get("definition", {}).get("tlp", "").upper()
            if tlp_def:
                tlp_value = f"TLP: {tlp_def}"
        elif t == "indicator":
            stix_indicators.append(
                StixIndicator(
                    name=obj.get("name", ""),
                    description=obj.get("description", ""),
                    pattern=obj.get("pattern", ""),
                    indicator_types=obj.get("indicator_types", []),
                    valid_from=obj.get("valid_from", ""),
                )
            )
        elif t == "malware":
            stix_malware.append(StixMalware(name=obj.get("name", ""), is_family=obj.get("is_family", False)))
        elif t == "sighting" and stix_sighting is None:
            stix_sighting = StixSighting(
                first_seen=obj.get("first_seen", ""),
                last_seen=obj.get("last_seen", ""),
                count=obj.get("count", 1),
            )

    mitre_techniques: List[MitreTechnique] = []
    extracted_iocs: List[ContextIOC] = []
    recommended_playbooks: List[ContextPlaybook] = []
    intelligence_tags: List[str] = []
    related_artifacts: Dict[str, List[str]] = {}
    summary = bundle.summary or {}
    if summary:
        add = summary.get("additional", {})
        for mt in add.get("mitre", []):
            mitre_techniques.append(
                MitreTechnique(
                    technique=mt.get("technique", ""),
                    description=mt.get("description", ""),
                    tactics=mt.get("tactics", []),
                    platforms=mt.get("platforms", []),
                    url=mt.get("references", [""])[0] if mt.get("references") else "",
                )
            )
        related_artifacts = add.get("related_artifacts", {})
        intelligence_tags = add.get("tags", [])
        for pb in summary.get("playbooks", []):
            recommended_playbooks.append(
                ContextPlaybook(
                    name=pb.get("name", ""),
                    description=pb.get("description", ""),
                    url=pb.get("url", ""),
                )
            )
        for ioc in summary.get("iocs", []):
            extracted_iocs.append(
                ContextIOC(
                    parsed_domain=ioc.get("parsed_domain", ""),
                    url=ioc.get("url", ""),
                    feed_name=ioc.get("feed_name", ""),
                    threat_detail=ioc.get("threat_detail", ""),
                )
            )

    intelligence_articles: List[ThreatIntelArticle] = []
    for art in bundle.articles or []:
        intelligence_articles.append(
            ThreatIntelArticle(
                title=art.get("title", ""),
                url=art.get("url", ""),
                description=art.get("description", ""),
                author=art.get("author", ""),
            )
        )

    det = bundle.defender_details or {}
    api_contacts_list = bundle.defender_contacts or []
    det_contacts = det.get("contacts", []) if det else []
    first_contact_details = det.get("firstContactDetails", {}) if det else {}
    last_contact_details = det.get("lastContactDetails", {}) if det else {}
    detail_contacts_list = det_contacts if isinstance(det_contacts, list) else []
    secops_targets: List[Dict[str, Any]] = []
    if isinstance(secops_details, dict):
        for target in secops_details.get("targetsSamples", []) or []:
            if not isinstance(target, dict):
                continue
            secops_targets.append(
                {
                    "endpointIp": target.get("endpoint_ip") or target.get("endpointIp"),
                    "endpointName": target.get("name") or target.get("endpoint_name"),
                }
            )

    sources = [
        api_contacts_list if isinstance(api_contacts_list, list) else [],
        detail_contacts_list,
        [first_contact_details] if first_contact_details else [],
        [last_contact_details] if last_contact_details else [],
        secops_targets,
    ]
    endpoint_breadth_sources: List[str] = []
    if api_contacts_list:
        endpoint_breadth_sources.append("defender_contacts")
    if detail_contacts_list:
        endpoint_breadth_sources.append("defender_details")
    if first_contact_details:
        endpoint_breadth_sources.append("firstContactDetails")
    if last_contact_details:
        endpoint_breadth_sources.append("lastContactDetails")
    if secops_targets:
        endpoint_breadth_sources.append("secops_targetsSamples")
    logger.debug(
        "Endpoint breadth sources incident=%s sources=%s",
        uuid,
        ",".join(endpoint_breadth_sources) or "none",
    )
    affected_endpoints = _merge_workstations(sources)

    disseminated = False
    triggered_integrations: List[str] = []
    dissemination_time = None
    mtt_dissemination = None
    mtt_response = None
    mtt_resolution = None
    if det:
        actions = det.get("actions", [])
        response_actions = [a for a in actions if a.get("action") == "response"]
        if response_actions:
            disseminated = True
            unique_integrations = set()
            first_resp_time = None
            for ra in response_actions:
                data = ra.get("data", {})
                ts = data.get("timestamp")
                if ts and (first_resp_time is None or ts < first_resp_time):
                    first_resp_time = ts
                int_type = data.get("integrationType")
                if int_type:
                    unique_integrations.add(int_type.replace("_", " ").title())
            triggered_integrations = sorted(list(unique_integrations))
            dissemination_time = first_resp_time
            mtt_dissemination = _calculate_latency(open_since, dissemination_time)
            mtt_response = _calculate_latency(first_contact, dissemination_time)

        close_action = next((a for a in actions if a.get("action") == "close"), None)
        if close_action:
            mtt_resolution = _calculate_latency(first_contact, close_action.get("datetime", ""))

    activity_incident_details = _normalize_activity_incident_details(secops_details)
    context_sources: List[Dict[str, Any]] = []
    if isinstance(api_contacts_list, list):
        context_sources.extend(row for row in api_contacts_list if isinstance(row, dict))
    if isinstance(detail_contacts_list, list):
        context_sources.extend(row for row in detail_contacts_list if isinstance(row, dict))
    if first_contact_details:
        context_sources.append(first_contact_details)
    if last_contact_details:
        context_sources.append(last_contact_details)
    if isinstance(bundle.activity_event_details, list):
        context_sources.extend(event_detail for event_detail in bundle.activity_event_details if isinstance(event_detail, dict))
    endpoint_context = _build_endpoint_context(context_sources, severity)
    if not endpoints_count:
        endpoints_count = len(affected_endpoints)

    return IncidentEvent(
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
        details=raw_incident.get("description", title),
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
        mtt_resolution=mtt_resolution,
        activity_incident_details=activity_incident_details,
        endpoint_context=endpoint_context,
    )
