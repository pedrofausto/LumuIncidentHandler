import asyncio
import logging
from datetime import timedelta, timezone
from urllib.parse import urlparse
from typing import Any, Dict, List

import httpx
from dateutil import parser

from .lumu_client import LumuSession, LumuEndpointCooldownException
from .models import IncidentSourceBundle

logger = logging.getLogger("lumu_monitor")


async def _safe_enrichment(label: str, incident_uuid: str, operation, default):
    try:
        return await operation
    except Exception as exc:
        logger.warning("%s enrichment failed for incident %s: %s", label, incident_uuid, exc)
        return default


def _coerce_count(value: Any) -> int:
    try:
        coerced = int(value)
        return coerced if coerced > 0 else 0
    except (TypeError, ValueError):
        return 0


def _normalize_endpoint_identity(value: Any) -> str:
    if not isinstance(value, str):
        return ""
    return value.strip().lower()


def _build_contact_identity_digest(*sources: Any) -> tuple[str, int]:
    identities: set[str] = set()
    for source in sources:
        if isinstance(source, list):
            rows = source
        elif isinstance(source, dict):
            rows = [source]
        else:
            continue
        for row in rows:
            if not isinstance(row, dict):
                continue
            for candidate in (
                row.get("endpointIp"),
                row.get("endpoint_ip"),
                row.get("ip"),
                row.get("ipAddress"),
                row.get("srcip"),
                row.get("endpointName"),
                row.get("name"),
                row.get("host"),
            ):
                normalized = _normalize_endpoint_identity(candidate)
                if normalized:
                    identities.add(normalized)
                    break
    return ("|".join(sorted(identities)), len(identities))


def _normalize_defender_context(context: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(context, dict):
        return {}
    related_artifacts: Dict[str, List[str]] = {}
    for key in ("sha256", "sha1", "md5"):
        value = context.get(key)
        if isinstance(value, list):
            cleaned = [item for item in value if isinstance(item, str) and item.strip()]
            if cleaned:
                related_artifacts[key] = cleaned
        elif isinstance(value, str) and value.strip():
            related_artifacts[key] = [value.strip()]

    playbooks = []
    for playbook_url in context.get("playbooks", []) or []:
        if isinstance(playbook_url, str) and playbook_url.strip():
            playbooks.append(
                {
                    "name": playbook_url.rstrip("/").split("/")[-1] or "playbook",
                    "description": "",
                    "url": playbook_url,
                }
            )

    iocs = []
    for trigger in context.get("threat_triggers", []) or []:
        if not isinstance(trigger, str) or not trigger.strip():
            continue
        parsed = urlparse(trigger)
        parsed_domain = parsed.hostname or trigger.replace("http://", "").replace("https://", "").split("/")[0]
        iocs.append(
            {
                "parsed_domain": parsed_domain,
                "url": trigger,
                "feed_name": "defender_context",
                "threat_detail": "; ".join(
                    item for item in context.get("threat_details", []) or [] if isinstance(item, str) and item.strip()
                ),
            }
        )

    mitre_details = []
    mitre = context.get("mitre", {})
    if isinstance(mitre, dict):
        for detail in mitre.get("details", []) or []:
            if not isinstance(detail, dict):
                continue
            technique = str(detail.get("technique") or detail.get("id") or "").strip()
            tactic = str(detail.get("tactic") or "").strip()
            if technique or tactic:
                mitre_details.append(
                    {
                        "technique": technique or tactic,
                        "description": "",
                        "tactics": [tactic] if tactic else [],
                        "platforms": [],
                        "references": [],
                    }
                )

    return {
        "additional": {
            "mitre": mitre_details,
            "related_artifacts": related_artifacts,
            "tags": [item for item in context.get("threat_details", []) or [] if isinstance(item, str) and item.strip()],
        },
        "playbooks": playbooks,
        "iocs": iocs,
    }


def _collect_endpoint_ids_from_details(details: Dict[str, Any], secops_details: Dict[str, Any]) -> set[str]:
    endpoint_ids: set[str] = set()

    def add_endpoint(value: Any) -> None:
        if isinstance(value, str) and value.strip():
            endpoint_ids.add(value.strip())

    if isinstance(details, dict):
        detail_contacts = details.get("contacts")
        if isinstance(detail_contacts, list):
            for row in detail_contacts:
                if not isinstance(row, dict):
                    continue
                add_endpoint(
                    row.get("endpointIp")
                    or row.get("ip")
                    or row.get("ipAddress")
                    or row.get("srcip")
                    or row.get("name")
                )
        for key in ("firstContactDetails", "lastContactDetails"):
            row = details.get(key)
            if isinstance(row, dict):
                add_endpoint(row.get("endpointIp") or row.get("endpointName") or row.get("name"))

    if isinstance(secops_details, dict):
        for row in secops_details.get("targetsSamples", []) or []:
            if not isinstance(row, dict):
                continue
            add_endpoint(row.get("endpoint_ip") or row.get("endpointIp") or row.get("name"))

    return endpoint_ids


def _extract_expected_endpoint_count(details: Dict[str, Any], secops_details: Dict[str, Any]) -> int:
    expected_endpoints = 0
    if isinstance(secops_details, dict):
        counts = secops_details.get("counts")
        if isinstance(counts, dict):
            expected_endpoints = _coerce_count(counts.get("endpointTargetsCount"))
    if expected_endpoints <= 0 and isinstance(details, dict):
        expected_endpoints = _coerce_count(
            details.get("totalEndpoints")
            or details.get("endpointsAffected")
            or details.get("contactsCount")
        )
    return expected_endpoints


def _record_has_contextual_signal(record: Dict[str, Any]) -> bool:
    if not isinstance(record, dict):
        return False
    if isinstance(record.get("sourceData"), dict) and record.get("sourceData"):
        return True
    for key in ("host", "path", "details", "sourceType", "sourceId", "response", "action"):
        value = record.get(key)
        if value not in (None, "", [], {}):
            return True
    return False


def _collect_contextual_endpoint_ids(details: Dict[str, Any]) -> set[str]:
    contextual_endpoint_ids: set[str] = set()

    def add_endpoint(record: Dict[str, Any]) -> None:
        if not _record_has_contextual_signal(record):
            return
        for candidate in (
            record.get("endpointIp"),
            record.get("endpoint_ip"),
            record.get("ip"),
            record.get("ipAddress"),
            record.get("srcip"),
            record.get("endpointName"),
            record.get("name"),
        ):
            if isinstance(candidate, str) and candidate.strip():
                contextual_endpoint_ids.add(candidate.strip())
                return

    if isinstance(details, dict):
        detail_contacts = details.get("contacts")
        if isinstance(detail_contacts, list):
            for row in detail_contacts:
                if isinstance(row, dict):
                    add_endpoint(row)
        for key in ("firstContactDetails", "lastContactDetails"):
            row = details.get(key)
            if isinstance(row, dict):
                add_endpoint(row)

    return contextual_endpoint_ids


def _collect_activity_event_ids(secops_details: Dict[str, Any]) -> List[str]:
    event_ids: List[str] = []
    seen_event_ids: set[str] = set()

    def add_event_id(value: Any) -> None:
        if not isinstance(value, str):
            return
        cleaned = value.strip()
        if cleaned and cleaned not in seen_event_ids:
            seen_event_ids.add(cleaned)
            event_ids.append(cleaned)

    def walk(value: Any, key_hint: str = "") -> None:
        normalized_hint = str(key_hint or "").strip().lower()
        if isinstance(value, dict):
            candidate_id = value.get("id")
            if "event" in normalized_hint and isinstance(candidate_id, str):
                add_event_id(candidate_id)
            for nested_key, nested_value in value.items():
                walk(nested_value, nested_key)
            return
        if isinstance(value, list):
            for item in value:
                walk(item, key_hint)

    if isinstance(secops_details, dict):
        walk(secops_details)

    return event_ids


def _parse_datetime(value: Any):
    if not value:
        return None
    try:
        parsed = parser.parse(str(value))
        if parsed.tzinfo is None:
            return parsed.replace(tzinfo=timezone.utc)
        return parsed
    except (TypeError, ValueError, OverflowError):
        return None


def _collect_incident_hosts(details: Dict[str, Any], secops_details: Dict[str, Any]) -> set[str]:
    hosts: set[str] = set()

    def add_host(value: Any) -> None:
        if isinstance(value, str) and value.strip():
            hosts.add(value.strip().lower())

    add_host(details.get("host"))
    for key in ("firstContactDetails", "lastContactDetails"):
        row = details.get(key)
        if isinstance(row, dict):
            add_host(row.get("host"))
    if isinstance(secops_details, dict):
        for offender in secops_details.get("offendersSamples", []) or []:
            if isinstance(offender, dict):
                add_host(offender.get("value") or offender.get("_id") or offender.get("name"))
    return hosts


def _collect_incident_details_text(details: Dict[str, Any], secops_details: Dict[str, Any]) -> set[str]:
    texts: set[str] = set()

    def add_text(value: Any) -> None:
        if isinstance(value, str) and value.strip():
            texts.add(value.strip().lower())
        elif isinstance(value, list):
            for item in value:
                add_text(item)

    add_text(details.get("details"))
    for key in ("firstContactDetails", "lastContactDetails"):
        row = details.get(key)
        if isinstance(row, dict):
            add_text(row.get("details"))
    if isinstance(secops_details, dict):
        add_text(secops_details.get("description"))
    return texts


def _collect_incident_types(details: Dict[str, Any], secops_details: Dict[str, Any]) -> set[str]:
    types: set[str] = set()

    def add_type(value: Any) -> None:
        if isinstance(value, str) and value.strip():
            types.add(value.strip().lower())
        elif isinstance(value, list):
            for item in value:
                add_type(item)

    add_type(details.get("types"))
    for key in ("firstContactDetails", "lastContactDetails"):
        row = details.get(key)
        if isinstance(row, dict):
            add_type(row.get("types"))
    if isinstance(secops_details, dict):
        add_type(secops_details.get("adversaryTypes"))
    return types


def _record_matches_incident(
    record: Dict[str, Any],
    endpoint_ip: str,
    incident_hosts: set[str],
    incident_detail_texts: set[str],
    incident_types: set[str],
    incident_time,
) -> bool:
    if not isinstance(record, dict):
        return False
    candidate_endpoint_ip = str(record.get("endpointIp") or record.get("endpoint_ip") or "").strip()
    if candidate_endpoint_ip != endpoint_ip:
        return False

    host = str(record.get("host") or "").strip().lower()
    detail_values = {
        str(value).strip().lower()
        for value in (record.get("details") or [])
        if isinstance(value, str) and value.strip()
    }
    type_values = {
        str(value).strip().lower()
        for value in (record.get("types") or [])
        if isinstance(value, str) and value.strip()
    }

    host_match = bool(host and host in incident_hosts)
    detail_match = bool(detail_values and detail_values.intersection(incident_detail_texts))
    type_match = bool(type_values and type_values.intersection(incident_types))

    if not (host_match or detail_match or type_match):
        return False

    record_dt = _parse_datetime(record.get("datetime"))
    if incident_time and record_dt:
        if abs(record_dt - incident_time) > timedelta(days=1):
            return False
    return True


async def fetch_incident_bundle(
    client: LumuSession,
    tenant_uuid: str,
    defender_key: str,
    incident_uuid: str,
    is_bootstrap_mode: bool = False,
    mode: str = "new",
    stored_contact_digest: str = "",
) -> IncidentSourceBundle:
    try:
        details_task = client.get_incident_details(defender_key, incident_uuid)
        context_task = client.get_incident_context(defender_key, incident_uuid)

        stix_task = None
        summary_task = None
        secops_details_task = None
        if mode == "new":
            stix_task = client.get_incident_stix(tenant_uuid, incident_uuid)
            summary_task = client.get_incident_context_summary(tenant_uuid, incident_uuid)
            secops_details_task = client.get_secops_incident_details(tenant_uuid, incident_uuid)

        details = await _safe_enrichment("details", incident_uuid, details_task, {})
        await asyncio.sleep(0.5)
        defender_context = await _safe_enrichment("defender context", incident_uuid, context_task, {})

        stix: Dict[str, Any] = {}
        summary: Dict[str, Any] = {}
        secops_details: Dict[str, Any] = {}
        if mode == "new":
            await asyncio.sleep(0.5)
            stix = await _safe_enrichment("STIX", incident_uuid, stix_task, {})
            await asyncio.sleep(0.5)
            summary = await _safe_enrichment("summary", incident_uuid, summary_task, {})
            await asyncio.sleep(0.5)
            secops_details = await _safe_enrichment("secops details", incident_uuid, secops_details_task, {})

            if not summary or not summary.get("additional"):
                summary = _normalize_defender_context(defender_context)
        else:
            summary = _normalize_defender_context(defender_context)

        contacts: List[Dict[str, Any]] = []
        detail_contacts = details.get("contacts") if isinstance(details, dict) else None
        detail_contacts_list = detail_contacts if isinstance(detail_contacts, list) else []
        detail_contact_digest, detail_endpoint_count = _build_contact_identity_digest(
            detail_contacts_list,
            details.get("firstContactDetails") if isinstance(details, dict) else {},
            details.get("lastContactDetails") if isinstance(details, dict) else {},
        )

        if mode == "new":
            expected_endpoints = _extract_expected_endpoint_count(details, secops_details)
            known_endpoint_ids = _collect_endpoint_ids_from_details(details, secops_details)
            contextual_endpoint_ids = _collect_contextual_endpoint_ids(details)
            has_sufficient_breadth = expected_endpoints > 0 and len(known_endpoint_ids) >= expected_endpoints
            has_sufficient_context = expected_endpoints > 0 and len(contextual_endpoint_ids) >= expected_endpoints
            should_fetch_contacts = (
                not detail_contacts_list
                or not has_sufficient_breadth
                or not has_sufficient_context
            )
        else:
            should_fetch_contacts = (
                stored_contact_digest
                and detail_contact_digest
                and detail_contact_digest != stored_contact_digest
            )

        if should_fetch_contacts:
            try:
                contacts = await client.get_incident_contacts(defender_key, incident_uuid)
            except httpx.HTTPStatusError as exc:
                if exc.response is not None and exc.response.status_code == 404:
                    logger.info(
                        "contacts enrichment unavailable tenant=%s incident=%s source=defender_contacts status=404",
                        tenant_uuid,
                        incident_uuid,
                    )
                else:
                    logger.warning("contacts enrichment failed for incident %s: %s", incident_uuid, exc)
            except LumuEndpointCooldownException as exc:
                logger.warning(
                    "contacts enrichment deferred incident=%s tenant=%s endpoint=%s reason=%s cooldown=%.2fs",
                    incident_uuid,
                    tenant_uuid,
                    exc.endpoint_name,
                    exc.reason_code,
                    exc.cooldown_remaining_seconds,
                )
            except Exception as exc:
                logger.warning("contacts enrichment failed for incident %s: %s", incident_uuid, exc)

        merged_digest, observed_endpoint_count = _build_contact_identity_digest(
            detail_contacts_list,
            contacts,
            details.get("firstContactDetails") if isinstance(details, dict) else {},
            details.get("lastContactDetails") if isinstance(details, dict) else {},
        )

        activity_event_details: List[Dict[str, Any]] = []
        endpoint_contacts_range: Dict[str, List[Dict[str, Any]]] = {}
        articles: List[Dict[str, Any]] = []

        if mode == "new":
            details_dict = details if isinstance(details, dict) else {}
            secops_dict = secops_details if isinstance(secops_details, dict) else {}
            incident_hosts = _collect_incident_hosts(details_dict, secops_dict)
            incident_detail_texts = _collect_incident_details_text(details_dict, secops_dict)
            incident_types = _collect_incident_types(details_dict, secops_dict)
            incident_time = _parse_datetime(
                secops_dict.get("timestamp") or details_dict.get("datetime")
            )
            target_samples = secops_dict.get("targetsSamples", []) if isinstance(secops_dict.get("targetsSamples", []), list) else []
            for target in target_samples:
                if not isinstance(target, dict):
                    continue
                endpoint_ip = str(target.get("endpoint_ip") or target.get("endpointIp") or "").strip()
                if not endpoint_ip:
                    continue
                try:
                    logger.debug(
                        "Querying contacts/range tenant=%s incident=%s endpoint_ip=%s",
                        tenant_uuid,
                        incident_uuid,
                        endpoint_ip,
                    )
                    contacts_range = await client.get_endpoint_contacts_range(
                        tenant_uuid,
                        endpoint_ip,
                        label=str(target.get("label") or target.get("environment") or "0"),
                        items=5,
                        page=1,
                    )
                    contacts_range_rows = contacts_range.get("contacts", []) if isinstance(contacts_range, dict) else []
                    accepted_rows = [
                        row for row in contacts_range_rows
                        if _record_matches_incident(
                            row,
                            endpoint_ip,
                            incident_hosts,
                            incident_detail_texts,
                            incident_types,
                            incident_time,
                        )
                    ]
                    if accepted_rows:
                        endpoint_contacts_range[endpoint_ip] = accepted_rows
                    logger.debug(
                        "contacts/range correlation tenant=%s incident=%s endpoint_ip=%s accepted=%s discarded=%s",
                        tenant_uuid,
                        incident_uuid,
                        endpoint_ip,
                        len(accepted_rows),
                        max(0, len(contacts_range_rows) - len(accepted_rows)),
                    )
                except httpx.HTTPStatusError as exc:
                    if exc.response is not None and exc.response.status_code == 404:
                        logger.info(
                            "contacts/range unavailable tenant=%s incident=%s endpoint_ip=%s status=404",
                            tenant_uuid,
                            incident_uuid,
                            endpoint_ip,
                        )
                    else:
                        logger.warning(
                            "contacts/range enrichment failed incident=%s endpoint_ip=%s reason=%s",
                            incident_uuid,
                            endpoint_ip,
                            exc,
                        )
                except Exception as exc:
                    logger.warning(
                        "contacts/range enrichment failed incident=%s endpoint_ip=%s reason=%s",
                        incident_uuid,
                        endpoint_ip,
                        exc,
                    )

            event_ids = _collect_activity_event_ids(secops_details)
            if not event_ids:
                logger.debug(
                    "Skipping managed activity event enrichment tenant=%s incident=%s reason=no_event_ids",
                    tenant_uuid,
                    incident_uuid,
                )
            for event_id in event_ids:
                await asyncio.sleep(0.5)
                try:
                    activity_event = await client.get_activity_event_details(tenant_uuid, event_id)
                    if isinstance(activity_event, dict) and activity_event:
                        activity_event_details.append(activity_event)
                except httpx.HTTPStatusError as exc:
                    if exc.response is not None and exc.response.status_code == 404:
                        logger.info(
                            "managed activity event unavailable tenant=%s incident=%s event_id=%s status=404",
                            tenant_uuid,
                            incident_uuid,
                            event_id,
                        )
                    else:
                        logger.warning(
                            "managed activity event enrichment failed incident=%s event_id=%s reason=%s",
                            incident_uuid,
                            event_id,
                            exc,
                        )
                except Exception as exc:
                    logger.warning(
                        "managed activity event enrichment failed incident=%s event_id=%s reason=%s",
                        incident_uuid,
                        event_id,
                        exc,
                    )

        return IncidentSourceBundle(
            incident_uuid=incident_uuid,
            tenant_uuid=tenant_uuid,
            defender_details=details if isinstance(details, dict) else {},
            defender_context=defender_context if isinstance(defender_context, dict) else {},
            defender_contacts=contacts if isinstance(contacts, list) else [],
            secops_details=secops_details if isinstance(secops_details, dict) else {},
            activity_event_details=activity_event_details,
            endpoint_contacts_range=endpoint_contacts_range,
            stix=stix if isinstance(stix, dict) else {},
            summary=summary if isinstance(summary, dict) else {},
            articles=articles if isinstance(articles, list) else [],
            contact_identity_digest=merged_digest,
            observed_endpoint_count=observed_endpoint_count or detail_endpoint_count,
        )
    except Exception as exc:
        logger.debug("Intelligence enrichment failed for incident %s: %s", incident_uuid, exc)
        return IncidentSourceBundle(
            incident_uuid=incident_uuid,
            tenant_uuid=tenant_uuid,
        )
