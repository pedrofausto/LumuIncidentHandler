import asyncio
import logging
from typing import Any, Dict, List

import httpx

from .lumu_client import LumuSession
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


async def fetch_incident_bundle(
    client: LumuSession,
    tenant_uuid: str,
    defender_key: str,
    incident_uuid: str,
    is_bootstrap_mode: bool = False,
) -> IncidentSourceBundle:
    try:
        details_task = client.get_incident_details(defender_key, incident_uuid)
        stix_task = client.get_incident_stix(tenant_uuid, incident_uuid)
        summary_task = client.get_incident_context_summary(tenant_uuid, incident_uuid)
        secops_details_task = client.get_secops_incident_details(tenant_uuid, incident_uuid)

        articles_task = None
        if not is_bootstrap_mode:
            articles_task = client.get_incident_external_articles(tenant_uuid, incident_uuid)

        stix = await _safe_enrichment("STIX", incident_uuid, stix_task, {})
        await asyncio.sleep(0.5)
        details = await _safe_enrichment("details", incident_uuid, details_task, {})
        await asyncio.sleep(0.5)
        summary = await _safe_enrichment("summary", incident_uuid, summary_task, {})
        await asyncio.sleep(0.5)
        secops_details = await _safe_enrichment("secops details", incident_uuid, secops_details_task, {})

        contacts: List[Dict[str, Any]] = []
        detail_contacts = details.get("contacts") if isinstance(details, dict) else None
        detail_contacts_list = detail_contacts if isinstance(detail_contacts, list) else []
        if detail_contacts_list:
            logger.debug(
                "Endpoint breadth source tenant=%s incident=%s source=defender_details contacts=%s",
                tenant_uuid,
                incident_uuid,
                len(detail_contacts_list),
            )
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
        if has_sufficient_breadth:
            logger.debug(
                "Defender details breadth tenant=%s incident=%s known=%s expected=%s contextual=%s",
                tenant_uuid,
                incident_uuid,
                len(known_endpoint_ids),
                expected_endpoints,
                len(contextual_endpoint_ids),
            )
        if should_fetch_contacts:
            try:
                contacts = await client.get_incident_contacts(defender_key, incident_uuid)
                logger.debug(
                    "Endpoint breadth source tenant=%s incident=%s source=defender_contacts contacts=%s",
                    tenant_uuid,
                    incident_uuid,
                    len(contacts),
                )
            except httpx.HTTPStatusError as exc:
                if exc.response is not None and exc.response.status_code == 404:
                    logger.info(
                        "contacts enrichment unavailable tenant=%s incident=%s source=defender_contacts status=404",
                        tenant_uuid,
                        incident_uuid,
                    )
                else:
                    logger.warning("contacts enrichment failed for incident %s: %s", incident_uuid, exc)
            except Exception as exc:
                logger.warning("contacts enrichment failed for incident %s: %s", incident_uuid, exc)

        activity_event_details: List[Dict[str, Any]] = []
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

        articles = []
        if articles_task:
            await asyncio.sleep(0.5)
            articles = await _safe_enrichment("external articles", incident_uuid, articles_task, [])

        return IncidentSourceBundle(
            incident_uuid=incident_uuid,
            tenant_uuid=tenant_uuid,
            defender_details=details if isinstance(details, dict) else {},
            defender_contacts=contacts if isinstance(contacts, list) else [],
            secops_details=secops_details if isinstance(secops_details, dict) else {},
            activity_event_details=activity_event_details,
            stix=stix if isinstance(stix, dict) else {},
            summary=summary if isinstance(summary, dict) else {},
            articles=articles if isinstance(articles, list) else [],
        )
    except Exception as exc:
        logger.debug("Intelligence enrichment failed for incident %s: %s", incident_uuid, exc)
        return IncidentSourceBundle(
            incident_uuid=incident_uuid,
            tenant_uuid=tenant_uuid,
        )
