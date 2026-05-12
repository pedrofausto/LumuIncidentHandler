import os
from dataclasses import dataclass
from datetime import datetime, timezone, timedelta
from typing import Any

import httpx
import pytest

from src.lumu_client import LumuSession


REQUIRED_ENV = [
    "LUMU_EMAIL",
    "LUMU_PASSWORD",
    "LUMU_MSSP_UUID",
    "CUSTOMER_UUID",
    "LUMU_DEFENDER_KEY",
]


@dataclass
class FieldCoverageResult:
    field: str
    exact_match: bool = False
    partial_match: bool = False
    missing_in_managed: bool = False
    only_in_managed: bool = False
    notes: str = ""


@dataclass
class IncidentCoverageSummary:
    incident_uuid: str
    coverage: list[FieldCoverageResult]


@dataclass
class CoverageReport:
    incidents: list[IncidentCoverageSummary]
    aggregate: dict[str, int]
    aggregate_percent_reusable: float
    blocker_fields: list[str]


def _missing_required_env() -> list[str]:
    return [name for name in REQUIRED_ENV if not os.getenv(name)]


def _sample_size() -> int:
    value = os.getenv("COMPARE_SAMPLE_SIZE", "5")
    try:
        parsed = int(value)
    except ValueError:
        parsed = 5
    return max(1, min(parsed, 20))


def _compare_from_date() -> str:
    provided = os.getenv("COMPARE_FROM_DATE")
    if provided:
        return provided
    return (datetime.now(timezone.utc) - timedelta(days=7)).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def _normalize_endpoint_record(item: dict[str, Any]) -> tuple[str, str, str, str]:
    host = str(
        item.get("endpointName")
        or item.get("hostname")
        or item.get("hostName")
        or item.get("name")
        or item.get("host")
        or item.get("deviceName")
        or item.get("endpointIp")
        or item.get("ip")
        or ""
    ).strip()
    srcip = str(
        item.get("endpointIp")
        or item.get("ip")
        or item.get("ipAddress")
        or item.get("srcip")
        or item.get("sourceIp")
        or item.get("sourceIP")
        or item.get("address")
        or ""
    ).strip()
    first = str(item.get("firstContact") or item.get("first_contact") or item.get("datetime") or item.get("timestamp") or "").strip()
    last = str(item.get("lastContact") or item.get("last_contact") or item.get("datetime") or item.get("timestamp") or "").strip()
    return (host, srcip, first, last)


def _collect_defender_endpoints(defender_details: dict[str, Any], defender_contacts: list[dict[str, Any]]) -> set[tuple[str, str, str, str]]:
    records: set[tuple[str, str, str, str]] = set()
    for item in defender_contacts:
        if isinstance(item, dict):
            records.add(_normalize_endpoint_record(item))
    det_contacts = defender_details.get("contacts", [])
    if not isinstance(det_contacts, list):
        det_contacts = []
    for item in det_contacts:
        if isinstance(item, dict):
            records.add(_normalize_endpoint_record(item))
    for key in ("firstContactDetails", "lastContactDetails"):
        item = defender_details.get(key, {})
        if isinstance(item, dict) and item:
            records.add(_normalize_endpoint_record(item))
    records.discard(("", "", "", ""))
    return records


def _collect_managed_endpoints(managed_details: dict[str, Any]) -> set[tuple[str, str, str, str]]:
    records: set[tuple[str, str, str, str]] = set()

    def walk(node: Any) -> None:
        if isinstance(node, dict):
            if any(k in node for k in ("endpointIp", "ip", "ipAddress", "sourceIp", "sourceIP", "endpointName", "hostname", "hostName")):
                records.add(_normalize_endpoint_record(node))
            for value in node.values():
                walk(value)
        elif isinstance(node, list):
            for value in node:
                walk(value)

    walk(managed_details)
    records.discard(("", "", "", ""))
    return records


def _collect_activity_endpoints(activity_details: dict[str, Any]) -> set[tuple[str, str, str, str]]:
    records: set[tuple[str, str, str, str]] = set()
    samples = activity_details.get("targetSamples", [])
    for sample in samples if isinstance(samples, list) else []:
        if isinstance(sample, dict):
            records.add(_normalize_endpoint_record(sample))
    records.discard(("", "", "", ""))
    return records


def _summarize_actions(actions: list[dict[str, Any]]) -> set[tuple[str, str]]:
    summary = set()
    if not isinstance(actions, list):
        return summary
    for action in actions:
        if not isinstance(action, dict):
            continue
        action_name = str(action.get("action") or "").strip().lower()
        ts = str(action.get("datetime") or action.get("timestamp") or action.get("data", {}).get("timestamp") or "").strip()
        if action_name or ts:
            summary.add((action_name, ts))
    return summary


def _coverage_bool(field: str, defender_has: bool, managed_has: bool, exact: bool = False, partial: bool = False, notes: str = "") -> FieldCoverageResult:
    return FieldCoverageResult(
        field=field,
        exact_match=exact and defender_has and managed_has,
        partial_match=partial and defender_has and managed_has and not exact,
        missing_in_managed=defender_has and not managed_has,
        only_in_managed=managed_has and not defender_has,
        notes=notes,
    )


def _build_incident_coverage(
    incident: dict[str, Any],
    defender_details: dict[str, Any],
    defender_contacts: list[dict[str, Any]],
    managed_details: dict[str, Any],
    activity_details: dict[str, Any],
) -> IncidentCoverageSummary:
    incident_uuid = str(incident.get("id") or incident.get("uuid") or "")

    defender_endpoints = _collect_defender_endpoints(defender_details, defender_contacts)
    managed_endpoints = _collect_managed_endpoints(managed_details)
    activity_endpoints = _collect_activity_endpoints(activity_details)
    managed_union_endpoints = managed_endpoints | activity_endpoints

    defender_actions = _summarize_actions(defender_details.get("actions", []))
    managed_actions = _summarize_actions(managed_details.get("actions", []))

    defender_status = str(incident.get("status") or "").strip().lower()
    managed_status = str(
        managed_details.get("status")
        or managed_details.get("incidentStatus")
        or activity_details.get("status")
        or activity_details.get("incidentStatus")
        or ""
    ).strip().lower()

    defender_last = str(incident.get("lastContact") or incident.get("statusTimestamp") or "").strip()
    managed_last = str(
        managed_details.get("lastContact")
        or managed_details.get("statusTimestamp")
        or managed_details.get("updatedAt")
        or managed_details.get("last_seen")
        or (managed_details.get("lastEvent", {}) if isinstance(managed_details.get("lastEvent", {}), dict) else {}).get("timestamp")
        or (activity_details.get("lastEvent", {}) if isinstance(activity_details.get("lastEvent", {}), dict) else {}).get("timestamp")
        or ""
    ).strip()

    defender_first = str(incident.get("firstContact") or incident.get("timestamp") or "").strip()
    managed_first = str(
        managed_details.get("firstContact")
        or managed_details.get("createdAt")
        or managed_details.get("first_seen")
        or (managed_details.get("firstEvent", {}) if isinstance(managed_details.get("firstEvent", {}), dict) else {}).get("timestamp")
        or (activity_details.get("firstEvent", {}) if isinstance(activity_details.get("firstEvent", {}), dict) else {}).get("timestamp")
        or ""
    ).strip()

    defender_endpoint_count = int(incident.get("totalEndpoints") or incident.get("contacts") or 0)
    counts = activity_details.get("counts", {}) if isinstance(activity_details.get("counts", {}), dict) else {}
    managed_count_from_counts = int(counts.get("totalTargetsCount") or counts.get("endpointTargetsCount") or 0)
    managed_endpoint_count = max(
        managed_count_from_counts,
        len({(host, ip) for host, ip, _, _ in managed_union_endpoints if host or ip}),
    )

    exact_endpoint_match = defender_endpoints == managed_union_endpoints and bool(defender_endpoints)
    partial_endpoint_match = bool(defender_endpoints & managed_union_endpoints) and not exact_endpoint_match

    exact_actions_match = defender_actions == managed_actions and bool(defender_actions)
    partial_actions_match = bool(defender_actions & managed_actions) and not exact_actions_match

    exact_metric_count = defender_endpoint_count == managed_endpoint_count and defender_endpoint_count > 0
    partial_metric_count = defender_endpoint_count > 0 and managed_endpoint_count > 0 and defender_endpoint_count != managed_endpoint_count

    coverage = [
        _coverage_bool("identity.incident_uuid", bool(incident_uuid), bool(incident_uuid), exact=bool(incident_uuid)),
        _coverage_bool("identity.company_id", bool(incident.get("companyId")), bool(managed_details.get("companyId")), exact=bool(incident.get("companyId")) and str(incident.get("companyId")) == str(managed_details.get("companyId"))),
        _coverage_bool("lifecycle.status", bool(defender_status), bool(managed_status), exact=bool(defender_status) and defender_status == managed_status),
        _coverage_bool("lifecycle.first_contact", bool(defender_first), bool(managed_first), exact=bool(defender_first) and defender_first == managed_first),
        _coverage_bool("lifecycle.last_contact", bool(defender_last), bool(managed_last), exact=bool(defender_last) and defender_last == managed_last),
        _coverage_bool("endpoint_metrics.total_affected", defender_endpoint_count > 0, managed_endpoint_count > 0, exact=exact_metric_count, partial=partial_metric_count, notes=f"defender={defender_endpoint_count} managed={managed_endpoint_count}"),
        _coverage_bool(
            "endpoint_records.host_ip_timestamps",
            bool(defender_endpoints),
            bool(managed_union_endpoints),
            exact=exact_endpoint_match,
            partial=partial_endpoint_match,
            notes=f"defender={len(defender_endpoints)} managed_union={len(managed_union_endpoints)} secops={len(managed_endpoints)} activity={len(activity_endpoints)}",
        ),
        _coverage_bool("response_actions.integration_timestamps", bool(defender_actions), bool(managed_actions), exact=exact_actions_match, partial=partial_actions_match, notes=f"defender={len(defender_actions)} managed={len(managed_actions)}"),
    ]

    return IncidentCoverageSummary(incident_uuid=incident_uuid, coverage=coverage)


def _aggregate_report(incident_summaries: list[IncidentCoverageSummary]) -> CoverageReport:
    aggregate = {
        "exact_match": 0,
        "partial_match": 0,
        "missing_in_managed": 0,
        "only_in_managed": 0,
    }
    field_missing_counter: dict[str, int] = {}
    total_defender_fields = 0
    reusable_fields = 0

    for summary in incident_summaries:
        for item in summary.coverage:
            aggregate["exact_match"] += int(item.exact_match)
            aggregate["partial_match"] += int(item.partial_match)
            aggregate["missing_in_managed"] += int(item.missing_in_managed)
            aggregate["only_in_managed"] += int(item.only_in_managed)

            defender_relevant = item.exact_match or item.partial_match or item.missing_in_managed
            if defender_relevant:
                total_defender_fields += 1
                reusable_fields += int(item.exact_match or item.partial_match)

            if item.missing_in_managed:
                field_missing_counter[item.field] = field_missing_counter.get(item.field, 0) + 1

    percent = 0.0
    if total_defender_fields > 0:
        percent = (reusable_fields / total_defender_fields) * 100.0

    blocker_fields = sorted([k for k, v in field_missing_counter.items() if v > 0])
    return CoverageReport(
        incidents=incident_summaries,
        aggregate=aggregate,
        aggregate_percent_reusable=percent,
        blocker_fields=blocker_fields,
    )


@pytest.fixture(scope="module")
def anyio_backend():
    return "asyncio"


@pytest.fixture(scope="module")
def _require_live_env() -> None:
    missing = _missing_required_env()
    if missing:
        pytest.skip(f"Skipping live Managed-vs-Defender comparison: missing env vars {', '.join(missing)}")


@pytest.fixture(scope="module")
async def live_coverage_report(_require_live_env) -> CoverageReport:
    company_uuid = os.getenv("CUSTOMER_UUID", "")
    company_key = os.getenv("LUMU_DEFENDER_KEY", "")
    from_date = _compare_from_date()
    sample_size = _sample_size()

    async with LumuSession() as client:
        await client.authenticate()

        baseline = await client.get_open_incidents(company_key=company_key, from_date=from_date)
        if not baseline:
            baseline = await client.get_all_incidents(company_key=company_key, from_date=from_date)

        candidates = [inc for inc in baseline if (inc.get("id") or inc.get("uuid"))]
        if not candidates:
            pytest.skip("No incidents found in Defender baseline for comparison.")

        sampled = candidates[:sample_size]
        summaries: list[IncidentCoverageSummary] = []

        for incident in sampled:
            incident_uuid = str(incident.get("id") or incident.get("uuid") or "")
            defender_details = await client.get_incident_details(company_key=company_key, incident_uuid=incident_uuid)
            try:
                defender_contacts = await client.get_incident_contacts(company_key=company_key, incident_uuid=incident_uuid)
            except httpx.HTTPStatusError as exc:
                if exc.response is not None and exc.response.status_code == 404:
                    defender_contacts = []
                else:
                    raise
            managed_details = await client.get_secops_incident_details(company_uuid=company_uuid, incident_uuid=incident_uuid)
            try:
                activity_details = await client.get_with_auth(
                    f"/data-api/companies/{company_uuid}/activity/incidents/{incident_uuid}/details"
                )
            except httpx.HTTPStatusError as exc:
                if exc.response is not None and exc.response.status_code == 404:
                    activity_details = {}
                else:
                    raise
            summaries.append(
                _build_incident_coverage(
                    incident=incident,
                    defender_details=defender_details if isinstance(defender_details, dict) else {},
                    defender_contacts=defender_contacts if isinstance(defender_contacts, list) else [],
                    managed_details=managed_details if isinstance(managed_details, dict) else {},
                    activity_details=activity_details if isinstance(activity_details, dict) else {},
                )
            )

    report = _aggregate_report(summaries)

    print("\n=== Managed-vs-Defender Coverage (per incident) ===")
    for summary in report.incidents:
        print(f"incident={summary.incident_uuid}")
        for row in summary.coverage:
            print(
                f"  {row.field}: exact={row.exact_match} partial={row.partial_match} "
                f"missing_in_managed={row.missing_in_managed} only_in_managed={row.only_in_managed} notes={row.notes}"
            )
    print("=== Aggregate ===")
    print(f"aggregate={report.aggregate}")
    print(f"reusable_percent={report.aggregate_percent_reusable:.2f}")
    print(f"blocker_fields={report.blocker_fields}")

    return report


@pytest.mark.integration
@pytest.mark.live
@pytest.mark.anyio
async def test_managed_secops_endpoint_reachable_for_sample_incidents(live_coverage_report: CoverageReport):
    assert len(live_coverage_report.incidents) > 0
    for item in live_coverage_report.incidents:
        assert item.incident_uuid


@pytest.mark.integration
@pytest.mark.live
@pytest.mark.anyio
async def test_field_coverage_managed_vs_defender_per_incident(live_coverage_report: CoverageReport):
    required_groups = {
        "identity.incident_uuid",
        "identity.company_id",
        "lifecycle.status",
        "lifecycle.first_contact",
        "lifecycle.last_contact",
        "endpoint_metrics.total_affected",
        "endpoint_records.host_ip_timestamps",
        "response_actions.integration_timestamps",
    }
    for summary in live_coverage_report.incidents:
        fields = {row.field for row in summary.coverage}
        assert required_groups.issubset(fields)


@pytest.mark.integration
@pytest.mark.live
@pytest.mark.anyio
async def test_endpoint_host_ip_reuse_coverage(live_coverage_report: CoverageReport):
    endpoint_rows = []
    for summary in live_coverage_report.incidents:
        for row in summary.coverage:
            if row.field == "endpoint_records.host_ip_timestamps":
                endpoint_rows.append(row)
    assert endpoint_rows, "Expected endpoint coverage rows"
    assert any(r.exact_match or r.partial_match or r.missing_in_managed for r in endpoint_rows)


@pytest.mark.integration
@pytest.mark.live
@pytest.mark.anyio
async def test_lifecycle_and_actions_reuse_coverage(live_coverage_report: CoverageReport):
    lifecycle_rows = []
    action_rows = []
    for summary in live_coverage_report.incidents:
        for row in summary.coverage:
            if row.field.startswith("lifecycle."):
                lifecycle_rows.append(row)
            if row.field == "response_actions.integration_timestamps":
                action_rows.append(row)
    assert lifecycle_rows, "Expected lifecycle coverage rows"
    assert action_rows, "Expected action coverage rows"


@pytest.mark.integration
@pytest.mark.live
@pytest.mark.anyio
async def test_aggregate_reuse_report_emits_blockers(live_coverage_report: CoverageReport):
    aggregate = live_coverage_report.aggregate
    assert set(aggregate.keys()) == {"exact_match", "partial_match", "missing_in_managed", "only_in_managed"}
    assert live_coverage_report.aggregate_percent_reusable >= 0.0
    assert live_coverage_report.aggregate_percent_reusable <= 100.0
    assert isinstance(live_coverage_report.blocker_fields, list)
