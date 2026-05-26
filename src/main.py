import asyncio
import dataclasses
import logging
import random
import socket
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

import httpx

from .analyzer import Analyzer
from .config import get_settings
from .enrichment_fetcher import fetch_incident_bundle
from .incident_builder import build_incident_event
from .kafka_client import KafkaClient
from .lumu_client import LumuSession
from .payload_serializer import normalize_customer_topic, serialize_incident_event
from .rate_policy import resolve_rate_policy_from_settings

logging.basicConfig(
    stream=sys.stdout,
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logging.getLogger("httpx").setLevel(logging.WARNING)
logger = logging.getLogger("lumu_monitor")


@dataclasses.dataclass
class TenantRuntime:
    tenant_uuid: str
    tenant_name: str
    defender_api_key: str
    kafka_topic: str


@dataclasses.dataclass
class JournalSyncResult:
    processed_count: int = 0
    success_count: int = 0
    failure_count: int = 0
    offset_advanced: bool = False
    offset_missing: bool = False
    request_failed: bool = False
    updates_seen: bool = False
    skipped_by_rate_guard: bool = False
    skip_reason: str | None = None
    skip_cooldown_seconds: float = 0.0


@dataclasses.dataclass
class OpenSnapshotResult:
    processed_count: int = 0
    success_count: int = 0
    failure_count: int = 0
    request_failed: bool = False


def get_agent_id() -> str:
    data_dir = Path(__file__).resolve().parent.parent / "data"
    data_dir.mkdir(parents=True, exist_ok=True)
    agent_id_file = data_dir / "agent_id"

    if agent_id_file.exists():
        existing = agent_id_file.read_text(encoding="utf-8").strip()
        if existing:
            return existing

    generated = str(uuid.uuid4())
    agent_id_file.write_text(generated, encoding="utf-8")
    return generated


def get_primary_host_ip() -> str:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect(("8.8.8.8", 80))
        return sock.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        sock.close()


def shape_kafka_payload(
    event_dict: Dict[str, Any],
    tenant_uuid: str,
    tenant_name: str,
    settings,
    hostname: str,
    agent_id: str,
    agent_ip: str,
) -> Dict[str, Any]:
    return serialize_incident_event(
        event_dict=event_dict,
        tenant_uuid=tenant_uuid,
        tenant_name=tenant_name,
        settings=settings,
        hostname=hostname,
        agent_id=agent_id,
        agent_ip=agent_ip,
    )


async def enrich_incident(
    client: LumuSession,
    tenant_uuid: str,
    company_key: str,
    inc_uuid: str,
    is_bootstrap_mode: bool = False,
    mode: str = "new",
    stored_contact_digest: str = "",
):
    return await fetch_incident_bundle(
        client=client,
        tenant_uuid=tenant_uuid,
        defender_key=company_key,
        incident_uuid=inc_uuid,
        is_bootstrap_mode=is_bootstrap_mode,
        mode=mode,
        stored_contact_digest=stored_contact_digest,
    )


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _is_429_http_error(exc: Exception) -> bool:
    return isinstance(exc, httpx.HTTPStatusError) and exc.response is not None and exc.response.status_code == 429


def _compute_tenant_cycle_jitter_seconds(max_seconds: int) -> float:
    if max_seconds <= 0:
        return 0.0
    return random.uniform(0.0, float(max_seconds))


async def run_journal_sync(
    client: LumuSession,
    analyzer: Analyzer,
    kafka: KafkaClient,
    tenant_uuid: str,
    tenant_name: str,
    company_key: str,
    kafka_topic: str,
) -> JournalSyncResult:
    result = JournalSyncResult()
    settings = get_settings()
    policy = resolve_rate_policy_from_settings(settings)
    items_per_page = policy.journal_items_per_page
    max_items_per_page = policy.journal_items_per_page
    delay_time_seconds = policy.journal_delay_time_seconds
    max_pages_per_cycle = policy.journal_max_pages_per_cycle
    if getattr(client, "is_defender_near_daily_cap", None) and client.is_defender_near_daily_cap(company_key, threshold=0.85):
        delay_time_seconds = max(delay_time_seconds, 30)
        max_pages_per_cycle = min(max_pages_per_cycle, 1)
        if getattr(client, "get_defender_budget_snapshot", None):
            budget = client.get_defender_budget_snapshot(company_key)
            logger.warning(
                "Near Defender daily cap in journal mode tenant=%s minute=%s/%s day=%s/%s using_delay=%ss pages_cap=%s",
                tenant_uuid,
                budget["minute_count"],
                budget["minute_limit"],
                budget["day_count"],
                budget["day_limit"],
                delay_time_seconds,
                max_pages_per_cycle,
            )
    pages_processed = 0

    while pages_processed < max_pages_per_cycle:
        previous_offset = analyzer.offset
        pre_batch_hits = client.rate_limit_hits
        current_items_per_page = items_per_page
        try:
            updates_data = await client.get_incident_updates(
                company_key,
                offset=analyzer.offset,
                items=current_items_per_page,
                delay_time=delay_time_seconds,
            )
        except Exception as exc:
            logger.warning(
                "Journal sync request failed tenant=%s tenant_name=%s offset=%s reason=%s",
                tenant_uuid,
                tenant_name,
                previous_offset,
                exc,
            )
            result.request_failed = True
            break
        pages_processed += 1

        updates_list = updates_data.get("updates", [])
        new_offset = updates_data.get("offset")
        if updates_data.get("_rate_guard_skipped"):
            result.skipped_by_rate_guard = True
            result.skip_reason = updates_data.get("_rate_guard_reason") or "rate_guard_skip"
            result.skip_cooldown_seconds = float(updates_data.get("_rate_guard_cooldown_seconds") or 0.0)
            logger.info(
                "Journal polling skipped by rate guard tenant=%s reason=%s cooldown_remaining=%.2fs",
                tenant_uuid,
                result.skip_reason,
                result.skip_cooldown_seconds,
            )
            break

        if not updates_list:
            logger.info("No new incident journal updates for tenant '%s'.", tenant_name)
            if new_offset is not None:
                if new_offset != previous_offset:
                    result.offset_advanced = True
                analyzer.offset = new_offset
                analyzer._save_state()
            else:
                result.offset_missing = True
                logger.warning(
                    "Journal updates returned no offset tenant=%s previous_offset=%s; stopping cycle",
                    tenant_uuid,
                    previous_offset,
                )
            break

        result.updates_seen = True
        logger.info("Retrieved %s journal update event(s). Processing...", len(updates_list))

        is_bootstrap_mode = len(updates_list) >= current_items_per_page
        if is_bootstrap_mode:
            logger.debug("High backlog detected (>= %s updates). Deep enrichments will be skipped.", current_items_per_page)

        raw_incidents = [
            incident
            for incident in analyzer.extract_incidents_from_updates(updates_list)
            if analyzer.has_seen_incident((incident.get("id") or incident.get("uuid") or ""))
        ]
        for incident in raw_incidents:
            incident["_sync_mode"] = "update"
            incident["_stored_contact_digest"] = analyzer.get_contact_digest(incident.get("id") or incident.get("uuid") or "")
        result.processed_count += len(raw_incidents)

        if raw_incidents:
            success, failed = await process_and_send_batch(
                client,
                analyzer,
                kafka,
                raw_incidents,
                tenant_uuid,
                tenant_name,
                company_key,
                kafka_topic,
                is_bootstrap_mode=is_bootstrap_mode,
            )
            result.success_count += success
            result.failure_count += failed
        else:
            logger.info("No incident-related updates in this journal batch.")

        if new_offset is None:
            result.offset_missing = True
            logger.warning(
                "Journal updates returned null offset tenant=%s previous_offset=%s; stopping cycle",
                tenant_uuid,
                previous_offset,
            )
            break

        if new_offset == previous_offset:
            logger.warning(
                "Journal offset did not advance tenant=%s offset=%s; stopping cycle to prevent infinite loop",
                tenant_uuid,
                previous_offset,
            )
            break

        result.offset_advanced = True
        analyzer.offset = new_offset
        analyzer._save_state()

        post_batch_hits = client.rate_limit_hits
        if post_batch_hits > pre_batch_hits:
            items_per_page = max(5, int(current_items_per_page / 2))
            logger.warning("Rate-limit pressure detected. Shrinking batch size to %s.", items_per_page)
        else:
            items_per_page = min(max_items_per_page, current_items_per_page + 5)

        if len(updates_list) < current_items_per_page:
            break

    if pages_processed >= max_pages_per_cycle:
        logger.info(
            "Journal page cap reached tenant=%s pages=%s max_pages_per_cycle=%s",
            tenant_uuid,
            pages_processed,
            max_pages_per_cycle,
        )

    return result


async def run_open_snapshot_sync(
    client: LumuSession,
    analyzer: Analyzer,
    kafka: KafkaClient,
    tenant_uuid: str,
    tenant_name: str,
    company_key: str,
    kafka_topic: str,
) -> OpenSnapshotResult:
    result = OpenSnapshotResult()
    try:
        open_incidents = await client.get_open_incidents(company_key, from_date=None)
        candidates = []
        for incident in open_incidents:
            incident_uuid = incident.get("id") or incident.get("uuid") or ""
            if not incident_uuid:
                continue
            if not analyzer.should_process_incident(incident):
                continue
            incident = dict(incident)
            incident["_sync_mode"] = "new" if not analyzer.has_seen_incident(incident_uuid) else "update"
            incident["_stored_contact_digest"] = analyzer.get_contact_digest(incident_uuid)
            candidates.append(incident)
        result.processed_count = len(candidates)
        if not candidates:
            logger.info("Open snapshot found no new or changed incidents for tenant '%s'.", tenant_name)
            return result
        near_cap = False
        if getattr(client, "is_defender_near_daily_cap", None) and client.is_defender_near_daily_cap(company_key, threshold=0.85):
            near_cap = True
            if getattr(client, "get_defender_budget_snapshot", None):
                budget = client.get_defender_budget_snapshot(company_key)
                logger.warning(
                    "Near Defender daily cap in snapshot mode tenant=%s minute=%s/%s day=%s/%s forcing bootstrap mode (skipping deep enrichments)",
                    tenant_uuid,
                    budget["minute_count"],
                    budget["minute_limit"],
                    budget["day_count"],
                    budget["day_limit"],
                )
            else:
                logger.warning("Near Defender daily cap in snapshot mode tenant=%s forcing bootstrap mode (skipping deep enrichments)", tenant_uuid)

        success, failed = await process_and_send_batch(
            client=client,
            analyzer=analyzer,
            kafka=kafka,
            raw_incidents=candidates,
            tenant_uuid=tenant_uuid,
            tenant_name=tenant_name,
            company_key=company_key,
            kafka_topic=kafka_topic,
            is_bootstrap_mode=near_cap,
        )
        result.success_count = success
        result.failure_count = failed
        return result
    except Exception as exc:
        logger.warning(
            "Open snapshot sync failed tenant=%s tenant_name=%s reason=%s",
            tenant_uuid,
            tenant_name,
            exc,
        )
        result.request_failed = True
        return result





async def monitor_tenant(
    client: LumuSession,
    analyzer: Analyzer,
    kafka: KafkaClient,
    tenant_uuid: str,
    tenant_name: str,
    company_key: str,
    kafka_topic: str,
):
    """
    Monitors a single tenant using an open-snapshot-first strategy with supplemental journal updates.
    """
    logger.info("Scanning security incidents for tenant '%s' (%s)...", tenant_name, tenant_uuid)
    publish_success_count = 0
    publish_failure_count = 0
    reconciliation_reason = "snapshot_primary"
    try:
        if not company_key:
            logger.warning("LUMU_DEFENDER_KEY is not set. Skipping incident scan.")
            return

        snapshot_result = await run_open_snapshot_sync(
            client=client,
            analyzer=analyzer,
            kafka=kafka,
            tenant_uuid=tenant_uuid,
            tenant_name=tenant_name,
            company_key=company_key,
            kafka_topic=kafka_topic,
        )
        publish_success_count += snapshot_result.success_count
        publish_failure_count += snapshot_result.failure_count

        journal_result = await run_journal_sync(
            client=client,
            analyzer=analyzer,
            kafka=kafka,
            tenant_uuid=tenant_uuid,
            tenant_name=tenant_name,
            company_key=company_key,
            kafka_topic=kafka_topic,
        )
        publish_success_count += journal_result.success_count
        publish_failure_count += journal_result.failure_count
        if journal_result.skipped_by_rate_guard:
            reconciliation_reason = journal_result.skip_reason or "journal_rate_guard_skip"
            logger.info(
                "Skipping same-cycle open-state reconciliation tenant=%s reason=%s because open snapshot is primary",
                tenant_uuid,
                reconciliation_reason,
            )

    except Exception as e:
        logger.error(f"Error processing incidents for tenant {tenant_uuid}: {str(e)}")
    finally:
        logger.info(
            "Cycle publish summary tenant=%s success=%s failed=%s snapshot_processed=%s journal_processed=%s reconciliation=%s next_due=%s",
            tenant_uuid,
            publish_success_count,
            publish_failure_count,
            snapshot_result.processed_count if 'snapshot_result' in locals() else 0,
            journal_result.processed_count if 'journal_result' in locals() else 0,
            reconciliation_reason,
            analyzer.open_state_sync_next_due_at or "unscheduled",
        )


async def process_and_send_batch(
    client: LumuSession,
    analyzer: Analyzer,
    kafka: KafkaClient,
    raw_incidents: List[Dict[str, Any]],
    tenant_uuid: str,
    tenant_name: str,
    company_key: str,
    kafka_topic: str,
    is_bootstrap_mode: bool = False
)-> tuple[int, int]:
    """
    Enriches raw incidents and streams them to Kafka as they complete.
    """
    settings = get_settings()
    hostname = socket.gethostname()
    agent_id = get_agent_id()
    agent_ip = get_primary_host_ip()

    uuid_to_raw = {}
    for inc in raw_incidents:
        uid = inc.get('uuid') or inc.get('id')
        if uid:
            uuid_to_raw[uid] = inc

    if not uuid_to_raw:
        return (0, 0)

    semaphore = asyncio.Semaphore(2)

    async def sem_enrich(inc_uuid):
        async with semaphore:
            raw_inc = uuid_to_raw.get(inc_uuid) or {}
            result = await fetch_incident_bundle(
                client=client,
                tenant_uuid=tenant_uuid,
                defender_key=company_key,
                incident_uuid=inc_uuid,
                is_bootstrap_mode=is_bootstrap_mode,
                mode=str(raw_inc.get("_sync_mode") or "new"),
                stored_contact_digest=str(raw_inc.get("_stored_contact_digest") or ""),
            )
            await asyncio.sleep(1.0)
            return result

    unique_uuids = list(uuid_to_raw.keys())
    tasks = [sem_enrich(uuid) for uuid in unique_uuids]

    logger.info(f"Enriching and streaming {len(unique_uuids)} incident(s) for '{tenant_name}'...")
    success_count = 0
    failure_count = 0

    for finished_task in asyncio.as_completed(tasks):
        try:
            bundle = await finished_task
            inc_uuid = bundle.incident_uuid
            raw_inc = uuid_to_raw.get(inc_uuid)

            if not raw_inc:
                continue

            event_type = analyzer.classify_incident_event_type(raw_inc)
            mapped_events = [
                build_incident_event(
                    raw_incident=raw_inc,
                    bundle=bundle,
                    event_type=event_type,
                )
            ]

            for event in mapped_events:
                try:
                    event_dict = dataclasses.asdict(event)
                    event_dict["customer_name"] = tenant_name
                    event_dict["customer_uuid"] = tenant_uuid
                    event_dict = serialize_incident_event(
                        event_dict=event_dict,
                        tenant_uuid=tenant_uuid,
                        tenant_name=tenant_name,
                        settings=settings,
                        hostname=hostname,
                        agent_id=agent_id,
                        agent_ip=agent_ip,
                    )

                    await kafka.send_incident(event_dict, topic=kafka_topic)
                    success_count += 1
                    incident_times = getattr(analyzer, "_incident_times", {}) or {}
                    stored_ts = incident_times.get(event.incident_uuid, "")
                    normalize_timestamp = getattr(analyzer, "_normalize_timestamp", lambda value: value)
                    compare_timestamps = getattr(analyzer, "_compare_timestamps", lambda _candidate, _stored: None)
                    logger.debug(
                        "Incident decision incident_uuid=%s chosen_last_contact=%s stored_state_timestamp=%s source=%s comparison_result=%s decision=send",
                        event.incident_uuid,
                        event.last_contact,
                        normalize_timestamp(stored_ts) if stored_ts else stored_ts,
                        getattr(event, "last_contact_source", "unknown"),
                        compare_timestamps(event.last_contact, stored_ts) if stored_ts else "missing_state",
                    )
                    logger.info(
                        "Incident publish success tenant_uuid=%s tenant_name=%s incident_uuid=%s topic=%s",
                        tenant_uuid,
                        tenant_name,
                        event.incident_uuid,
                        kafka_topic,
                    )

                    analyzer.update_incident_time(
                        event.incident_uuid,
                        event.last_contact,
                        contact_digest=bundle.contact_identity_digest,
                        observed_endpoint_count=bundle.observed_endpoint_count,
                        status=event.status,
                    )
                except Exception as e:
                    failure_count += 1
                    logger.error(
                        "Failed to send incident incident_uuid=%s topic=%s reason=%s delivery_timeout=%ss",
                        event.incident_uuid,
                        kafka_topic,
                        e,
                        settings.kafka_delivery_timeout_seconds,
                    )

        except Exception as e:
            logger.error(f"Streaming error for an incident task: {e}")
            failure_count += 1
    return (success_count, failure_count)


async def run_tenant_batch(
    client: LumuSession,
    kafka: KafkaClient,
    analyzers_by_tenant: Dict[str, Analyzer],
    tenant_registry: Dict[str, TenantRuntime],
    settings,
) -> None:
    policy = resolve_rate_policy_from_settings(settings)
    semaphore = asyncio.Semaphore(policy.tenant_concurrency_cap)
    runtime_items = list(tenant_registry.items())

    async def run_tenant_with_cap(runtime: TenantRuntime) -> None:
        jitter_seconds = _compute_tenant_cycle_jitter_seconds(policy.tenant_cycle_jitter_max_seconds)
        logger.debug(
            "Tenant queued tenant_uuid=%s tenant_name=%s jitter=%.2fs",
            runtime.tenant_uuid,
            runtime.tenant_name,
            jitter_seconds,
        )
        async with semaphore:
            started = time.monotonic()
            logger.debug(
                "Tenant slot acquired tenant_uuid=%s tenant_name=%s",
                runtime.tenant_uuid,
                runtime.tenant_name,
            )
            if jitter_seconds > 0:
                await asyncio.sleep(jitter_seconds)
            analyzer = analyzers_by_tenant.setdefault(runtime.tenant_uuid, Analyzer(state_file_key=runtime.tenant_uuid))
            await monitor_tenant(
                client=client,
                analyzer=analyzer,
                kafka=kafka,
                tenant_uuid=runtime.tenant_uuid,
                tenant_name=runtime.tenant_name,
                company_key=runtime.defender_api_key,
                kafka_topic=runtime.kafka_topic,
            )
            elapsed = time.monotonic() - started
            logger.debug(
                "Tenant slot released tenant_uuid=%s tenant_name=%s elapsed=%.2fs",
                runtime.tenant_uuid,
                runtime.tenant_name,
                elapsed,
            )

    tasks = [asyncio.create_task(run_tenant_with_cap(runtime)) for _tenant_uuid, runtime in runtime_items]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    for (tenant_uuid, runtime), result in zip(runtime_items, results):
        if isinstance(result, Exception):
            logger.error(
                "Tenant cycle failed tenant_uuid=%s tenant_name=%s reason=%s",
                tenant_uuid,
                runtime.tenant_name,
                result,
            )


async def run_loop():
    settings = get_settings()
    policy = resolve_rate_policy_from_settings(settings)
    interval_seconds = settings.polling_interval_minutes * 60
    analyzers_by_tenant: Dict[str, Analyzer] = {}
    tenant_registry: Dict[str, TenantRuntime] = {}

    logger.info("Lumu Incident Handler started.")
    logger.info(
        "Kafka runtime config bootstrap=%s delivery_timeout=%ss flush_timeout=%ss",
        settings.kafka_bootstrap_servers,
        settings.kafka_delivery_timeout_seconds,
        settings.kafka_flush_timeout_seconds,
    )
    logger.info(
        "Defender budget config enforce=%s minute_limit=%s day_limit=%s journal_items=%s journal_delay=%ss journal_pages_cap=%s",
        policy.defender_budget_enforce,
        policy.defender_budget_minute_limit,
        policy.defender_budget_day_limit,
        policy.journal_items_per_page,
        policy.journal_delay_time_seconds,
        policy.journal_max_pages_per_cycle,
    )
    logger.info(
        "Tenant scheduler config concurrency_cap=%s cycle_jitter_max_seconds=%s",
        policy.tenant_concurrency_cap,
        policy.tenant_cycle_jitter_max_seconds,
    )

    try:
        async with LumuSession() as client, KafkaClient() as kafka:
            await client.authenticate()
            logger.info("Bootstrapping multi-tenant Defender key cache...")

            async def refresh_tenant_registry(force_full: bool = False) -> None:
                tenants = await client.get_tenants(items=500, page=1)
                logger.info("Discovered %s supervised tenant(s).", len(tenants))
                discovered_uuids: set[str] = set()
                key_fetch_success = 0
                key_fetch_failed = 0

                for tenant in tenants:
                    tenant_uuid = str(tenant.get("uuid") or "").strip()
                    tenant_name = str(tenant.get("name") or "").strip() or "unknown"
                    if not tenant_uuid:
                        continue
                    discovered_uuids.add(tenant_uuid)

                    topic = normalize_customer_topic(tenant_name)
                    if not topic:
                        key_fetch_failed += 1
                        logger.error(
                            "Skipping tenant due to invalid normalized topic tenant_uuid=%s tenant_name=%s",
                            tenant_uuid,
                            tenant_name,
                        )
                        continue

                    if not force_full and tenant_uuid in tenant_registry:
                        existing = tenant_registry[tenant_uuid]
                        if existing.tenant_name != tenant_name or existing.kafka_topic != topic:
                            tenant_registry[tenant_uuid] = TenantRuntime(
                                tenant_uuid=tenant_uuid,
                                tenant_name=tenant_name,
                                defender_api_key=existing.defender_api_key,
                                kafka_topic=topic,
                            )
                            logger.info(
                                "Tenant metadata refreshed tenant_uuid=%s tenant_name=%s topic=%s",
                                tenant_uuid,
                                tenant_name,
                                topic,
                            )
                        continue

                    endpoint = (
                        f"/api/msp/companies/{settings.lumu_mssp_uuid}/"
                        f"supervised_companies/{tenant_uuid}/defender_api_key"
                    )
                    try:
                        key_response = await client.get_with_auth(endpoint)
                        defender_api_key = ""
                        if isinstance(key_response, dict):
                            defender_api_key = str(key_response.get("defender_api_key") or "").strip()
                        if not defender_api_key:
                            raise RuntimeError("defender_api_key missing")

                        tenant_registry[tenant_uuid] = TenantRuntime(
                            tenant_uuid=tenant_uuid,
                            tenant_name=tenant_name,
                            defender_api_key=defender_api_key,
                            kafka_topic=topic,
                        )
                        analyzers_by_tenant.setdefault(tenant_uuid, Analyzer(state_file_key=tenant_uuid))
                        key_fetch_success += 1
                        logger.info(
                            "Tenant key bootstrap success tenant_uuid=%s tenant_name=%s topic=%s",
                            tenant_uuid,
                            tenant_name,
                            topic,
                        )
                    except Exception as exc:
                        key_fetch_failed += 1
                        logger.error(
                            "Tenant key bootstrap failed tenant_uuid=%s tenant_name=%s reason=%s",
                            tenant_uuid,
                            tenant_name,
                            exc,
                        )

                stale = set(tenant_registry.keys()) - discovered_uuids
                for tenant_uuid in stale:
                    tenant_registry.pop(tenant_uuid, None)
                    analyzers_by_tenant.pop(tenant_uuid, None)
                    logger.warning("Tenant removed from registry tenant_uuid=%s", tenant_uuid)

                logger.info(
                    "Tenant key bootstrap summary discovered=%s loaded=%s failed=%s active_registry=%s",
                    len(discovered_uuids),
                    key_fetch_success,
                    key_fetch_failed,
                    len(tenant_registry),
                )

            await refresh_tenant_registry(force_full=True)
            last_full_refresh_time = time.monotonic()

            while True:
                logger.info("--- Starting Incident Polling Cycle ---")
                try:
                    now = time.monotonic()
                    force_full = False
                    if now - last_full_refresh_time >= 86400:
                        force_full = True
                        last_full_refresh_time = now
                        logger.info("Performing scheduled full tenant key refresh.")
                    await refresh_tenant_registry(force_full=force_full)
                    await run_tenant_batch(
                        client=client,
                        kafka=kafka,
                        analyzers_by_tenant=analyzers_by_tenant,
                        tenant_registry=tenant_registry,
                        settings=settings,
                    )
                except Exception as e:
                    logger.error(f"Critical error during polling cycle: {str(e)}")

                logger.info(f"Cycle complete. Waiting {settings.polling_interval_minutes} minutes for next check.")
                await asyncio.sleep(interval_seconds)

    except asyncio.CancelledError:
        logger.info("Monitor interrupted. Shutting down gracefully...")


if __name__ == "__main__":
    try:
        asyncio.run(run_loop())
    except KeyboardInterrupt:
        pass
