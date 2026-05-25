import json
import logging
import os
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from src.config import get_settings
from src.models import IncidentEvent
from src.time_utils import format_utc_z, parse_utc_datetime

logger = logging.getLogger(__name__)


class Analyzer:
    def __init__(self, state_file_key: str = "default"):
        base_state_file = Path(get_settings().alert_state_file).name
        key = "".join(ch if ch.isalnum() else "_" for ch in state_file_key).strip("_") or "default"
        self._state_file = f"{key}_{base_state_file}"
        self.force_offset_reset_applied = False
        state_data = self._load_state()

        if state_data and "incidents" not in state_data and "last_pulled_time" not in state_data:
            logger.info("Migrating legacy state schema to new per-incident schema...")
            self._incident_times = {str(k): str(v) for k, v in state_data.items()}
            if self._incident_times:
                max_val = max(self._incident_times.values())
                try:
                    float_ts = float(max_val)
                    self.last_pulled_time = datetime.fromtimestamp(float_ts, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
                except ValueError:
                    self.last_pulled_time = max_val
            else:
                self.last_pulled_time = ""
            self.offset = get_settings().lumu_initial_offset
            self.open_state_sync_last_success_at = ""
            self.open_state_sync_next_due_at = ""
            self.open_state_sync_failure_count = 0
        else:
            self.last_pulled_time: str = state_data.get("last_pulled_time", "")
            if not self.last_pulled_time:
                self.last_pulled_time = get_settings().lumu_initial_time
            self._incident_times: Dict[str, str] = state_data.get("incidents", {})
            self.open_state_sync_last_success_at = str(state_data.get("open_state_sync_last_success_at", "") or "")
            self.open_state_sync_next_due_at = str(state_data.get("open_state_sync_next_due_at", "") or "")
            self.open_state_sync_failure_count = int(state_data.get("open_state_sync_failure_count", 0) or 0)

            persisted_offset = state_data.get("offset", 0)
            env_offset = get_settings().lumu_initial_offset
            force_offset = get_settings().lumu_force_offset

            if force_offset:
                logger.info(
                    "LUMU_FORCE_OFFSET is enabled. Overriding persisted offset (%s) with LUMU_INITIAL_OFFSET (%s).",
                    persisted_offset,
                    env_offset,
                )
                self.offset = env_offset
                self._incident_times = {}
                self.open_state_sync_last_success_at = ""
                self.open_state_sync_next_due_at = ""
                self.open_state_sync_failure_count = 0
                self.force_offset_reset_applied = True
                self._save_state()
            else:
                self.offset = persisted_offset

    @staticmethod
    def _format_utc(dt: datetime) -> str:
        return format_utc_z(dt)

    @staticmethod
    def _parse_utc(raw_value: str) -> Optional[datetime]:
        return parse_utc_datetime(raw_value)

    def _normalize_timestamp(self, raw_value: str) -> str:
        parsed = self._parse_utc(raw_value)
        return self._format_utc(parsed) if parsed else str(raw_value or "")

    def _compare_timestamps(self, candidate_raw: str, stored_raw: str) -> Optional[int]:
        candidate_dt = self._parse_utc(candidate_raw)
        stored_dt = self._parse_utc(stored_raw)
        if candidate_dt is None or stored_dt is None:
            return None
        if candidate_dt > stored_dt:
            return 1
        if candidate_dt < stored_dt:
            return -1
        return 0

    def should_process_incident(self, raw_incident: Dict[str, Any]) -> bool:
        uuid = raw_incident.get("id") or raw_incident.get("uuid")
        if not uuid:
            return False

        last_contact = raw_incident.get("lastContact") or raw_incident.get("timestamp") or ""
        stored_ts = self._incident_times.get(uuid, "")
        normalized_last_contact = self._normalize_timestamp(last_contact)
        if not stored_ts:
            logger.debug(
                "Incident decision incident_uuid=%s chosen_last_contact=%s stored_state_timestamp=%s source=top_level comparison_result=missing_state decision=send",
                uuid,
                normalized_last_contact,
                stored_ts,
            )
            return True

        comparison = self._compare_timestamps(normalized_last_contact, stored_ts)
        if comparison is None:
            decision = bool(normalized_last_contact and normalized_last_contact != stored_ts)
            logger.debug(
                "Incident decision incident_uuid=%s chosen_last_contact=%s stored_state_timestamp=%s source=top_level comparison_result=unparsed skip_reason=%s decision=%s",
                uuid,
                normalized_last_contact,
                self._normalize_timestamp(stored_ts),
                "string_fallback" if normalized_last_contact else "invalid_timestamp",
                "send" if decision else "skip",
            )
            return decision

        logger.debug(
            "Incident decision incident_uuid=%s chosen_last_contact=%s stored_state_timestamp=%s source=top_level comparison_result=%s skip_reason=%s decision=%s",
            uuid,
            normalized_last_contact,
            self._normalize_timestamp(stored_ts),
            comparison,
            "unchanged" if comparison == 0 else "older_than_state" if comparison < 0 else "",
            "send" if comparison > 0 else "skip",
        )
        return comparison > 0

    def classify_incident_event_type(self, raw_incident: Dict[str, Any]) -> str:
        explicit_event_type = raw_incident.get("_lumu_event_type")
        if explicit_event_type in {"NewIncidentCreated", "IncidentUpdated"}:
            return explicit_event_type

        uuid = raw_incident.get("id") or raw_incident.get("uuid")
        if uuid and uuid not in self._incident_times:
            return "NewIncidentCreated"
        return "IncidentUpdated"

    def update_incident_time(self, uuid: str, timestamp: str):
        if uuid and timestamp:
            normalized_ts = self._normalize_timestamp(timestamp)
            self._incident_times[uuid] = normalized_ts
            if not self.last_pulled_time:
                self.last_pulled_time = normalized_ts
            else:
                comparison = self._compare_timestamps(normalized_ts, self.last_pulled_time)
                if comparison is None:
                    if normalized_ts > self.last_pulled_time:
                        self.last_pulled_time = normalized_ts
                elif comparison > 0:
                    self.last_pulled_time = normalized_ts
            self._save_state()

    def is_open_state_sync_due(self, now_utc: datetime) -> bool:
        next_due = self._parse_utc(self.open_state_sync_next_due_at)
        if next_due is None:
            return True
        return now_utc.astimezone(timezone.utc) >= next_due

    def mark_open_state_sync_success(self, now_utc: datetime, interval_minutes: int, jitter_seconds: int) -> None:
        base_due = now_utc.astimezone(timezone.utc) + timedelta(minutes=interval_minutes)
        jitter = random.randint(-jitter_seconds, jitter_seconds) if jitter_seconds > 0 else 0
        next_due = base_due + timedelta(seconds=jitter)
        if next_due <= now_utc.astimezone(timezone.utc):
            next_due = now_utc.astimezone(timezone.utc) + timedelta(seconds=1)

        self.open_state_sync_last_success_at = self._format_utc(now_utc)
        self.open_state_sync_next_due_at = self._format_utc(next_due)
        self.open_state_sync_failure_count = 0
        self.force_offset_reset_applied = False
        self._save_state()

    def mark_open_state_sync_failure(self, now_utc: datetime, base_backoff_minutes: int, max_backoff_minutes: int) -> None:
        self.open_state_sync_failure_count += 1
        backoff_minutes = min(max_backoff_minutes, base_backoff_minutes * (2 ** (self.open_state_sync_failure_count - 1)))
        next_due = now_utc.astimezone(timezone.utc) + timedelta(minutes=backoff_minutes)
        self.open_state_sync_next_due_at = self._format_utc(next_due)
        self._save_state()

    def _load_state(self) -> Dict[str, Any]:
        base_dir = Path(__file__).resolve().parent.parent / "data"
        abs_path = (base_dir / Path(self._state_file).name).resolve()

        if not abs_path.is_relative_to(base_dir):
            logger.error("Security Alert: Path traversal attempt blocked for state file: %s", self._state_file)
            return {}

        if not abs_path.exists():
            return {}
        try:
            with open(abs_path, "r") as f:
                content = f.read()
                if not content:
                    return {}
                return json.loads(content)
        except (json.JSONDecodeError, IOError) as exc:
            logger.error("Failed to load state file %s: %s", self._state_file, exc)
            return {}

    def _save_state(self):
        try:
            cutoff = datetime.now(timezone.utc) - timedelta(days=60)
            pruned_incidents: Dict[str, str] = {}
            for incident_uuid, raw_ts in self._incident_times.items():
                try:
                    parsed = parse_utc_datetime(raw_ts)
                    if parsed is None:
                        raise ValueError("invalid timestamp")
                    if parsed >= cutoff:
                        pruned_incidents[incident_uuid] = self._format_utc(parsed)
                except (ValueError, TypeError, OverflowError):
                    pruned_incidents[incident_uuid] = raw_ts
            self._incident_times = pruned_incidents

            base_dir = Path(__file__).resolve().parent.parent / "data"
            abs_path = (base_dir / Path(self._state_file).name).resolve()

            if not abs_path.is_relative_to(base_dir):
                logger.error("Security Alert: Path traversal attempt blocked for state file: %s", self._state_file)
                return

            parent_dir = abs_path.parent
            parent_dir.mkdir(parents=True, exist_ok=True)

            temp_file = str(abs_path) + ".tmp"
            fd = os.open(temp_file, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w") as f:
                json.dump(
                    {
                        "last_pulled_time": self.last_pulled_time,
                        "offset": self.offset,
                        "incidents": self._incident_times,
                        "open_state_sync_last_success_at": self.open_state_sync_last_success_at,
                        "open_state_sync_next_due_at": self.open_state_sync_next_due_at,
                        "open_state_sync_failure_count": self.open_state_sync_failure_count,
                    },
                    f,
                    indent=2,
                )
                f.flush()
                os.fsync(f.fileno())

            os.replace(temp_file, str(abs_path))
        except (IOError, OSError) as exc:
            logger.error("Failed to save state file %s: %s", self._state_file, exc)

    def extract_incidents_from_updates(self, updates_data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        incidents = []
        for update in updates_data:
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
                    logger.warning("Update event %s missing incident data.", event_type)
            elif event_type == "OpenIncidentsStatusUpdated":
                logger.debug("Received status update: %s", event_data)
            else:
                logger.debug("Ignoring update event type: %s", event_type)
        return incidents

    def filter_changed_incidents(self, events: List[IncidentEvent]) -> List[IncidentEvent]:
        changed_events = []
        state_updated = False
        new_max_time = self.last_pulled_time

        for event in events:
            stored_ts = self._incident_times.get(event.incident_uuid, "")
            normalized_last_contact = self._normalize_timestamp(event.last_contact)
            is_new = not stored_ts
            comparison = self._compare_timestamps(normalized_last_contact, stored_ts) if stored_ts else 1
            is_updated = bool(normalized_last_contact and comparison is not None and comparison > 0)

            if is_new or is_updated:
                changed_events.append(event)
                if normalized_last_contact:
                    self._incident_times[event.incident_uuid] = normalized_last_contact
                    state_updated = True
            else:
                logger.debug(
                    "Incident decision incident_uuid=%s chosen_last_contact=%s stored_state_timestamp=%s source=%s comparison_result=%s skip_reason=%s decision=skip",
                    event.incident_uuid,
                    normalized_last_contact,
                    self._normalize_timestamp(stored_ts) if stored_ts else stored_ts,
                    getattr(event, "last_contact_source", "unknown"),
                    comparison if comparison is not None else "unparsed",
                    "unchanged" if comparison == 0 else "older_than_state" if comparison is not None and comparison < 0 else "invalid_timestamp",
                )

            if normalized_last_contact:
                if not new_max_time:
                    new_max_time = normalized_last_contact
                    state_updated = True
                else:
                    max_comparison = self._compare_timestamps(normalized_last_contact, new_max_time)
                    if max_comparison is None:
                        if normalized_last_contact > new_max_time:
                            new_max_time = normalized_last_contact
                            state_updated = True
                    elif max_comparison > 0:
                        new_max_time = normalized_last_contact
                        state_updated = True

        if state_updated:
            self.last_pulled_time = new_max_time
            self._save_state()

        return changed_events
