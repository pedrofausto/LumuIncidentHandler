from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Optional

from dateutil import parser


def parse_utc_datetime(raw_value: Any) -> Optional[datetime]:
    if raw_value in (None, ""):
        return None
    try:
        parsed = parser.parse(str(raw_value))
    except (ValueError, TypeError, OverflowError):
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def format_utc_z(dt: datetime) -> str:
    normalized = dt.astimezone(timezone.utc)
    return normalized.isoformat(timespec="milliseconds").replace("+00:00", "Z")


def normalize_utc_timestamp(raw_value: Any) -> str:
    parsed = parse_utc_datetime(raw_value)
    return format_utc_z(parsed) if parsed else ""
