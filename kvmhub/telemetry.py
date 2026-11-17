"""M1 minimum credible subset: end evidence that can be read after the fact."""
from __future__ import annotations

import json
import re
import time
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from .recovery import live_state

EVIDENCE_KEEP = 32

SID_MASK_KEEP = 8

AUDIT_INT_FIELDS = (
    "duration_ms", "connections", "reconnects", "upstream_close_code",
    "client_bytes", "server_bytes", "key_events", "peak_buffered_bytes",
    "recoveries", "recovery_attempts", "recovery_latency_ms", "dropped_input",
    "recovery_input_replayed", "recovery_input_dropped",
    "geometry_reloads",
)
AUDIT_CLASS_FIELDS = ("exception_type",)
AUDIT_DECIMAL_FIELDS = ("since_last_rx_s",)
AUDIT_MAX_INT = 2 ** 31 - 1
AUDIT_MAX_TYPES = 32
AUDIT_MAX_DETAIL_CHARS = 1024


def mask_sid(sid: str, keep: int = SID_MASK_KEEP) -> str:
    return sid if len(sid) <= keep else sid[:keep] + "…"


def _iso(ts: float | None) -> str | None:
    if ts is None:
        return None
    return datetime.fromtimestamp(ts).astimezone().isoformat(timespec="seconds")


def _code(value: Any) -> str | None:
    if isinstance(value, str) and re.fullmatch(r"[a-z0-9_]{1,40}", value):
        return value
    return None


def _audit_int(value: Any) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value if 0 <= value <= AUDIT_MAX_INT else None


def _audit_seconds(value: Any) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    if not 0 <= value <= 86400 or value != value or value in (float("inf"), float("-inf")):
        return None
    return round(float(value), 1)


def _audit_class(value: Any) -> str | None:
    if isinstance(value, str) and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,60}", value):
        return value
    return None


def _audit_geometry(value: Any) -> dict[str, int] | None:
    if not isinstance(value, dict):
        return None
    width, height = value.get("width"), value.get("height")
    if (isinstance(width, int) and not isinstance(width, bool) and 0 <= width <= 65535
            and isinstance(height, int) and not isinstance(height, bool) and 0 <= height <= 65535):
        return {"width": width, "height": height}
    return None


def _audit_json_size(data: dict[str, Any]) -> int:
    return len(json.dumps(data, separators=(",", ":")))


def audit_evidence(record: Any) -> dict[str, Any]:
    if not isinstance(record, dict):
        return {}
    out: dict[str, Any] = {}
    for key in AUDIT_INT_FIELDS:
        value = _audit_int(record.get(key))
        if value is not None:
            out[key] = value
    for key in AUDIT_DECIMAL_FIELDS:
        value = _audit_seconds(record.get(key))
        if value is not None:
            out[key] = value
    for key in AUDIT_CLASS_FIELDS:
        value = _audit_class(record.get(key))
        if value is not None:
            out[key] = value
    code = _code(record.get("recovery_last_error"))
    if code is not None:
        out["recovery_last_error"] = code
    code = _code(record.get("cleanup_outcome"))
    if code is not None:
        out["cleanup_outcome"] = code

    types = record.get("client_message_types")
    if isinstance(types, dict):
        cleaned: dict[str, int] = {}
        for kind, count in list(types.items())[:AUDIT_MAX_TYPES]:
            try:
                numeric = int(kind)
            except (TypeError, ValueError):
                continue
            if not isinstance(kind, (int, str)) or not str(kind).isdigit() or not 0 <= numeric <= 255:
                continue
            value = _audit_int(count)
            if value is not None:
                cleaned[str(numeric)] = value
        if cleaned:
            out["client_message_types"] = cleaned

    denied = record.get("denied")
    if isinstance(denied, dict):
        kind = _audit_int(denied.get("kind"))
        length = _audit_int(denied.get("length"))
        if kind is not None and length is not None and kind <= 255:
            out["denied"] = {"kind": kind, "length": length}

    keep = out.get("client_message_types")
    while keep and _audit_json_size(out) > AUDIT_MAX_DETAIL_CHARS and len(keep) > 1:
        items = list(keep.items())
        keep = dict(items[:max(1, len(items) // 2)])
        out["client_message_types"] = keep
    if _audit_json_size(out) > AUDIT_MAX_DETAIL_CHARS:
        out.pop("client_message_types", None)
    if _audit_json_size(out) > AUDIT_MAX_DETAIL_CHARS:
        return {"evidence_truncated": True}
    return out


def upstream_shape(upstream: Any) -> dict[str, Any]:
    data: dict[str, Any] = {}
    as_dict = getattr(upstream, "as_dict", None)
    if callable(as_dict):
        try:
            data = as_dict() or {}
        except Exception:  # noqa: BLE001 - evidence must never fail the ending
            data = {}
    transport = getattr(upstream, "upstream", None)
    close_code = getattr(transport, "upstream_close_code", None)
    if close_code is None:
        close_code = getattr(transport if transport is not None else upstream, "close_code", None)
    types = data.get("client_message_types") or {}
    counts = {int(kind): int(count) for kind, count in types.items()}
    denied = data.get("denied")
    clock = getattr(transport, "clock", None)
    last_rx = getattr(getattr(transport, "stats", None), "last_event_at", 0)
    since = None
    if (callable(clock) and isinstance(last_rx, (int, float))
            and not isinstance(last_rx, bool) and last_rx > 0):
        since = _audit_seconds(max(0.0, float(clock()) - float(last_rx)))
    return {
        "upstream_close_code": close_code if isinstance(close_code, int) else None,
        "client_bytes": int(data.get("client_bytes", getattr(upstream, "client_bytes", 0)) or 0),
        "server_bytes": int(data.get("server_bytes", getattr(upstream, "server_bytes", 0)) or 0),
        "key_events": int(getattr(upstream, "client_key_events", 0) or 0),
        "client_message_types": {str(kind): count for kind, count in counts.items()},
        "client_message_summary": ",".join(f"{kind}:{count}" for kind, count in sorted(counts.items())),
        "denied": {"kind": int(denied["kind"]), "length": int(denied["length"])}
                  if isinstance(denied, dict) and "kind" in denied and "length" in denied else None,
        "peak_buffered_bytes": int(data.get("peak_buffered_bytes", 0) or 0),
        "exception_type": _audit_class(data.get("exception_type")),
        "since_last_rx_s": since,
        "recoveries": int(data.get("recoveries", 0) or 0),
        "recovery_attempts": int(data.get("recovery_attempts", 0) or 0),
        "recovery_last_error": _code(data.get("recovery_last_error")),
        "recovery_latency_ms": (int(data["recovery_latency_ms"])
                                if isinstance(data.get("recovery_latency_ms"), int) else None),
        "dropped_input": int(data.get("dropped_input", 0) or 0),
        "recovery_input_replayed": int(data.get("recovery_input_replayed", 0) or 0),
        "recovery_input_dropped": int(data.get("recovery_input_dropped", 0) or 0),
        "reload_requested": bool(data.get("reload_requested", False)),
        "reload_reason": _code(data.get("reload_reason")),
        "geometry_before": _audit_geometry(data.get("geometry_before")),
        "geometry_after": _audit_geometry(data.get("geometry_after")),
    }


@dataclass
class SessionTelemetry:

    started_at: float = field(default_factory=time.time)
    started_mono: float = field(default_factory=time.monotonic)
    connections: int = 0
    reconnects: int = 0
    upstream: Any = None
    cleanup_outcome: str | None = None
    geometry_reloads: int = 0

    def note_connection(self, upstream: Any = None) -> None:
        self.connections += 1
        if self.connections > 1:
            self.reconnects += 1
        if upstream is not None:
            self.upstream = upstream

    def note_geometry_reload(self) -> None:
        self.geometry_reloads += 1

    def live(self, *, ws_open: int, opening: int, lease_remaining: float, closing: bool) -> dict[str, Any]:
        shape = upstream_shape(self.upstream)
        shape.pop("upstream_close_code", None)
        return {
            "state": "closing" if closing else self.phase(),
            "uptime_s": round(time.monotonic() - self.started_mono, 1),
            "lease_remaining_s": round(max(0.0, lease_remaining), 1),
            "connections": self.connections,
            "reconnects": self.reconnects,
            "ws_open": ws_open,
            "opening": opening,
            "geometry_reloads": self.geometry_reloads,
            **shape,
        }

    def phase(self) -> str:
        recovery = live_state(self.upstream)
        if recovery is not None and recovery.state == "recovering":
            return "recovering"
        return "live"

    def evidence(self, *, sid: str, reason: str, cleanup: str, upstream: Any = None,
                 now: float | None = None) -> dict[str, Any]:
        ended = time.time() if now is None else now
        record = {
            "sid": sid,
            "started_at": _iso(self.started_at),
            "ended_at": _iso(ended),
            "duration_ms": int(max(0.0, ended - self.started_at) * 1000),
            "end_reason": reason,
            "cleanup": cleanup,
            "connections": self.connections,
            "reconnects": self.reconnects,
            "geometry_reloads": self.geometry_reloads,
            **upstream_shape(self.upstream if upstream is None else upstream),
        }
        if self.cleanup_outcome is not None:
            outcome = _code(self.cleanup_outcome)
            if outcome is not None:
                record["cleanup_outcome"] = outcome
        return record


class EvidenceLog:

    def __init__(self, keep: int = EVIDENCE_KEEP) -> None:
        self.keep = keep
        self._items: deque[dict[str, Any]] = deque(maxlen=keep)

    def add(self, record: dict[str, Any]) -> dict[str, Any]:
        self._items.append(record)
        return record

    def recent(self, limit: int = 5, *, mask: bool = True) -> list[dict[str, Any]]:
        items = list(reversed(self._items))[:limit]
        if not mask:
            return items
        return [dict(item, sid=mask_sid(item["sid"])) for item in items]

    def __len__(self) -> int:
        return len(self._items)
