"""M1 minimum credible subset: end evidence that can be read after the fact."""
from __future__ import annotations

import re
import time
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

EVIDENCE_KEEP = 32

SID_MASK_KEEP = 8


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
        "recoveries": int(data.get("recoveries", 0) or 0),
        "recovery_attempts": int(data.get("recovery_attempts", 0) or 0),
        "recovery_last_error": _code(data.get("recovery_last_error")),
        "recovery_latency_ms": (int(data["recovery_latency_ms"])
                                if isinstance(data.get("recovery_latency_ms"), int) else None),
        "dropped_input": int(data.get("dropped_input", 0) or 0),
    }


@dataclass
class SessionTelemetry:

    started_at: float = field(default_factory=time.time)
    started_mono: float = field(default_factory=time.monotonic)
    connections: int = 0
    reconnects: int = 0
    upstream: Any = None

    def note_connection(self, upstream: Any = None) -> None:
        self.connections += 1
        if self.connections > 1:
            self.reconnects += 1
        if upstream is not None:
            self.upstream = upstream

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
            **shape,
        }

    def phase(self) -> str:
        recovery = getattr(self.upstream, "recovery", None)
        if recovery is not None and getattr(recovery, "state", None) == "recovering":
            return "recovering"
        return "live"

    def evidence(self, *, sid: str, reason: str, cleanup: str, upstream: Any = None,
                 now: float | None = None) -> dict[str, Any]:
        ended = time.time() if now is None else now
        return {
            "sid": sid,
            "started_at": _iso(self.started_at),
            "ended_at": _iso(ended),
            "duration_ms": int(max(0.0, ended - self.started_at) * 1000),
            "end_reason": reason,
            "cleanup": cleanup,
            "connections": self.connections,
            "reconnects": self.reconnects,
            **upstream_shape(self.upstream if upstream is None else upstream),
        }


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
