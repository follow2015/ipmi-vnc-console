"""M3: one explicit phase per session, with a transition table and a log."""
from __future__ import annotations

import logging
import time
from collections import deque
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

log = logging.getLogger(__name__)

HISTORY_KEEP = 24


class Phase(str, Enum):
    CONNECTING = "connecting"
    LIVE = "live"
    RECONNECTING = "reconnecting"
    ENDED = "ended"


ALLOWED: dict[Phase, frozenset[Phase]] = {
    Phase.CONNECTING: frozenset({Phase.LIVE, Phase.ENDED}),
    Phase.LIVE: frozenset({Phase.RECONNECTING, Phase.ENDED}),
    Phase.RECONNECTING: frozenset({Phase.LIVE, Phase.ENDED}),
    Phase.ENDED: frozenset(),
}


@dataclass
class SessionMachine:
    phase: Phase = Phase.CONNECTING
    reconnects: int = 0
    history: deque = field(default_factory=lambda: deque(maxlen=HISTORY_KEEP))

    @property
    def ended(self) -> bool:
        return self.phase is Phase.ENDED

    def to(self, target: Phase, why: str = "") -> bool:
        if target is self.phase:
            return True
        if target not in ALLOWED[self.phase]:
            log.warning("session refused transition %s -> %s (%s)",
                        self.phase.value, target.value, why or "-")
            return False
        source = self.phase
        if source is Phase.RECONNECTING and target is Phase.LIVE:
            self.reconnects += 1
        self.phase = target
        self.history.append({"at": round(time.monotonic(), 3), "from": source.value,
                             "to": target.value, "why": why})
        level = logging.DEBUG if target is Phase.RECONNECTING else logging.INFO
        log.log(level, "session phase %s -> %s (%s)", source.value, target.value, why or "-")
        return True

    def as_dict(self) -> dict[str, Any]:
        return {"phase": self.phase.value, "reconnects": self.reconnects,
                "ended": self.ended,
                "last_transition": dict(self.history[-1]) if self.history else None}
