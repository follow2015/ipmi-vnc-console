"""M3 stage 1: keep the browser session while the BMC console is rebuilt."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping

NON_RETRYABLE = frozenset({
    "bmc_auth_failed",
    "upstream_frame_too_large",
    "upstream_budget_exceeded",
    "upstream_invalid_response",
    "client_message_denied",
    "client_message_malformed",
    "connection_limit",
    "subprotocol_required",
})

NON_RETRYABLE_CLOSE_CODES = frozenset({12592})


def retryable(error: str | None, close_code: int | None = None) -> bool:
    if isinstance(close_code, int) and close_code in NON_RETRYABLE_CLOSE_CODES:
        return False
    return error not in NON_RETRYABLE


def _clamp(value: Any, low: float, high: float, default: float) -> float:
    try:
        number = float(value)
    except (TypeError, ValueError):
        return default
    if number != number or number in (float("inf"), float("-inf")):
        return default
    return max(low, min(high, number))


@dataclass(frozen=True)
class RecoveryPolicy:

    attempts: int = 2
    first_delay: float = 0.4
    max_delay: float = 2.0
    max_total: int = 3
    deadline: float = 20.0
    frame_timeout: float = 3.0

    @classmethod
    def from_config(cls, cfg: Mapping[str, Any]) -> "RecoveryPolicy":
        attempts = int(_clamp(cfg.get("upstream_recovery_attempts", cls.attempts), 0, 5, cls.attempts))
        max_total = int(_clamp(cfg.get("upstream_recovery_max_total", cls.max_total), 0, 4, cls.max_total))
        return cls(
            attempts=attempts,
            first_delay=_clamp(cfg.get("upstream_recovery_delay_seconds", cls.first_delay), 0.05, 5.0,
                               cls.first_delay),
            max_delay=_clamp(cfg.get("upstream_recovery_max_delay_seconds", cls.max_delay), 0.05, 10.0,
                             cls.max_delay),
            max_total=max_total,
            deadline=_clamp(cfg.get("upstream_recovery_deadline_seconds", cls.deadline), 1.0, 60.0,
                            cls.deadline),
            frame_timeout=_clamp(cfg.get("upstream_recovery_frame_timeout_seconds", cls.frame_timeout),
                                 0.2, 30.0, cls.frame_timeout),
        )

    def delay(self, attempt: int) -> float:
        return min(self.first_delay * 2 ** max(0, attempt - 1), self.max_delay)


@dataclass
class RecoveryState:

    policy: RecoveryPolicy
    episodes: int = 0
    attempts: int = 0
    recoveries: int = 0
    dropped_input: int = 0
    last_error: str | None = None
    last_latency_ms: int | None = None
    state: str = "relaying"
    history: list[str] = field(default_factory=list)

    def may_try(self, error: str | None, close_code: int | None = None) -> bool:
        if self.state == "given_up" or self.policy.attempts <= 0:
            return False
        if self.recoveries >= self.policy.max_total:
            return False
        return retryable(error, close_code)

    def begin(self) -> None:
        self.episodes += 1
        self.state = "recovering"
        self.history.clear()

    def attempt(self) -> None:
        self.attempts += 1

    def fail(self, error: str) -> None:
        self.last_error = error
        self.history.append(error)

    def succeed(self, latency_ms: int) -> None:
        self.recoveries += 1
        self.last_latency_ms = max(0, latency_ms)
        self.state = "relaying"

    def give_up(self, error: str | None) -> None:
        if error:
            self.last_error = error
        self.state = "given_up"

    def counters(self) -> dict[str, Any]:
        return {
            "state": self.state,
            "recoveries": self.recoveries,
            "recovery_attempts": self.attempts,
            "recovery_episodes": self.episodes,
            "recovery_last_error": self.last_error,
            "recovery_latency_ms": self.last_latency_ms,
            "dropped_input": self.dropped_input,
        }
