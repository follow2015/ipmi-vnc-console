"""M3 stage 1 end-to-end drill against one real BMC, with M1 evidence as a witness."""
from __future__ import annotations

import argparse
import asyncio
import json
import multiprocessing
import os
import queue
import re
import shutil
import socket
import struct
import subprocess
import sys
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from kvmhub.common import UI_ORIGIN, UI_PORT, WORKER_PORT  # noqa: E402
from kvmhub.recovery import RecoveryPolicy  # noqa: E402
from kvmhub.rfb_upstream import RfbUpstream, UpstreamConfig  # noqa: E402
from kvmhub.run import manager_process, worker_process  # noqa: E402
from kvmhub.store import Store  # noqa: E402
from kvmhub.telemetry import (AUDIT_CLASS_FIELDS, AUDIT_DECIMAL_FIELDS,
                              AUDIT_INT_FIELDS, mask_sid)  # noqa: E402
from tools.browser_e2e import _find_chromium, _find_playwright  # noqa: E402
from tools.passthrough_check import prepare, shaping_from_arg, wait_port  # noqa: E402
from tools.revoke_check import Manager, finish_browser, parse_ready  # noqa: E402
from tools.silent_upstream_check import Relay, audit_actions, wait_for  # noqa: E402

ALLOWED_EVIDENCE_KEYS = frozenset((
    *AUDIT_INT_FIELDS, *AUDIT_DECIMAL_FIELDS, *AUDIT_CLASS_FIELDS,
    "client_message_types", "denied", "recovery_last_error", "evidence_truncated",
    "cleanup_outcome",
))
FORBIDDEN_EVIDENCE_KEYS = frozenset((
    "sid", "started_at", "ended_at", "end_reason", "cleanup",
    "client_message_summary", "password", "username", "ticket",
))
TERMINAL_STATUSES = ("closed", "failed", "lost")


class CutRelay(Relay):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.cut_count = 0
        self.last_cut_pairs = 0

    def cut(self) -> int:
        with self._lock:
            pairs = list(self._pairs.values())
            self._pairs = {}
        for near, far in pairs:
            try:
                near.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER,
                                struct.pack("ii", 1, 0))
            except OSError:
                pass
            for sock in (near, far):
                try:
                    sock.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                try:
                    sock.close()
                except OSError:
                    pass
        self.cut_count += 1
        self.last_cut_pairs = len(pairs)
        return len(pairs)


def run_recovery_browser(node: str, module: str, chromium: str, base: str,
                         token: str, asset: str, hold_ms: int,
                         screenshot: str | None, hold_key: str = "",
                         key_hold_ms: int = 0, idle_ms: int = 0):
    env = dict(os.environ, KVM_PLAYWRIGHT=module, KVM_CHROMIUM=chromium,
               KVM_BASE=base, KVM_TOKEN=token, KVM_ASSET=asset,
               KVM_RECOVERY_MODE="1", KVM_RECOVERY_TIMEOUT_MS=str(hold_ms))
    if hold_key:
        env["KVM_HOLD_KEY"] = hold_key
        env["KVM_HOLD_MS"] = str(key_hold_ms)
        env["KVM_HOLD_IDLE_MS"] = str(idle_ms)
    if screenshot:
        env["KVM_SCREENSHOT"] = screenshot
    process = subprocess.Popen([node, "tools/passthrough_browser.cjs"], cwd=ROOT, env=env,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1)
    lines: list[str] = []
    errors: list[str] = []
    ready: queue.Queue = queue.Queue()
    keys: queue.Queue = queue.Queue()

    def pump():
        for line in process.stdout:
            lines.append(line)
            payload = parse_ready(line)
            if payload is not None:
                ready.put(payload)
            elif line.startswith("HOLDKEY "):
                try:
                    keys.put(json.loads(line[len("HOLDKEY "):]))
                except json.JSONDecodeError:
                    pass
        ready.put(None)

    def drain():
        for line in process.stderr:
            errors.append(line)

    threading.Thread(target=pump, daemon=True).start()
    threading.Thread(target=drain, daemon=True).start()
    try:
        handshake = ready.get(timeout=hold_ms / 1000 + 90)
    except queue.Empty:
        handshake = None
    return process, handshake, lines, errors, keys


def recovery_evidence_verdict(evidence: dict) -> dict:
    reasons: list[str] = []
    if evidence.get("errors"):
        reasons.append("browser_errors")
    handshake = evidence.get("handshake") or {}
    if handshake.get("state") != "normal":
        reasons.append("console_not_normal_before_cut")
    if (handshake.get("canvas") or {}).get("non_black", 0) <= 0:
        reasons.append("no_picture_before_cut")
    if not (evidence.get("cut") or {}).get("sockets_reset"):
        reasons.append("upstream_link_not_reset")
    if not evidence.get("new_upstream_connections"):
        reasons.append("no_rebuilt_socket")

    recovery = evidence.get("recovery") or {}
    if not recovery.get("state_never_failed"):
        reasons.append("browser_noticed_the_cut")
    if recovery.get("requests_after_ready") != 0:
        reasons.append("browser_reconnected")
    if (recovery.get("max_recoveries") or 0) < 1:
        reasons.append("gateway_never_recovered")
    if (recovery.get("sample_count") or 0) < 2:
        reasons.append("no_sampling_window")
    first, last = recovery.get("server_bytes_first"), recovery.get("server_bytes_last")
    if first is None or last is None:
        reasons.append("no_server_view")
    elif not isinstance(first, int) or not isinstance(last, int) or last <= first:
        reasons.append("no_new_frames_after_recovery")

    during = evidence.get("session_after_cut") or {}
    if during.get("status") != "active":
        reasons.append("session_ended_on_upstream_loss")
    ended = evidence.get("session") or {}
    if ended.get("status") not in TERMINAL_STATUSES:
        reasons.append("session_not_ended")
    if ended.get("cleanup") != "confirmed":
        reasons.append("cleanup_not_confirmed")
    if "session_finished" not in (evidence.get("audit_actions") or []):
        reasons.append("end_not_audited")

    audit = evidence.get("audit_evidence")
    if not isinstance(audit, dict) or not audit:
        reasons.append("no_audit_evidence")
    else:
        if set(audit) - ALLOWED_EVIDENCE_KEYS:
            reasons.append("evidence_field_out_of_whitelist")
        if set(audit) & FORBIDDEN_EVIDENCE_KEYS:
            reasons.append("forbidden_evidence_field")
        if (audit.get("recoveries") or 0) < 1:
            reasons.append("recovery_not_in_audit")
        for key in AUDIT_INT_FIELDS:
            if key in audit and (isinstance(audit[key], bool) or not isinstance(audit[key], int)):
                reasons.append("non_integer_counter")
                break
    if audit != evidence.get("session_end_evidence"):
        reasons.append("audit_row_disagrees")
    if evidence.get("sentinel_leaked"):
        reasons.append("credential_in_audit")
    if evidence.get("output_is_clean") is False:
        reasons.append("credential_in_output")
    return {"verdict": "pass" if not reasons else "fail", "reasons": reasons,
            "end_reason": ended.get("reason")}


def multi_cut_verdict(evidence: dict) -> dict:
    reasons: list[str] = []
    handshake = evidence.get("handshake") or {}
    if handshake.get("state") != "normal":
        reasons.append("console_not_normal_before_cut")
    if (handshake.get("canvas") or {}).get("non_black", 0) <= 0:
        reasons.append("no_picture_before_cut")

    cuts = evidence.get("cuts") or []
    requested = int(evidence.get("cuts_requested") or 0)
    max_total = evidence.get("policy_max_total")
    ended_at = evidence.get("ended_at_cut")
    if not cuts:
        reasons.append("no_cut_observed")
    if not isinstance(max_total, int) or isinstance(max_total, bool):
        reasons.append("no_policy_ceiling")
        max_total = None
    if len(cuts) < min(requested, (max_total or 0) + 1):
        reasons.append("fewer_cuts_than_requested")

    rebuilt = 0
    for record in cuts:
        index = record.get("index")
        if index == ended_at:
            continue
        if not record.get("sockets_reset"):
            reasons.append("upstream_link_not_reset")
            continue
        if record.get("recovery_ms") is None:
            reasons.append(f"no_rebuilt_socket_at_cut_{index}")
        else:
            rebuilt += 1

    session = evidence.get("session") or {}
    if ended_at is None:
        if max_total is not None and len(cuts) > max_total:
            reasons.append("cap_not_enforced")
    else:
        if max_total is not None and ended_at != max_total + 1:
            reasons.append("session_died_before_cap")
        if session.get("reason") != "upstream_reconnect_failed":
            reasons.append("wrong_end_reason_for_cap")
    if session.get("status") not in TERMINAL_STATUSES:
        reasons.append("session_not_ended")
    if session.get("cleanup") != "confirmed":
        reasons.append("cleanup_not_confirmed")
    if "session_finished" not in (evidence.get("audit_actions") or []):
        reasons.append("end_not_audited")

    recovery = evidence.get("recovery") or {}
    if (recovery.get("sample_count") or 0) < 2:
        reasons.append("no_sampling_window")
    first, last = recovery.get("server_bytes_first"), recovery.get("server_bytes_last")
    if first is None or last is None:
        reasons.append("no_server_view")
    elif not isinstance(first, int) or not isinstance(last, int) or last <= first:
        reasons.append("no_new_frames_after_recovery")

    audit = evidence.get("audit_evidence")
    if not isinstance(audit, dict) or not audit:
        reasons.append("no_audit_evidence")
    else:
        if set(audit) - ALLOWED_EVIDENCE_KEYS:
            reasons.append("evidence_field_out_of_whitelist")
        if set(audit) & FORBIDDEN_EVIDENCE_KEYS:
            reasons.append("forbidden_evidence_field")
        recorded = audit.get("recoveries")
        if isinstance(recorded, bool) or not isinstance(recorded, int):
            reasons.append("non_integer_counter")
        elif recorded != rebuilt:
            reasons.append("recovery_count_disagrees")
        for key in AUDIT_INT_FIELDS:
            if key in audit and (isinstance(audit[key], bool) or not isinstance(audit[key], int)):
                reasons.append("non_integer_counter")
                break
    if audit != evidence.get("session_end_evidence"):
        reasons.append("audit_row_disagrees")
    if evidence.get("sentinel_leaked"):
        reasons.append("credential_in_audit")
    if evidence.get("output_is_clean") is False:
        reasons.append("credential_in_output")
    return {"verdict": "pass" if not reasons else "fail", "reasons": reasons,
            "end_reason": session.get("reason")}


def idle_churn(samples: list, start: int, end: int) -> dict:
    window = [sig for at, sig in samples if start <= at <= end]
    changes = sum(1 for index in range(1, len(window)) if window[index] != window[index - 1])
    pairs = max(1, len(window) - 1)
    span = (max(end, start) - start) if window else 0
    return {"samples": len(window), "changes": changes, "pairs": pairs,
            "window_ms": int(span), "distinct": len(set(window)),
            "change_ratio": round(changes / pairs, 2)}


BUSY_RATIO = 0.9
QUIET_RATIO = 0.5


QUIET_SETTLE_MS = 1200


def held_key_windows(evidence: dict) -> dict:
    recovery = evidence.get("recovery") or {}
    samples = recovery.get("samples_sig") or []
    hold = recovery.get("hold") or {}
    down_at, up_at = hold.get("down_at"), hold.get("up_at")
    ready_at = recovery.get("ready_at")
    if not samples or down_at is None or up_at is None or ready_at is None:
        return {}
    cuts = evidence.get("cuts") or []
    recovery_ms = cuts[0].get("recovery_ms") if cuts else None
    cut_at = cuts[0].get("cut_at_ms") if cuts else None
    rebuilt_at = (cut_at + recovery_ms) if (cut_at and recovery_ms is not None) else None
    start = max(up_at, rebuilt_at or 0) + QUIET_SETTLE_MS
    baseline = idle_churn(samples, ready_at, down_at)
    after = idle_churn(samples, start, samples[-1][0])
    return {"baseline": baseline, "after": after, "rebuilt_at": rebuilt_at,
            "after_start": start, "release_during_rebuild":
                bool(rebuilt_at is not None and up_at < rebuilt_at)}


def held_key_verdict(evidence: dict) -> dict:
    base = recovery_evidence_verdict(evidence)
    reasons = list(base["reasons"])
    recovery = evidence.get("recovery") or {}
    hold = recovery.get("hold") or {}
    cuts = evidence.get("cuts") or []
    cut_at = cuts[0].get("cut_at_ms") if cuts else None
    down_at, up_at = hold.get("down_at"), hold.get("up_at")
    if down_at is None:
        reasons.append("key_never_pressed")
    if up_at is None:
        reasons.append("key_never_released")
    if cut_at is not None and down_at is not None and down_at > cut_at:
        reasons.append("key_pressed_after_the_cut")
    if cut_at is not None and up_at is not None and up_at <= cut_at:
        reasons.append("key_released_before_the_cut")

    windows = held_key_windows(evidence)
    evidence["stuck_watch"] = windows
    if not windows:
        reasons.append("no_hold_timeline")
    else:
        after, baseline = windows["after"], windows["baseline"]
        windows["discriminating"] = baseline["change_ratio"] < QUIET_RATIO
        if baseline["samples"] < 3 or after["samples"] < 3:
            reasons.append("no_quiet_window")
        elif after["change_ratio"] >= BUSY_RATIO and after["change_ratio"] > baseline["change_ratio"]:
            reasons.append("screen_changed_after_release")

    if windows.get("release_during_rebuild"):
        counters = recovery.get("input_counters") or {}
        replayed, dropped = counters.get("replayed"), counters.get("dropped")
        if not isinstance(replayed, int) or isinstance(replayed, bool) or replayed < 1:
            reasons.append("release_during_rebuild_was_not_replayed")
        if isinstance(dropped, int) and not isinstance(dropped, bool) and dropped > 0:
            reasons.append("input_dropped_during_rebuild")
    if (recovery.get("input_counters") or {}).get("dropped", 0):
        reasons.append("input_dropped_during_rebuild")

    session = evidence.get("session") or {}
    return {"verdict": "pass" if not reasons else "fail", "reasons": reasons,
            "end_reason": session.get("reason")}


LOGOUT_STATUS = re.compile(r"^status_(\d{3})$")


def refused_logout_verdict(evidence: dict) -> dict:
    reasons: list[str] = []
    if evidence.get("errors"):
        reasons.append("browser_errors")
    handshake = evidence.get("handshake") or {}
    if handshake.get("state") != "normal":
        reasons.append("console_not_normal")
    if (handshake.get("canvas") or {}).get("non_black", 0) <= 0:
        reasons.append("no_picture")
    if evidence.get("cuts"):
        reasons.append("upstream_was_cut")
    if (evidence.get("recovery") or {}).get("state_never_failed") is not True:
        reasons.append("console_failed_without_a_cut")

    session = evidence.get("session") or {}
    if session.get("status") not in TERMINAL_STATUSES:
        reasons.append("session_not_ended")
    if session.get("reason") != "client_closed":
        reasons.append("wrong_end_reason")
    if session.get("cleanup") != "pending":
        reasons.append("cleanup_not_pending")

    outcome = str(evidence.get("cleanup_outcome") or "")
    status = LOGOUT_STATUS.fullmatch(outcome)
    if status is None:
        reasons.append("logout_never_reached_the_device")
    elif status.group(1).startswith("2"):
        reasons.append("logout_was_accepted")

    if evidence.get("slot_released") is not False:
        reasons.append("slot_released_despite_pending")
    if "session_finished" not in (evidence.get("audit_actions") or []):
        reasons.append("end_not_audited")

    audit = evidence.get("audit_evidence")
    if not isinstance(audit, dict) or not audit:
        reasons.append("no_audit_evidence")
    else:
        if set(audit) - ALLOWED_EVIDENCE_KEYS:
            reasons.append("evidence_field_out_of_whitelist")
        if set(audit) & FORBIDDEN_EVIDENCE_KEYS:
            reasons.append("forbidden_evidence_field")
        if audit.get("cleanup_outcome") != outcome:
            reasons.append("audit_disagrees_on_logout_outcome")
    if audit != evidence.get("session_end_evidence"):
        reasons.append("audit_row_disagrees")
    if evidence.get("sentinel_leaked"):
        reasons.append("credential_in_audit")
    if evidence.get("output_is_clean") is False:
        reasons.append("credential_in_output")
    return {"verdict": "pass" if not reasons else "fail", "reasons": reasons,
            "end_reason": session.get("reason")}


def refused_rebuild_verdict(evidence: dict) -> dict:
    reasons: list[str] = []
    handshake = evidence.get("handshake") or {}
    if handshake.get("state") != "normal":
        reasons.append("console_not_normal_before_cut")
    if (handshake.get("canvas") or {}).get("non_black", 0) <= 0:
        reasons.append("no_picture_before_cut")
    if evidence.get("listener_closed") is not True:
        reasons.append("still_accepting_reconnects")

    cuts = evidence.get("cuts") or []
    if len(cuts) != 1:
        reasons.append("expected_exactly_one_cut")
    else:
        record = cuts[0]
        if not record.get("sockets_reset"):
            reasons.append("upstream_link_not_reset")
        if record.get("recovery_ms") is not None:
            reasons.append("console_rebuilt_after_refusal")

    session = evidence.get("session") or {}
    if session.get("status") not in TERMINAL_STATUSES:
        reasons.append("session_not_ended")
    if session.get("reason") != "upstream_reconnect_failed":
        reasons.append("wrong_end_reason_for_failed_rebuild")
    if session.get("cleanup") not in ("confirmed", "pending"):
        reasons.append("cleanup_state_unknown")
    if "session_finished" not in (evidence.get("audit_actions") or []):
        reasons.append("end_not_audited")

    if (evidence.get("recovery") or {}).get("recoveries"):
        reasons.append("rebuild_succeeded_after_refusal")

    audit = evidence.get("audit_evidence")
    if not isinstance(audit, dict) or not audit:
        reasons.append("no_audit_evidence")
    else:
        if set(audit) - ALLOWED_EVIDENCE_KEYS:
            reasons.append("evidence_field_out_of_whitelist")
        if set(audit) & FORBIDDEN_EVIDENCE_KEYS:
            reasons.append("forbidden_evidence_field")
        if audit.get("recoveries") not in (0, None):
            reasons.append("audit_claims_a_rebuild")
        attempts = audit.get("recovery_attempts")
        if isinstance(attempts, bool) or not isinstance(attempts, int) or attempts < 1:
            reasons.append("no_rebuild_attempt_recorded")
    if audit != evidence.get("session_end_evidence"):
        reasons.append("audit_row_disagrees")
    if evidence.get("sentinel_leaked"):
        reasons.append("credential_in_audit")
    if evidence.get("output_is_clean") is False:
        reasons.append("credential_in_output")
    return {"verdict": "pass" if not reasons else "fail", "reasons": reasons,
            "end_reason": session.get("reason")}


def recovery_event(lines: list[str], after_ms: int, minimum: int) -> dict | None:
    for line in lines:
        if not line.startswith("RECOVERY "):
            continue
        try:
            payload = json.loads(line[len("RECOVERY "):])
        except json.JSONDecodeError:
            continue
        if not isinstance(payload, dict) or payload.get("at", 0) < after_ms:
            continue
        server = payload.get("server") or {}
        if (server.get("recoveries") or 0) >= minimum:
            return payload
    return None


def output_is_clean(evidence: dict, markers: list[str]) -> bool:
    serialised = json.dumps(evidence, ensure_ascii=False)
    return all(not marker or marker not in serialised for marker in markers)


def _detail_evidence(store: Store, sid: str) -> dict | None:
    row = store.db.execute(
        "SELECT detail FROM audit WHERE session_id=? AND action='session_finished' "
        "ORDER BY id LIMIT 1", (sid,)).fetchone()
    if row is None:
        return None
    try:
        return json.loads(row["detail"]).get("evidence")
    except (json.JSONDecodeError, AttributeError):
        return None


def _stored_evidence(store: Store, sid: str) -> dict | None:
    raw = store.get(sid)["end_evidence"]
    if not raw:
        return None
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return None


def _squeeze_worker(host, fingerprint, username, password, count, stop, result):
    async def run():
        upstreams = []
        try:
            for _ in range(count):
                upstream = RfbUpstream(_bmc_config(host, fingerprint))
                await upstream.login(username, password)
                await upstream.open(request_frames=True)
                upstreams.append(upstream)
            result["opened"] = len(upstreams)
            while not stop.is_set():
                await asyncio.sleep(0.2)
        except Exception as exc:  # noqa: BLE001 - the evidence names the failure
            result["error"] = getattr(exc, "code", None) or type(exc).__name__
            result["opened"] = result.get("opened", len(upstreams))
        finally:
            for upstream in upstreams:
                try:
                    await upstream.close()
                except Exception:  # noqa: BLE001 - cleanup must not mask the result
                    pass
            result["closed"] = len(upstreams)

    asyncio.run(run())


def _bmc_config(host: str, fingerprint: str) -> UpstreamConfig:
    return UpstreamConfig(host=host, port=443, cert_sha256=fingerprint,
                          max_frame_bytes=1024 * 1024, max_total_bytes=64 * 1024 * 1024,
                          max_frames=4000, enforce_relay_budget=False)


async def second_login(cfg: UpstreamConfig, username: str, password: str) -> dict:
    upstream = RfbUpstream(cfg)
    try:
        await upstream.login(username, password)
        return {"cookies": dict(upstream._cookies), "logged_in": True}
    finally:
        await upstream.http.close()


async def release_second_login(cfg: UpstreamConfig, cookies: dict) -> dict:
    upstream = RfbUpstream(cfg)
    upstream._cookies = dict(cookies)
    upstream._logged_in = bool(cookies)
    try:
        cleaned = await upstream.close()
        return {"cleaned": cleaned, "outcome": upstream.last_logout_outcome,
                "status": upstream.last_logout_status}
    finally:
        await upstream.http.close()


def squeeze_verdict(evidence: dict) -> dict:
    reasons: list[str] = []
    if evidence.get("errors"):
        reasons.append("browser_errors")
    handshake = evidence.get("handshake") or {}
    if handshake.get("state") != "normal":
        reasons.append("console_not_normal")
    if (handshake.get("canvas") or {}).get("non_black", 0) <= 0:
        reasons.append("no_picture")
    if evidence.get("cuts"):
        reasons.append("upstream_was_cut_by_the_drill")
    if (evidence.get("squeeze_opened") or 0) < 1:
        reasons.append("no_extra_console_opened")

    session = evidence.get("session") or {}
    if session.get("status") not in TERMINAL_STATUSES:
        reasons.append("session_not_ended")
    if session.get("cleanup") != "confirmed":
        reasons.append("cleanup_not_confirmed")
    if "session_finished" not in (evidence.get("audit_actions") or []):
        reasons.append("end_not_audited")
    audit = evidence.get("audit_evidence")
    if not isinstance(audit, dict) or not audit:
        reasons.append("no_audit_evidence")
    else:
        if set(audit) - ALLOWED_EVIDENCE_KEYS:
            reasons.append("evidence_field_out_of_whitelist")
        if set(audit) & FORBIDDEN_EVIDENCE_KEYS:
            reasons.append("forbidden_evidence_field")
    if audit != evidence.get("session_end_evidence"):
        reasons.append("audit_row_disagrees")
    if evidence.get("sentinel_leaked"):
        reasons.append("credential_in_audit")
    if evidence.get("output_is_clean") is False:
        reasons.append("credential_in_output")

    rebuilt = (evidence.get("recovery") or {}).get("max_recoveries") or 0
    verdict = {"verdict": "pass" if not reasons else "fail", "reasons": reasons,
               "end_reason": session.get("reason"),
               "device_side_loss": bool(rebuilt >= 1)}
    verdict["device_outcome"] = ("device_evicted_our_console" if rebuilt >= 1
                                else "device_kept_our_console")
    return verdict


def stolen_session_verdict(evidence: dict) -> dict:
    base = refused_logout_verdict(evidence)
    reasons = list(base["reasons"])
    if evidence.get("steal_logged_in") is not True:
        reasons.append("second_login_did_not_succeed")
    if "cleanup_not_pending" in reasons:
        reasons.append("logout_was_accepted_after_a_second_login")
    return {"verdict": "pass" if not reasons else "fail", "reasons": reasons,
            "end_reason": base["end_reason"]}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--host", required=True, help="the real BMC; the relay forwards to it")
    parser.add_argument("--cert-sha256", required=True)
    parser.add_argument("--directory", default=".local-recovery-e2e")
    parser.add_argument("--protocol-versions", default="",
                        help="comma-separated RFB greetings approved for this device")
    parser.add_argument("--out")
    parser.add_argument("--screenshot", help="local PNG path; never committed")
    parser.add_argument("--hold-ms", type=int, default=14000,
                        help="how long the browser samples after READY")
    parser.add_argument("--cut-delay-ms", type=int, default=2500,
                        help="settle time after READY before resetting the upstream link")
    parser.add_argument("--cuts", type=int, default=1,
                        help="how many times to reset the upstream link in one session; "
                             "use policy_max_total + 1 to reach the ceiling")
    parser.add_argument("--cut-interval-ms", type=int, default=3000,
                        help="wait between a rebuilt console and the next reset")
    parser.add_argument("--rebuild-timeout", type=float, default=10.0,
                        help="how long a rebuilt upstream socket may take to appear")
    parser.add_argument("--input-shaping", default="",
                        help="JSON M2 policy for this run; a shaped session across a rebuild "
                             "is its own question, not a variant of an unshaped one")
    parser.add_argument("--squeeze-consoles", type=int, default=0, metavar="N",
                        help="after the console is up, open N extra consoles straight to the "
                             "BMC so the device, not the drill, decides which socket to close")
    parser.add_argument("--release-stolen-first", action="store_true",
                        help="log the second session out before leaving: if this BMC's logout "
                             "ends every session for the account, the gateway's own logout then "
                             "has nothing left to end")
    parser.add_argument("--steal-session", action="store_true",
                        help="log in again as the same account before leaving, so the BMC has "
                             "to decide whether the first web session still may log out")
    parser.add_argument("--refuse-logout", action="store_true",
                        help="no cut at all: open one console, leave it, and let the BMC "
                             "refuse the logout because --logout-path names an endpoint it "
                             "does not serve. Answers the one question --refuse-rebuild cannot")
    parser.add_argument("--logout-path", default="",
                        help="declare a different BMC logout endpoint for this capability. "
                             "A path the device does not serve is a reachable BMC that "
                             "refuses the logout -- the one case that used to be unmeasured")
    parser.add_argument("--refuse-rebuild", action="store_true",
                        help="after the first cut, stop accepting new upstream connections: "
                             "the rebuild fails with the budget still unspent")
    parser.add_argument("--hold-key", default="",
                        help="a key to hold down across the cut (e.g. Shift); the link is "
                             "reset as soon as the browser reports the press")
    parser.add_argument("--key-hold-ms", type=int, default=4000,
                        help="how long the key stays down, measured from the press")
    parser.add_argument("--idle-ms", type=int, default=5000,
                        help="length of the two quiet windows that bracket the hold")
    parser.add_argument("--end-timeout", type=float, default=45.0)
    parser.add_argument("--keep", action="store_true", help="keep the fixture directory")
    parser.add_argument("--playwright", default=os.environ.get("KVM_PLAYWRIGHT"))
    parser.add_argument("--chromium", default=os.environ.get("KVM_CHROMIUM"))
    parser.add_argument("--node", default="node")
    args = parser.parse_args()

    username = os.environ.get("BMC_USER")
    credential = os.environ.get("BMC_PASSWORD")
    if not username or not credential:
        parser.error("BMC_USER and BMC_PASSWORD must be set")
    fingerprint = args.cert_sha256.replace(":", "").lower()
    if len(fingerprint) != 64 or any(c not in "0123456789abcdef" for c in fingerprint):
        parser.error("--cert-sha256 must be 64 hex characters")
    if args.squeeze_consoles:
        if (args.refuse_rebuild or args.hold_key or args.refuse_logout
                or args.steal_session or args.logout_path):
            parser.error("--squeeze-consoles answers a different question; run it alone")
        if args.cuts != 1:
            parser.error("--squeeze-consoles does not cut; leave --cuts at its default")
        if args.squeeze_consoles > 6:
            parser.error("--squeeze-consoles is capped at 6: the measured ceiling is 4")
        args.cuts = 0
    if args.release_stolen_first and not args.steal_session:
        parser.error("--release-stolen-first only makes sense with --steal-session")
    if args.steal_session:
        if args.refuse_rebuild or args.hold_key or args.refuse_logout or args.logout_path:
            parser.error("--steal-session answers a different question; run it alone")
        if args.cuts != 1:
            parser.error("--steal-session does not cut; leave --cuts at its default")
        args.cuts = 0
    if args.refuse_logout:
        if not args.logout_path:
            parser.error("--refuse-logout needs --logout-path: the refusal has to come "
                         "from the device, not from a drill-side cut")
        if args.refuse_rebuild or args.hold_key:
            parser.error("--refuse-logout answers a different question; run it alone")
        if args.cuts != 1:
            parser.error("--refuse-logout does not cut; leave --cuts at its default")
        args.cuts = 0
    if args.cuts < 1 and not (args.refuse_logout or args.steal_session or args.squeeze_consoles):
        parser.error("--cuts must be at least 1")
    if args.refuse_rebuild and args.cuts != 1:
        parser.error("--refuse-rebuild needs exactly one cut: the session ends after it")
    if args.hold_key:
        if args.cuts != 1:
            parser.error("--hold-key needs exactly one cut: the hold is a one-shot timeline")
        if args.refuse_rebuild:
            parser.error("--hold-key and --refuse-rebuild answer different questions; run them apart")
        needed = 2 * args.idle_ms + args.key_hold_ms + 3000
        if args.hold_ms < needed:
            parser.error(f"--hold-key needs --hold-ms of at least {needed} "
                         f"(2x{args.idle_ms} idle + {args.key_hold_ms} held + 3000 settle)")
    if args.cuts > 1 and args.cuts < RecoveryPolicy.max_total + 1:
        print(f"note: --cuts {args.cuts} stays under the ceiling of "
              f"{RecoveryPolicy.max_total + 1} losses; the cap will not be reached",
              file=sys.stderr)
    try:
        shaping = shaping_from_arg(args.input_shaping)
    except ValueError as exc:
        parser.error(f"--input-shaping rejected: {exc}")
    versions = tuple(v.strip() for v in args.protocol_versions.split(",") if v.strip())
    module = args.playwright or _find_playwright()
    chromium = args.chromium or _find_chromium()
    if not module or not chromium:
        parser.error("playwright-core and a Chromium build are required (see tools/browser_e2e.py)")

    directory = ROOT / args.directory
    if directory.exists():
        parser.error(f"{directory} already exists; choose a fresh --directory")

    relay = CutRelay(args.host, 443).start()
    root, key, target = prepare(directory, f"127.0.0.1:{relay.port}", fingerprint,
                                username, credential, versions, input_shaping=shaping,
                                logout_path=args.logout_path or None)
    manager_token = (root / "login-token").read_text().strip()
    asset = "real-1"

    ctx = multiprocessing.get_context("spawn")
    processes = [
        ctx.Process(target=manager_process, args=(str(root / "manager.json"),), name="manager"),
        ctx.Process(target=worker_process, args=(str(root / "worker.json"),), name="worker"),
    ]
    evidence = {"recorded_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
                "target_host": args.host, "asset": asset, "via_relay": True,
                "adapter": "supermicro-x10-passthrough",
                "approved_protocol_versions": list(versions),
                "hold_ms": args.hold_ms, "cut_delay_ms": args.cut_delay_ms,
                "errors": []}
    exit_code = 1
    store = None
    browser = None
    try:
        for process in processes:
            process.start()
        evidence["services_ready"] = wait_port(UI_PORT) and wait_port(WORKER_PORT)
        if not evidence["services_ready"]:
            evidence["errors"].append("services_not_ready")
            return 1

        manager = Manager(root, UI_ORIGIN)
        manager.login(manager_token)
        store = Store(root / "manager.sqlite3", key, passthrough_targets=(target,))

        browser, handshake, lines, stderr_lines, key_lines = run_recovery_browser(
            args.node, module, chromium, UI_ORIGIN, manager_token, asset,
            args.hold_ms, args.screenshot, args.hold_key, args.key_hold_ms, args.idle_ms)
        if handshake is None:
            evidence["errors"].append("browser_never_reached_normal")
            result, code = finish_browser(browser, lines, stderr_lines)
            evidence["browser"] = {k: result.get(k) for k in ("steps", "errors", "console_errors")}
            evidence["browser_exit"] = code
            ended = store.db.execute(
                "SELECT id,status,cleanup,reason FROM session "
                "ORDER BY created DESC LIMIT 1").fetchone()
            if ended is not None:
                evidence["early_session"] = {k: ended[k] for k in
                                             ("status", "cleanup", "reason")}
                evidence["early_audit_evidence"] = _detail_evidence(store, ended["id"])
            evidence["verdict"] = "fail"
            return 1

        active = store.db.execute(
            "SELECT id FROM session WHERE status IN ('active','connecting') "
            "ORDER BY created DESC LIMIT 1").fetchone()
        if not active:
            evidence["errors"].append("no_active_session")
            evidence["verdict"] = "fail"
            return 1
        sid = active["id"]
        evidence["session_id_prefix"] = mask_sid(sid)
        evidence["handshake"] = {"state": handshake.get("state"),
                                 "canvas": handshake.get("canvas"),
                                 "client_bytes": handshake.get("client_bytes"),
                                 "sid_matches": handshake.get("sid") == sid}
        slot = store.db.execute(
            "SELECT session_id FROM asset_slot WHERE asset_id=?", (asset,)).fetchone()
        evidence["slot_held_before_cut"] = bool(slot and slot["session_id"] == sid)
        relay.forget_closed()
        evidence["connections_before_cut"] = relay.connections
        evidence["accepted_before_cut"] = relay.accepted
        evidence["cuts_requested"] = args.cuts
        evidence["rebuild_refused"] = bool(args.refuse_rebuild)
        evidence["refused_logout"] = bool(args.refuse_logout)
        evidence["steal_session"] = bool(args.steal_session)
        evidence["steal_released_first"] = evidence.get("steal_released_first")
        evidence["logout_path"] = args.logout_path or None
        evidence["input_shaping"] = shaping
        evidence["policy_max_total"] = RecoveryPolicy.max_total

        squeezed: dict = {}
        squeeze_stop = threading.Event()
        if args.squeeze_consoles:
            threading.Thread(target=_squeeze_worker, daemon=True,
                             args=(args.host, fingerprint, username, credential,
                                   args.squeeze_consoles, squeeze_stop, squeezed)).start()
            time.sleep(3)
            evidence["squeeze_requested"] = args.squeeze_consoles
            evidence["squeeze_opened"] = squeezed.get("opened", 0)
            evidence["squeeze_error"] = squeezed.get("error")

        stolen: dict | None = None
        if args.steal_session:
            try:
                stolen = asyncio.run(second_login(_bmc_config(args.host, fingerprint),
                                                 username, credential))
                evidence["steal_logged_in"] = True
                if args.release_stolen_first:
                    evidence["steal_released_first"] = asyncio.run(
                        release_second_login(_bmc_config(args.host, fingerprint),
                                             stolen.get("cookies") or {}))
                    stolen = None
            except Exception as exc:  # noqa: BLE001 - the evidence says what broke
                evidence["steal_logged_in"] = False
                evidence["steal_error"] = type(exc).__name__
                evidence["errors"].append("second_login_failed")

        cuts: list[dict] = []
        ended_at_cut = None
        for index in range(1, args.cuts + 1):
            if args.hold_key:
                press = None
                deadline = time.monotonic() + args.hold_ms / 1000 + 15
                while time.monotonic() < deadline:
                    try:
                        event = key_lines.get(timeout=0.2)
                    except queue.Empty:
                        event = None
                    if event and event.get("phase") == "down":
                        press = event
                        break
                    if store.get(sid)["status"] in TERMINAL_STATUSES:
                        break
                evidence["key_press"] = press
                if press is None:
                    evidence["errors"].append("key_was_never_pressed")
                    break
            else:
                time.sleep((args.cut_delay_ms if index == 1 else args.cut_interval_ms) / 1000)
            current = store.get(sid)
            if current["status"] in TERMINAL_STATUSES:
                evidence["errors"].append(f"session_ended_before_cut_{index}")
                break
            reset = relay.cut()
            cut_at = int(time.time() * 1000)
            if args.refuse_rebuild and index == 1:
                evidence["listener_closed"] = relay.close_listener()
                evidence["rebuild_refused_at_cut"] = index
            down_before = relay.bytes_down
            deadline = time.monotonic() + args.rebuild_timeout
            event = None
            while time.monotonic() < deadline:
                event = recovery_event(lines, cut_at, index)
                if event is not None:
                    break
                if store.get(sid)["status"] in TERMINAL_STATUSES:
                    break
                time.sleep(0.1)
            current = store.get(sid)
            server = (event or {}).get("server") or {}
            cuts.append({"index": index, "sockets_reset": reset, "cut_at_ms": cut_at,
                         "recovery_ms": (event["at"] - cut_at) if event else None,
                         "observed_recoveries": server.get("recoveries"),
                         "frames_bytes": relay.bytes_down - down_before,
                         "new_connections": relay.connections,
                         "session_status": current["status"],
                         "session_reason": current["reason"]})
            if index == 1:
                evidence["cut"] = {"sockets_reset": reset, "at_ms": cut_at}
                evidence["new_upstream_connections"] = relay.connections
                evidence["session_after_cut"] = {k: current[k] for k in
                                                 ("status", "cleanup", "reason")}
            if current["status"] in TERMINAL_STATUSES:
                ended_at_cut = index
                break
        if args.refuse_rebuild:
            terminal, _ = wait_for(
                lambda: (store.get(sid) if store.get(sid)["status"] in TERMINAL_STATUSES else None),
                args.end_timeout)
            evidence["session"] = ({k: terminal[k] for k in ("status", "cleanup", "reason")}
                                   if terminal else None)
        evidence["cuts"] = cuts
        evidence["ended_at_cut"] = ended_at_cut
        if relay.accepts:
            origin = relay.accepts[0]
            evidence["accept_timeline_ms"] = [round((t - origin) * 1000) for t in relay.accepts]
        if not cuts and not (args.refuse_logout or args.steal_session or args.squeeze_consoles):
            evidence["errors"].append("no_socket_to_reset")

        squeeze_stop.set()
        squeeze_stop.set()
        result, code = finish_browser(browser, lines, stderr_lines)
        evidence["browser_exit"] = code
        if stderr_lines:
            evidence["browser_stderr_tail"] = "".join(stderr_lines)[-400:]
        evidence["browser"] = {k: result.get(k) for k in
                               ("steps", "errors", "console_errors", "http_404")}
        if result.get("errors"):
            evidence["errors"].extend(str(e)[:120] for e in result["errors"][:3])
        recovery = result.get("recovery") or {}
        evidence["recovery"] = recovery
        evidence["canvas_after_cut"] = result.get("canvas_after_cut")
        evidence["connections_after_cut"] = relay.connections
        evidence["accepted_after_cut"] = relay.accepted

        def ended():
            current = store.get(sid)
            return current if current["status"] in TERMINAL_STATUSES else None

        terminal, _ = wait_for(ended, args.end_timeout)
        if terminal is None:
            evidence["fallback_revoke"] = True
            status, body = manager.revoke(sid)
            evidence["revoke_status"] = status
            evidence["revoke_body"] = body
            terminal, _ = wait_for(ended, args.end_timeout)
        final = terminal or store.get(sid)
        evidence["session"] = {k: final[k] for k in ("status", "cleanup", "reason")}
        evidence["cleanup_pending"] = bool(final["cleanup"] == "pending")
        slot = store.db.execute(
            "SELECT session_id FROM asset_slot WHERE asset_id=?", (asset,)).fetchone()
        evidence["slot_released"] = bool(slot is None or slot["session_id"] is None)
        evidence["audit_actions"] = audit_actions(store, sid)
        evidence["audit_evidence"] = _detail_evidence(store, sid)
        evidence["session_end_evidence"] = _stored_evidence(store, sid)
        evidence["cleanup_outcome"] = (evidence["audit_evidence"] or {}).get("cleanup_outcome")
        if stolen and stolen.get("cookies"):
            try:
                evidence["steal_logout"] = asyncio.run(
                    release_second_login(_bmc_config(args.host, fingerprint), stolen["cookies"]))
            except Exception as exc:  # noqa: BLE001 - recorded, not swallowed
                evidence["steal_logout"] = {"cleaned": False, "error": type(exc).__name__}

        detail_row = store.db.execute(
            "SELECT detail FROM audit WHERE session_id=? AND action='session_finished' "
            "ORDER BY id LIMIT 1", (sid,)).fetchone()
        detail_text = detail_row["detail"] if detail_row else ""
        detail_markers = [credential, username, os.environ.get("KVM_SECRET", ""), sid]
        output_markers = [credential, os.environ.get("KVM_SECRET", "")]
        evidence["sentinel_leaked"] = not output_is_clean({"detail": detail_text}, detail_markers)
        evidence["output_is_clean"] = output_is_clean(evidence, output_markers)

        if args.squeeze_consoles:
            verdict = squeeze_verdict(evidence)
        elif args.steal_session:
            verdict = stolen_session_verdict(evidence)
        elif args.refuse_logout:
            verdict = refused_logout_verdict(evidence)
        elif args.hold_key:
            evidence["hold_key"] = args.hold_key
            evidence["key_hold_ms"] = args.key_hold_ms
            evidence["idle_window_ms"] = args.idle_ms
            evidence["key_press"] = evidence.get("key_press")
            verdict = held_key_verdict(evidence)
        elif args.refuse_rebuild:
            verdict = refused_rebuild_verdict(evidence)
        elif len(cuts) <= 1:
            verdict = recovery_evidence_verdict(evidence)
        else:
            verdict = multi_cut_verdict(evidence)
        evidence.update(verdict)
        exit_code = 0 if verdict["verdict"] == "pass" and evidence["output_is_clean"] else 1
    finally:
        if store is not None:
            store.close()
        if browser is not None and browser.poll() is None:
            browser.kill()
        relay.stop()
        for process in processes:
            if process.is_alive():
                process.terminate()
        for process in processes:
            process.join(timeout=10)
            if process.is_alive():
                process.kill()
                process.join()
        if args.out:
            out = Path(args.out)
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_text(json.dumps(evidence, indent=2, ensure_ascii=False) + "\n",
                           encoding="utf-8")
        if not args.keep:
            shutil.rmtree(root, ignore_errors=True)
    print(json.dumps({k: evidence.get(k) for k in
                      ("verdict", "reasons", "errors", "handshake", "cut", "cuts",
                       "ended_at_cut", "policy_max_total", "recovery", "accept_timeline_ms",
                       "rebuild_refused", "listener_closed", "refused_logout", "logout_path",
                       "steal_session", "steal_logged_in", "steal_logout",
                       "squeeze_requested", "squeeze_opened", "squeeze_error", "device_outcome",
                       "device_side_loss",
                       "input_shaping", "slot_released",
                       "hold_key", "key_hold_ms", "idle_window_ms", "key_press",
                       "stuck_watch", "cleanup_pending", "cleanup_outcome",
                       "connections_before_cut", "accepted_before_cut",
                       "connections_after_cut", "accepted_after_cut", "new_upstream_connections",
                       "session_after_cut", "session", "audit_actions",
                       "audit_evidence", "session_end_evidence", "output_is_clean",
                       "early_session", "early_audit_evidence")},
                     indent=2, ensure_ascii=False))
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
