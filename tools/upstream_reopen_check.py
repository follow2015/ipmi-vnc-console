#!/usr/bin/env python3
"""Measure whether a real BMC console can be re-opened without logging in again."""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
import time
from pathlib import Path

import aiohttp

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from kvmhub.ast2100_protocol import RFB_VERSION
from kvmhub.common import Problem
from kvmhub.rfb_upstream import RfbUpstream, UpstreamConfig

SCENARIOS = ("clean", "abort", "stale", "idle", "fanout", "logout", "relogin")


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--host", default=os.environ.get("KVM_BMC_HOST", ""))
    p.add_argument("--port", type=int, default=443)
    p.add_argument("--cert-sha256", required=True, help="pinned certificate SHA-256 (64 hex)")
    p.add_argument("--scenario", default="all", choices=(*SCENARIOS, "all"))
    p.add_argument("--frames", type=int, default=2, help="updates to wait for per step")
    p.add_argument("--idle", type=float, default=20.0, help="seconds between drop and re-open")
    p.add_argument("--fanout", type=int, default=5, help="console sockets to stack up")
    p.add_argument("--connector-limit", type=int, default=16,
                   help="probe-owned pool size; keep it well above --fanout so a "
                        "refusal is the BMC's and not our own queue")
    p.add_argument("--protocol-versions", default="",
                   help="comma-separated RFB greetings approved for this device")
    p.add_argument("--out", help="write the redacted report here")
    return p


def _code(exc: BaseException) -> str:
    return getattr(exc, "code", None) or type(exc).__name__


class Step:

    def __init__(self, name: str) -> None:
        self.name = name
        self.ok = False
        self.error: str | None = None
        self.ms = 0.0

    async def run(self, coro) -> bool:
        started = time.monotonic()
        try:
            await coro
            self.ok = True
        except Problem as exc:
            self.error = _code(exc)
        except Exception as exc:  # noqa: BLE001 - a probe must report, not crash
            self.error = type(exc).__name__
        finally:
            self.ms = round((time.monotonic() - started) * 1000, 1)
        return self.ok

    def as_dict(self) -> dict:
        out = {"ok": self.ok, "ms": self.ms}
        if self.error:
            out["error"] = self.error
        return out


def _transport(args) -> RfbUpstream:
    versions = tuple(v.strip() for v in args.protocol_versions.split(",") if v.strip())
    cfg = UpstreamConfig(host=args.host, port=args.port, scheme="https",
                         cert_sha256=args.cert_sha256,
                         protocol_versions=versions or (RFB_VERSION.strip(),))
    session = aiohttp.ClientSession(
        connector=aiohttp.TCPConnector(
            ssl=aiohttp.Fingerprint(bytes.fromhex(args.cert_sha256)),
            limit=args.connector_limit),
        cookie_jar=aiohttp.DummyCookieJar(), trust_env=False, auto_decompress=False,
        timeout=aiohttp.ClientTimeout(total=None, connect=cfg.request_timeout))
    upstream = RfbUpstream(cfg, session=session)
    upstream.probe_http = session
    return upstream


async def _login(upstream: RfbUpstream, step_name: str = "login") -> Step:
    step = Step(step_name)
    await step.run(upstream.login(os.environ["BMC_USER"], os.environ["BMC_PASSWORD"]))
    return step


def _console_shape(upstream: RfbUpstream, before_frames: int) -> dict:
    return {"frames": upstream.stats.frames - before_frames,
            "width": upstream.stats.width, "height": upstream.stats.height,
            "init": upstream.init_event, "close_code": upstream.upstream_close_code}


async def _cleanup(upstream: RfbUpstream | None, *, close_http: bool = True) -> str:
    if upstream is None:
        return "skipped"
    result = "error"
    try:
        result = await upstream.close()
    except Exception as exc:  # noqa: BLE001
        result = f"error:{type(exc).__name__}"
    finally:
        session = getattr(upstream, "probe_http", None)
        if close_http and session is not None:
            await session.close()
    return result


async def scenario_clean(args) -> dict:
    up = _transport(args)
    report: dict = {}
    try:
        report["login"] = (await _login(up)).as_dict()
        opened = Step("open")
        await opened.run(up.open(request_frames=True))
        report["open"] = opened.as_dict()
        if not opened.ok:
            return report
        await up.wait_frames(args.frames)
        before = up.stats.frames
        report["first_console"] = _console_shape(up, 0)

        dropped = Step("drop_websocket")
        await dropped.run(up.drop_websocket(code=1001))
        report["drop"] = dropped.as_dict()

        reopened = Step("reopen")
        await reopened.run(up.reopen())
        report["reopen"] = reopened.as_dict()
        if reopened.ok:
            await up.wait_frames(args.frames)
            report["second_console"] = _console_shape(up, before)
    finally:
        report["cleanup"] = await _cleanup(up)
    return report


def _abort_transport(upstream: RfbUpstream) -> bool:
    ws = upstream._ws
    connection = getattr(getattr(ws, "_response", None), "connection", None)
    transport = getattr(connection, "transport", None) or getattr(
        getattr(ws, "_writer", None), "transport", None)
    if transport is None:
        return False
    transport.abort()
    return True


async def scenario_abort(args) -> dict:
    up = _transport(args)
    report: dict = {}
    try:
        report["login"] = (await _login(up)).as_dict()
        opened = Step("open")
        await opened.run(up.open(request_frames=True))
        report["open"] = opened.as_dict()
        if not opened.ok:
            return report
        await up.wait_frames(args.frames)
        before = up.stats.frames
        report["first_console"] = _console_shape(up, 0)

        reset = Step("abort_transport")
        await reset.run(_abort_now(up))
        report["reset"] = reset.as_dict()
        report["reset_reachable"] = True

        reopened = Step("reopen_after_reset")
        await reopened.run(up.reopen())
        report["reopen"] = reopened.as_dict()
        if reopened.ok:
            await up.wait_frames(args.frames)
            report["second_console"] = _console_shape(up, before)
    finally:
        report["cleanup"] = await _cleanup(up)
    return report


async def _abort_now(upstream: RfbUpstream) -> bool:
    if not _abort_transport(upstream):
        raise RuntimeError("transport_not_reachable")
    await asyncio.sleep(0.2)
    return True


async def scenario_stale(args) -> dict:
    up = _transport(args)
    report: dict = {}
    try:
        report["login"] = (await _login(up)).as_dict()
        first = Step("open_first")
        await first.run(up.open(request_frames=True))
        report["open_first"] = first.as_dict()
        if not first.ok:
            return report
        await up.wait_frames(args.frames)
        report["first_console"] = _console_shape(up, 0)

        old = up._ws
        before = up.stats.frames
        second = Step("open_second")
        await second.run(up.open(request_frames=True))
        report["open_second"] = second.as_dict()
        if second.ok:
            await up.wait_frames(args.frames)
            report["second_console"] = _console_shape(up, before)
        await asyncio.sleep(0.6)
        report["first_socket_after_second_open"] = {
            "closed": bool(old is not None and old.closed),
            "close_code": None if old is None else old.close_code,
        }
    finally:
        report["cleanup"] = await _cleanup(up)
    return report


async def scenario_idle(args) -> dict:
    up = _transport(args)
    report: dict = {"idle_seconds": args.idle}
    try:
        report["login"] = (await _login(up)).as_dict()
        opened = Step("open")
        await opened.run(up.open(request_frames=True))
        report["open"] = opened.as_dict()
        if not opened.ok:
            return report
        await up.wait_frames(args.frames)
        report["first_console"] = _console_shape(up, 0)

        await up.drop_websocket(code=1001)
        await asyncio.sleep(args.idle)

        before = up.stats.frames
        reopened = Step("reopen")
        await reopened.run(up.reopen())
        report["reopen"] = reopened.as_dict()
        report["session_gone"] = reopened.error == "bmc_auth_failed"
        if reopened.ok:
            await up.wait_frames(args.frames)
            report["second_console"] = _console_shape(up, before)
    finally:
        report["cleanup"] = await _cleanup(up)
    return report


async def scenario_fanout(args) -> dict:
    up = _transport(args)
    report: dict = {"requested": args.fanout}
    sockets: list = []
    try:
        report["login"] = (await _login(up)).as_dict()
        results = []
        for index in range(args.fanout):
            step = Step(f"open_{index + 1}")
            await step.run(up.open(request_frames=True))
            entry = step.as_dict()
            if step.ok:
                sockets.append(up._ws)
                frames = Step(f"frames_{index + 1}")
                await frames.run(up.wait_frames(1, timeout=6.0))
                entry["frames"] = frames.as_dict()
            results.append(entry)
            if not step.ok:
                break
        report["opens"] = results
        report["accepted"] = len(sockets)
        await asyncio.sleep(0.5)
        report["still_open_before_logout"] = [not s.closed for s in sockets]
    finally:
        up._ws = None
        report["cleanup"] = await _cleanup(up)
        report["logout_status"] = up.last_logout_status
        await asyncio.sleep(1.5)
        report["orphans_after_logout"] = [{"closed": bool(s.closed),
                                           "close_code": s.close_code} for s in sockets]
    return report


async def scenario_logout(args) -> dict:
    up = _transport(args)
    report: dict = {}
    orphan = None
    try:
        report["login"] = (await _login(up)).as_dict()
        opened = Step("open")
        await opened.run(up.open(request_frames=True))
        report["open"] = opened.as_dict()
        if not opened.ok:
            return report
        await up.wait_frames(args.frames)
        report["console"] = _console_shape(up, 0)

        orphan = up._ws
        up._ws = None
        report["cleanup"] = await _cleanup(up, close_http=False)
        report["logout_status"] = up.last_logout_status
        await asyncio.sleep(1.0)
        report["console_closed_by_logout"] = bool(orphan is not None and orphan.closed)
        report["console_close_code"] = None if orphan is None else orphan.close_code

        if orphan is not None and not orphan.closed:
            drained = 0
            while True:
                try:
                    message = await asyncio.wait_for(orphan.receive(), 0.25)
                except (TimeoutError, asyncio.TimeoutError):
                    break
                drained += 1
                if message.type is not aiohttp.WSMsgType.BINARY:
                    break
            report["drained_before_probe"] = drained
            up._ws = orphan
            alive = Step("frame_after_logout")
            await alive.run(up.wait_frames(1, timeout=5.0))
            report["console_answers_after_logout"] = alive.ok
            report["frame_after_logout"] = alive.as_dict()
            up._ws = None
    finally:
        if not report.get("cleanup"):
            report["cleanup"] = await _cleanup(up)
        else:
            session = getattr(up, "probe_http", None)
            if session is not None:
                await session.close()
    return report


async def scenario_relogin(args) -> dict:
    first = _transport(args)
    second = None
    report: dict = {}
    try:
        report["login_first"] = (await _login(first, "login_first")).as_dict()
        opened = Step("open")
        await opened.run(first.open(request_frames=True))
        report["open"] = opened.as_dict()
        if not opened.ok:
            return report
        await first.wait_frames(args.frames)
        report["first_console"] = _console_shape(first, 0)
        watch = first._ws

        second = _transport(args)
        relogin = await _login(second, "login_second")
        report["login_second"] = relogin.as_dict()
        await asyncio.sleep(0.8)
        report["first_socket_after_second_login"] = {
            "closed": bool(watch is not None and watch.closed),
            "close_code": None if watch is None else watch.close_code,
        }
        if watch is not None and not watch.closed:
            while True:
                try:
                    message = await asyncio.wait_for(watch.receive(), 0.25)
                except (TimeoutError, asyncio.TimeoutError):
                    break
                if message.type is not aiohttp.WSMsgType.BINARY:
                    break
            still_fed = Step("first_console_frame_after_second_login")
            await still_fed.run(first.wait_frames(1, timeout=4.0))
            report["first_console_answers_after_second_login"] = still_fed.ok
            report["first_console_probe"] = still_fed.as_dict()
        if relogin.ok:
            opened2 = Step("open_second_session")
            await opened2.run(second.open(request_frames=True))
            report["open_second_session"] = opened2.as_dict()
            if opened2.ok:
                await second.wait_frames(args.frames)
                report["second_console"] = _console_shape(second, 0)
    finally:
        report["cleanup_second"] = await _cleanup(second)
        report["cleanup_first"] = await _cleanup(first)
    return report


RUNNERS = {"clean": scenario_clean, "abort": scenario_abort, "stale": scenario_stale,
           "idle": scenario_idle, "fanout": scenario_fanout,
           "logout": scenario_logout, "relogin": scenario_relogin}


def _fed(fanout: dict) -> int | None:
    opens = fanout.get("opens")
    if not opens:
        return None
    return sum(1 for entry in opens if (entry.get("frames") or {}).get("ok"))


def _muted(fanout: dict) -> int | None:
    opens = fanout.get("opens")
    if not opens:
        return None
    return sum(1 for entry in opens
               if entry.get("ok") and not (entry.get("frames") or {}).get("ok"))


def verdict(report: dict) -> dict:
    clean = report.get("clean") or {}
    stale = report.get("stale") or {}
    idle = report.get("idle") or {}
    abort = report.get("abort") or {}
    fanout = report.get("fanout") or {}
    logout = report.get("logout") or {}
    relogin = report.get("relogin") or {}
    reopen_ok = bool((clean.get("reopen") or {}).get("ok"))
    return {
        "same_session_reopen": reopen_ok,
        "reopen_ms": (clean.get("reopen") or {}).get("ms"),
        "second_socket_while_first_open": bool((stale.get("open_second") or {}).get("ok")),
        "old_socket_killed_by_second": (stale.get("first_socket_after_second_open")
                                        or {}).get("closed"),
        "session_survives_idle_gap": (idle.get("session_gone") is False
                                      if "session_gone" in idle else None),
        "consoles_fed_per_session": _fed(fanout),
        "consoles_closed_right_after_handshake": _muted(fanout),
        "logout_closes_console_sockets": (all(o["closed"] for o in
                                            fanout.get("orphans_after_logout") or [])
                                        if fanout.get("orphans_after_logout") else None),
        "console_survives_logout": logout.get("console_answers_after_logout"),
        "recovers_after_a_reset": bool((abort.get("reopen") or {}).get("ok")
                                       and (abort.get("second_console") or {}).get("frames", 0)),
        "second_login_kills_first": (relogin.get("first_socket_after_second_login")
                                     or {}).get("closed"),
        "second_login_mutes_first": (relogin.get("first_console_answers_after_second_login")
                                     is False),
        "kick_user_enable": ((clean.get("first_console") or {}).get("init") or {}
                             ).get("kick_user_enable"),
    }


async def main(args) -> int:
    if not args.host:
        print("missing --host or KVM_BMC_HOST", file=sys.stderr)
        return 2
    if not os.environ.get("BMC_USER") or not os.environ.get("BMC_PASSWORD"):
        print("BMC_USER and BMC_PASSWORD must be set; credentials are never arguments",
              file=sys.stderr)
        return 2
    chosen = SCENARIOS if args.scenario == "all" else (args.scenario,)
    report: dict = {"host": args.host, "scenarios": {}}
    for name in chosen:
        scenario = await RUNNERS[name](args)
        report["scenarios"][name] = scenario
        print(f"[{name}] " + json.dumps(scenario, ensure_ascii=False), flush=True)
    report["verdict"] = verdict(report["scenarios"])
    print("[verdict] " + json.dumps(report["verdict"], ensure_ascii=False))
    if args.out:
        path = Path(args.out)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"report -> {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main(parser().parse_args())))
