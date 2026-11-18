"""Concurrent data-plane benchmark (synthetic BMC, real relay path)."""
from __future__ import annotations

import argparse
import asyncio
import ctypes
import json
import statistics
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import aiohttp  # noqa: E402
from aiohttp import WSMsgType  # noqa: E402
from aiohttp.test_utils import TestServer  # noqa: E402
from cryptography import x509  # noqa: E402
from cryptography.hazmat.primitives import hashes  # noqa: E402

from kvmhub.adapter import MockAdapter  # noqa: E402
from kvmhub.common import WORKER_PORT, digest, server_tls  # noqa: E402
from kvmhub.mock_bmc import create_mock  # noqa: E402
from kvmhub.worker import GATEWAY_KEY, Runtime, create_worker  # noqa: E402
from tools.bootstrap import generate  # noqa: E402

BROWSER_SECRET = "bench-browser-placeholder"
SYNTHETIC_USER = "bench-user"
SYNTHETIC_PASS = "bench-password"


def _rss_bytes() -> int:
    if sys.platform == "win32":
        from ctypes import wintypes
        try:
            class _Counters(ctypes.Structure):
                _fields_ = [("cb", wintypes.DWORD), ("PageFaultCount", wintypes.DWORD),
                            ("PeakWorkingSetSize", ctypes.c_size_t),
                            ("WorkingSetSize", ctypes.c_size_t),
                            ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
                            ("QuotaPagedPoolUsage", ctypes.c_size_t),
                            ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
                            ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                            ("PagefileUsage", ctypes.c_size_t),
                            ("PeakPagefileUsage", ctypes.c_size_t)]
            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)  # type: ignore[attr-defined]
            kernel32.GetCurrentProcess.restype = wintypes.HANDLE
            kernel32.GetCurrentProcess.argtypes = []
            handle = kernel32.GetCurrentProcess()
            getter = getattr(kernel32, "K32GetProcessMemoryInfo", None)
            if getter is None:  # pragma: no cover - older Windows
                getter = ctypes.WinDLL("psapi", use_last_error=True).GetProcessMemoryInfo  # type: ignore[attr-defined]
            getter.argtypes = [wintypes.HANDLE, ctypes.POINTER(_Counters), wintypes.DWORD]
            getter.restype = wintypes.BOOL
            counters = _Counters()
            counters.cb = ctypes.sizeof(_Counters)
            ok = getter(handle, ctypes.byref(counters), counters.cb)
            return int(counters.WorkingSetSize) if ok else 0
        except (AttributeError, OSError):
            return 0
    try:
        import resource
    except ImportError:
        return 0
    value = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return value * (1 if sys.platform == "darwin" else 1024)


def _cpu_seconds() -> float:
    return time.process_time()


def _cpu_ns() -> int:
    return time.process_time_ns()


async def _one_console(browser, url, sid, *, seconds):
    host = f"w1-{sid}.kvm.localhost:{WORKER_PORT}"
    headers = {"Host": host, "Origin": f"https://{host}",
               "Cookie": "__Host-kvm_sid=" + BROWSER_SECRET}
    received = 0
    bytes_in = 0
    dropped = False
    error = ""
    async with browser.ws_connect(url, protocols=("binary",), headers=headers) as ws:
        deadline = time.monotonic() + seconds
        sent = 0
        while time.monotonic() < deadline:
            if sent < max(1, int(seconds * 4)):
                await ws.send_bytes(f"input-{sid[:4]}-{sent}".encode())
                sent += 1
            try:
                msg = await ws.receive(timeout=0.5)
            except asyncio.TimeoutError:
                continue
            if msg.type in (WSMsgType.BINARY, WSMsgType.TEXT):
                received += 1
                bytes_in += len(msg.data if isinstance(msg.data, bytes) else msg.data.encode())
            elif msg.type in (WSMsgType.CLOSE, WSMsgType.ERROR, WSMsgType.CLOSED):
                dropped = True
                break
    return {"sid": sid, "received": received, "bytes_in": bytes_in,
            "dropped": dropped, "error": error}


async def run_probe(*, sessions: int, seconds: int, tmp_path: Path) -> dict:
    directory = generate(tmp_path / "identity")
    cfg = json.loads((Path(directory) / "worker.json").read_text())

    upstream_app = create_mock(SYNTHETIC_USER, SYNTHETIC_PASS)
    upstream = TestServer(upstream_app, scheme="https")
    await upstream.start_server(ssl=server_tls(cfg["server_cert"], cfg["server_key"]))

    app = create_worker(cfg)
    app.on_startup.clear()
    app.on_cleanup.clear()
    gateway = app[GATEWAY_KEY]
    reports = []

    async def call(sid, op, data=None):
        reports.append((op, data))
        return {"ok": True}
    gateway.call = call

    cert = x509.load_pem_x509_certificate(Path(cfg["server_cert"]).read_bytes())
    fingerprint = cert.fingerprint(hashes.SHA256()).hex()
    target = str(upstream.make_url("/")).rstrip("/")

    runtimes = []
    try:
        for index in range(sessions):
            adapter = MockAdapter({"target": target, "fingerprint": fingerprint,
                                   "adapter": "mock-v1"})
            await adapter.login(SYNTHETIC_USER, SYNTHETIC_PASS)
            sid = f"{index + 1:032x}"
            runtime = Runtime(sid, digest(BROWSER_SECRET), adapter, time.monotonic() + 60)
            gateway.sessions[sid] = runtime
            runtimes.append(runtime)

        async with TestServer(app) as server:
            url = server.make_url("/console")
            rss_before = _rss_bytes()
            cpu_before = _cpu_ns()
            started = time.monotonic()
            async with aiohttp.ClientSession() as browser:
                results = await asyncio.gather(
                    *(_one_console(browser, url, rt.sid, seconds=seconds) for rt in runtimes))
            elapsed = time.monotonic() - started
            cpu_after = _cpu_ns()
            rss_after = _rss_bytes()
    finally:
        revoke_started = time.monotonic()
        await asyncio.gather(*(gateway.finish(rt, "revoked") for rt in runtimes))
        revoke_seconds = time.monotonic() - revoke_started
        for adapter in (rt.adapter for rt in runtimes):
            await adapter.close()
        await upstream.close()

    delivered = [r for r in results if not r["dropped"] and r["received"] > 0]
    dropped = [r for r in results if r["dropped"]]
    bytes_total = sum(r["bytes_in"] for r in results)
    frames_total = sum(r["received"] for r in results)
    per_console = [r["received"] for r in results]

    report = {
        "sessions": sessions,
        "seconds": seconds,
        "connections": {
            "opened": len(results),
            "delivered": len(delivered),
            "dropped": len(dropped),
            "no_loss": len(delivered) == len(results),
        },
        "throughput": {
            "frames_total": frames_total,
            "bytes_total": bytes_total,
            "frames_per_second": round(frames_total / elapsed, 1) if elapsed else 0,
            "bytes_per_second": round(bytes_total / elapsed, 1) if elapsed else 0,
            "min_per_console": min(per_console) if per_console else 0,
            "max_per_console": max(per_console) if per_console else 0,
            "median_per_console": int(statistics.median(per_console)) if per_console else 0,
        },
        "resources": {
            "rss_before_bytes": rss_before,
            "rss_after_bytes": rss_after,
            "rss_delta_bytes": rss_after - rss_before,
            "rss_available": rss_after > 0,
            "cpu_seconds": round((cpu_after - cpu_before) / 1_000_000_000, 3),
            "cpu_nanoseconds": cpu_after - cpu_before,
            "cpu_counter_advanced": (cpu_after - cpu_before) > 0,
            "elapsed_seconds": round(elapsed, 3),
        },
        "revoke": {
            "sessions": len(runtimes),
            "all_consoles_closed": all(not rt.ws for rt in runtimes),
            "seconds": round(revoke_seconds, 3),
        },
        "shape_only": True,
    }
    report["assertions"] = {
        "no_connection_loss": report["connections"]["no_loss"],
        "every_console_delivered": report["connections"]["delivered"] == sessions,
        "revoke_closed_all": report["revoke"]["all_consoles_closed"],
        "cpu_measured": cpu_after >= cpu_before and elapsed > 0,
        "rss_measured": rss_before > 0 and rss_after > 0,
    }
    return report


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--sessions", type=int, default=40)
    p.add_argument("--seconds", type=int, default=2)
    p.add_argument("--out", help="also write the JSON report to this path")
    args = p.parse_args(argv)
    if args.sessions < 1 or args.seconds < 1:
        p.error("--sessions and --seconds must be >= 1")

    import tempfile
    with tempfile.TemporaryDirectory(prefix="kvm-bench-") as tmp:
        report = asyncio.run(run_probe(sessions=args.sessions, seconds=args.seconds,
                                       tmp_path=Path(tmp)))
    text = json.dumps(report, ensure_ascii=False, indent=1)
    print(text)
    if args.out:
        Path(args.out).write_text(text + "\n", encoding="utf-8")
    return 0 if all(report["assertions"].values()) else 1


if __name__ == "__main__":
    raise SystemExit(main())
