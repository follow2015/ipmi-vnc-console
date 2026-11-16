#!/usr/bin/env python3
"""Experiment D: is the host's CapsLock state stable across cold starts?"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _ssl_ctx():
    import ssl
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


async def _reset(host: str, fingerprint: str, kind: str) -> dict:
    import aiohttp

    auth = {"Authorization": "Basic " + __import__("base64").b64encode(
        f"{os.environ['BMC_USER']}:{os.environ['BMC_PASSWORD']}".encode()).decode()}
    async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=_ssl_ctx())) as session:
        async with session.post(f"https://{host}/redfish/v1/Systems/1/Actions/ComputerSystem.Reset",
                                json={"ResetType": kind}, headers=auth,
                                allow_redirects=False) as response:
            body = await response.read()
            return {"status": response.status, "bytes": len(body)}


def text_landed(readback: dict | None) -> bool:
    block = readback or {}
    groups = block.get("visible_groups")
    return isinstance(groups, int) and groups >= 1


def stability(known: list[str]) -> bool:
    return len(known) >= 2 and len(set(known)) == 1


def geometry(case: dict | None) -> dict:
    import sys as _sys
    _sys.path.insert(0, str(ROOT))
    from tools.passthrough_check import _glyph_height, _tallest_cell

    out: dict = {}
    for name in ("lower", "upper"):
        cell = _tallest_cell((case or {}).get(name))
        out[name] = None if cell is None else {
            "top": cell.get("top"), "bottom": cell.get("bottom"),
            "height": _glyph_height(cell), "ink": cell.get("ink")}
    return out


def probe(directory: Path, host: str, fingerprint: str, versions: str,
          screenshot: Path | None = None) -> dict:
    env = dict(os.environ)
    command = [sys.executable, str(ROOT / "tools/passthrough_check.py"),
               "--host", host, "--cert-sha256", fingerprint,
               "--protocol-versions", versions, "--probe-echo", "--probe-case",
               "--directory", str(directory), "--out", str(directory / "probe.json")]
    if screenshot is not None:
        command += ["--screenshot", str(screenshot)]
    completed = subprocess.run(command, cwd=ROOT, env=env, capture_output=True,
                               text=True, timeout=240)
    payload = {}
    try:
        payload = json.loads((directory / "probe.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        pass
    return {"returncode": completed.returncode,
            "state": payload.get("state_after_input"),
            "non_black": (payload.get("canvas_after_input") or {}).get("non_black"),
            "canvas": payload.get("canvas_after_input") or {},
            "probe": payload.get("probe_readback") or {},
            "geometry": geometry(payload.get("probe_case")),
            "stderr_tail": completed.stderr[-200:] if completed.stderr else None}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--host", required=True)
    parser.add_argument("--cert-sha256", required=True)
    parser.add_argument("--protocol-versions", default="")
    parser.add_argument("--directory", default=".local-capslock")
    parser.add_argument("--rounds", type=int, default=5)
    parser.add_argument("--boot-timeout", type=float, default=300.0)
    parser.add_argument("--settle", type=float, default=85.0,
                        help="time to wait before the first probe after a reset")
    parser.add_argument("--retry-wait", type=float, default=10.0,
                        help="pause between probes while the host is still booting")
    parser.add_argument("--shot-dir", default=None,
                        help="keep one PNG per round here for human audit; never committed")
    parser.add_argument("--out")
    args = parser.parse_args()
    if not os.environ.get("BMC_USER") or not os.environ.get("BMC_PASSWORD"):
        parser.error("BMC_USER and BMC_PASSWORD must be set")
    if args.rounds < 1 or args.rounds > 10:
        parser.error("--rounds is between 1 and 10; this reboots a real machine")

    fingerprint = args.cert_sha256.replace(":", "").lower()
    base = ROOT / args.directory
    if base.exists():
        parser.error(f"{base} already exists; choose a fresh --directory")
    if args.shot_dir:
        Path(args.shot_dir).mkdir(parents=True, exist_ok=True)

    rounds: list[dict] = []
    for index in range(1, args.rounds + 1):
        reset = asyncio.run(_reset(args.host, fingerprint, "GracefulRestart"))
        started = time.time()
        time.sleep(args.settle)
        attempt = None
        attempts: list[dict] = []
        while time.time() - started < args.boot_timeout:
            probe_dir = base / f"round-{index}-{int(time.time())}"
            shot = (Path(args.shot_dir) / f"round-{index}.png") if args.shot_dir else None
            attempt = probe(probe_dir, args.host, fingerprint, args.protocol_versions, shot)
            attempts.append({"at_seconds": round(time.time() - started, 1),
                             "verdict": (attempt["probe"] or {}).get("verdict"),
                             "non_black": attempt["non_black"],
                             "canvas": [attempt["canvas"].get("width"),
                                        attempt["canvas"].get("height")],
                             "directory": probe_dir.name})
            if attempt["state"] == "normal" and text_landed(attempt["probe"]):
                break
            time.sleep(args.retry_wait)
        caps = (attempt or {}).get("probe", {}).get("caps_lock", "unknown")
        rounds.append({"round": index, "reset": reset,
                       "boot_seconds": round(time.time() - started, 1),
                       "caps_lock": caps,
                       "case_method": (attempt or {}).get("probe", {}).get("case_method"),
                       "state": (attempt or {}).get("state"),
                       "non_black": (attempt or {}).get("non_black"),
                       "readback": (attempt or {}).get("probe"),
                       "geometry": (attempt or {}).get("geometry"),
                       "attempts": attempts})
        print(json.dumps({k: rounds[-1][k] for k in
                          ("round", "boot_seconds", "caps_lock", "case_method",
                           "state", "non_black")}, ensure_ascii=False), flush=True)

    known = [r["caps_lock"] for r in rounds if r["caps_lock"] in ("on", "off")]
    evidence = {
        "experiment": "D",
        "question": "Is CapsLock on after every cold start, or does it vary?",
        "host_alias": "192.0.2.11",
        "rounds_requested": args.rounds,
        "criterion": ("a round counts as reached only when the sentinel's own diff produced "
                      "at least one measured glyph group; brightness and 'the frame changed' "
                      "are both rejected (a boot splash is bright, a boot log scrolls)"),
        "rounds": rounds,
        "measured": len(known),
        "values": sorted(set(known)),
        "stable": stability(known),
        "stability_needs_measurements": 2,
        "grub_stage": "not measurable: no character is echoed at the GRUB menu",
        "not_measured": ("CapsLock state at the GRUB menu, and whether the firmware's "
                         "own state (before any OS) matches the OS one"),
    }
    if args.out:
        out = Path(args.out)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(evidence, indent=2, ensure_ascii=False) + "\n",
                       encoding="utf-8")
    print(json.dumps({k: evidence[k] for k in ("measured", "values", "stable")},
                     ensure_ascii=False))
    return 0 if known else 1


if __name__ == "__main__":
    raise SystemExit(main())
