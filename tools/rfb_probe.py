#!/usr/bin/env python3
"""Bounded real-BMC console probe for the protocol-gateway transport."""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from kvmhub.common import Problem
from kvmhub.rfb_upstream import RfbUpstream, UpstreamConfig

SHIFT_L = 0xFFE1
SAFETY = {
    "power_operations": 0,
    "configuration_changes": 0,
    "keyboard_characters_typed": 0,
    "keyboard_modifier_only": True,
    "rect_payloads_recorded": False,
    "ticket_value_recorded": False,
    "credential_values_recorded": False,
}


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--host", default=os.environ.get("KVM_BMC_HOST", ""))
    p.add_argument("--port", type=int, default=443)
    p.add_argument("--cert-sha256", help="pinned certificate SHA-256 (required for TLS)")
    p.add_argument("--entry-path", default="/cgi/url_redirect.cgi?url_name=man_ikvm_html5_bootstrap")
    p.add_argument("--frames", type=int, default=3, help="framebuffer updates to observe")
    p.add_argument("--timeout", type=float, default=8.0)
    p.add_argument("--no-input", action="store_true", help="skip the pointer and Shift events")
    p.add_argument("--out", help="write the redacted report to this path")
    return p


async def run(args, report: dict) -> int:
    cfg = UpstreamConfig(host=args.host, port=args.port, scheme="https",
                         cert_sha256=args.cert_sha256, bootstrap_path=args.entry_path,
                         handshake_timeout=args.timeout, request_timeout=args.timeout)
    upstream = RfbUpstream(cfg)
    report["tls_pinning"] = "sha256 fingerprint pinned on every connection"
    started = time.monotonic()
    try:
        await upstream.login(os.environ["BMC_USER"], os.environ["BMC_PASSWORD"])
        report["web_login"] = "ok"
        ticket = await upstream.read_ticket()
        report["bootstrap_ticket"] = {"present": True, "length": len(ticket)}
        ticket = None
        await upstream.open()
        init = upstream.server_init
        report["handshake"] = {
            "protocol_version": "055.008",
            "security_type": 16,
            "server_init": None if init is None else {
                "width": init.width, "height": init.height,
                "bits_per_pixel": init.bits_per_pixel, "depth": init.depth,
                "true_color": init.true_color, "name_length": init.name_length},
            "insyde_extension": upstream.init_event,
        }
        observed = await upstream.wait_frames(args.frames, timeout=args.timeout)
        report["framebuffer_updates_observed"] = observed
        if not args.no_input:
            await upstream.send_pointer(init.width // 2, init.height // 2, 0)
            await upstream.send_pointer(init.width // 2 + 1, init.height // 2, 0)
            await upstream.send_key(SHIFT_L, True)
            await upstream.send_key(SHIFT_L, False)
            await upstream.wait_frames(1, timeout=args.timeout)
            report["input"] = {"pointer_events": 2, "key_events": 2,
                               "keys": ["Shift_L down/up"], "characters_typed": 0}
        report["stats"] = upstream.stats.as_dict()
        report["elapsed_seconds"] = round(time.monotonic() - started, 3)
        exit_code = 0
    except Problem as exc:
        report["error"] = exc.code
        exit_code = 2
    except (KeyError, ValueError, OSError) as exc:
        report["error"] = type(exc).__name__
        exit_code = 2
    finally:
        try:
            report["cleanup"] = await upstream.close()
        except Exception:
            report["cleanup"] = "failed"
        report["safety"] = SAFETY
    if exit_code == 0 and report.get("cleanup") in ("failed", None):
        exit_code = 3
    return exit_code


def main(argv=None) -> int:
    args = parser().parse_args(argv)
    if not args.host:
        parser().error("--host or KVM_BMC_HOST is required")
    if not args.cert_sha256:
        parser().error("--cert-sha256 is required; plaintext probing is not supported")
    if not os.environ.get("BMC_USER") or not os.environ.get("BMC_PASSWORD"):
        parser().error("BMC_USER and BMC_PASSWORD must be set in the environment")
    if not 1 <= args.frames <= 20:
        parser().error("--frames must be in 1..20")
    report = {"probe": "rfb-gateway", "host": args.host, "port": args.port,
              "recorded_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
              "scope": "one console session: handshake, frame metadata, pointer/modifier input, logout"}
    code = asyncio.run(run(args, report))
    payload = json.dumps(report, ensure_ascii=False, indent=2)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as handle:
            handle.write(payload + "\n")
    print(payload)
    return code


if __name__ == "__main__":
    sys.exit(main())
