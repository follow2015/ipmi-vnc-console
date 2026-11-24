#!/usr/bin/env python3
"""Bounded ATEN Java/TCP video probe; no Java, input or power commands."""
from __future__ import annotations

import argparse
import asyncio
import getpass
import json
import os
from pathlib import Path
import struct
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from kvmhub.aten_java_upstream import AtenJavaUpstream
from kvmhub.common import Problem, bmc_allowed_networks_from_env


async def probe(host: str, pin: str, username: str, password: str, *, frames=3) -> dict:
    report = {"host": host, "adapter": "aten-java-rfb-tcp", "input_sent": False,
              "power_commands_sent": False, "frames": [], "success": False}
    upstream = AtenJavaUpstream(host, pin, networks=bmc_allowed_networks_from_env())
    try:
        async with asyncio.timeout(45):
            await upstream.login(username, password)
            raw = upstream.server_init_raw
            width, height = struct.unpack_from(">HH", raw)
            report["server_init"] = {"width": width, "height": height, "bpp": raw[4]}
            budget = 0
            for _ in range(frames):
                await upstream.send_raw(struct.pack(">BBHHHH", 3, 0, 0, 0, width, height))
                for _ in range(64):
                    kind = (await upstream._read(1))[0]
                    if kind == 0:
                        header = await upstream._read(3)
                        rects = struct.unpack_from(">H", header, 1)[0]
                        if not 1 <= rects <= 64:
                            raise ValueError("rect_count_invalid")
                        for _ in range(rects):
                            header = await upstream._read(20)
                            x, y, w, h, enc, mode, length = struct.unpack(">HHHHiii", header)
                            budget += length
                            if not 0 <= length <= 4 * 1024 * 1024 or budget > 16 * 1024 * 1024:
                                raise ValueError("video_budget_exceeded")
                            await upstream._read(length)
                            report["frames"].append({"x": x, "y": y, "width": w, "height": h,
                                                      "encoding": enc, "mode": mode, "bytes": length,
                                                      "no_signal": length == 0})
                        break
                    if kind == 57:
                        await upstream._read(264)
                    elif kind == 22:
                        await upstream._read(1)
                    elif kind == 55:
                        await upstream._read(3)
                    elif kind == 4:
                        cursor = await upstream._read(20)
                        _, _, w, h, valid = struct.unpack(">IIIII", cursor)
                        if w > 128 or h > 128 or valid not in (0, 1):
                            raise ValueError("cursor_invalid")
                        if valid:
                            await upstream._read(4 + w * h * 2)
                    elif kind not in (2, 26, 53, 54):
                        raise ValueError("server_message_unsupported")
                else:
                    raise ValueError("message_budget_exceeded")
            report["success"] = len(report["frames"]) >= frames
    except (Problem, OSError, ValueError, TimeoutError, asyncio.IncompleteReadError) as exc:
        report["error"] = exc.code if isinstance(exc, Problem) else type(exc).__name__
    finally:
        report["cleanup_confirmed"] = await upstream.close()
        report["cleanup_outcome"] = upstream.cleanup_outcome
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", required=True)
    parser.add_argument("--cert-sha256", required=True)
    parser.add_argument("--frames", type=int, choices=range(1, 6), default=3)
    args = parser.parse_args()
    username = os.environ.get("BMC_USER")
    if not username:
        parser.error("BMC_USER is required")
    password = os.environ.get("BMC_PASSWORD") or getpass.getpass("BMC password: ")
    try:
        report = asyncio.run(probe(args.host, args.cert_sha256, username, password, frames=args.frames))
    except Problem as exc:
        print(json.dumps({"error": exc.code}))
        return 2
    print(json.dumps(report, ensure_ascii=False))
    return 0 if report["success"] and report["cleanup_confirmed"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
