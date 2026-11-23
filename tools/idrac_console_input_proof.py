"""Driver for the production three-entry browser input proof."""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from tools.browser_e2e import _find_chromium, _find_playwright  # noqa: E402

ENTRY_NAMES = ("physical", "softkey", "paste")
SENSITIVE = ("KVM_PASSWORD", "KVM_TENANT", "KVM_USER", "KVM_TOKEN")


def redact(text: str) -> str:
    out = (text or "")[-1200:]
    for name in SENSITIVE:
        value = os.environ.get(name)
        if value:
            out = out.replace(value, "[redacted]")
    out = re.sub(r"([?&](?:ticket|token|csrf|challenge|password|pwd|secret|t)=)[^&\s\"'<>]+",
                 r"\1[redacted]", out, flags=re.I)
    out = re.sub(r"https?://[^\s\"'<>]+",
                 lambda m: (m.group(0).split("?")[0]), out)
    return out


def judge(payload: dict) -> tuple[bool, dict]:
    settled = payload.get("canvas_size_stable") is True
    steps = payload.get("steps") or []
    protocol = payload.get("input_protocol")
    expected = payload.get("protocol_expected") or "standard8"
    lifecycle = payload.get("state_after_input") == "normal" and "close_requested" in steps

    checks = {
        "framebuffer_settled": settled,
        "protocol_ok": protocol == expected,
        "meta_asset_id_match": payload.get("meta_asset_id_match") is True,
        "session_lifecycle": lifecycle,
    }
    guards = payload.get("guard_checks")
    if isinstance(guards, dict) and guards:
        checks["safety_red_lines"] = all(bool(v) for v in guards.values())
    if "no_enter_sent" in payload:
        checks["no_enter_sent"] = payload["no_enter_sent"] is True

    entries = {}
    for name in ENTRY_NAMES:
        raw = (payload.get("entries") or {}).get(name) or {}
        verdict = raw.get("verdict") or {}
        entry = {
            "control_valid": bool(verdict.get("control_valid")),
            "visible": bool(verdict.get("visible")),
            "echo_removed": bool(verdict.get("reversible")),
            "restored_clean": bool(verdict.get("clean_ok")),
            "key_budget_ok": bool(verdict.get("budget_ok")),
            "keys_sent": raw.get("keys"),
            "threshold": verdict.get("threshold"),
            "idle_pixels": (raw.get("idle") or {}).get("pixels"),
            "typed_pixels": (raw.get("typed") or {}).get("pixels"),
            "restored_pixels": (raw.get("restored") or {}).get("pixels"),
            "clean_pixels": (raw.get("clean") or {}).get("pixels"),
        }
        entries[name] = entry
        checks[name + "_visible"] = entry["visible"]
        checks[name + "_echo_removed"] = entry["echo_removed"]
        checks[name + "_restored_clean"] = entry["restored_clean"]
        checks[name + "_key_budget_ok"] = entry["key_budget_ok"]

    ok = (all(checks.values()) and not payload.get("errors"))
    return ok, {"checks": checks, "entries": entries}


def build_evidence(payload: dict | None, returncode: int, stderr: str, args, verdict: dict) -> dict:
    evidence = {
        "mode": "stub" if args.stub else "production",
        "asset": args.asset,
        "expected_protocol": args.expect_protocol,
        "browser_exit": returncode,
        "input_protocol": (payload or {}).get("input_protocol"),
        "canvas_size": (payload or {}).get("canvas_size"),
        "canvas_size_stable": (payload or {}).get("canvas_size_stable"),
        "steps": (payload or {}).get("steps") or [],
        "errors": (payload or {}).get("errors") or [],
        "console_errors": (payload or {}).get("console_errors") or [],
        "keys_total": (payload or {}).get("keys_total"),
        "state_after_input": (payload or {}).get("state_after_input"),
        "guard_checks": (payload or {}).get("guard_checks"),
        "no_enter_sent": (payload or {}).get("no_enter_sent"),
        "verdict_checks": verdict.get("checks") or {},
        "entries": verdict.get("entries") or {},
    }
    if not payload:
        evidence["errors"].append("browser_produced_no_result")
    if stderr.strip():
        evidence["browser_stderr_tail"] = redact(stderr)
    return evidence


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--stub", action="store_true",
                        help="local smoke test: route stubs + real console HTML, no BMC / production")
    parser.add_argument("--asset", default=os.environ.get("KVM_ASSET",
                        "96df7f56-9cb0-4532-9d51-fa22045fad6f"))
    parser.add_argument("--base", default=os.environ.get("KVM_BASE"))
    parser.add_argument("--expect-protocol", default=os.environ.get("KVM_EXPECT_PROTOCOL", "standard8"))
    parser.add_argument("--out", help="write evidence JSON here (never contains secrets)")
    parser.add_argument("--shots", help="optional local screenshot directory")
    parser.add_argument("--playwright", default=os.environ.get("KVM_PLAYWRIGHT"))
    parser.add_argument("--chromium", default=os.environ.get("KVM_CHROMIUM"))
    parser.add_argument("--node", default="node")
    args = parser.parse_args()

    module = args.playwright or _find_playwright()
    chromium = args.chromium or _find_chromium()
    if not module or not chromium:
        parser.error("playwright-core and a Chromium build are required (see tools/browser_e2e.py)")

    script = ROOT / "tools" / "idrac_console_input_proof.cjs"
    env = dict(os.environ)
    env["KVM_PLAYWRIGHT"] = module
    env["KVM_CHROMIUM"] = chromium
    env["KVM_ASSET"] = args.asset
    env["KVM_EXPECT_PROTOCOL"] = args.expect_protocol
    env["KVM_STUB"] = "1" if args.stub else "0"
    if args.base:
        env["KVM_BASE"] = args.base
    if args.shots:
        env["KVM_SHOTS"] = args.shots
    if not args.stub:
        for name in ("KVM_USER", "KVM_PASSWORD"):
            if not env.get(name):
                parser.error(name + " must be set outside stub mode")

    try:
        completed = subprocess.run([args.node, str(script)], cwd=str(ROOT), env=env,
                                   capture_output=True, text=True, timeout=300)
    except (OSError, subprocess.TimeoutExpired) as exc:
        evidence = build_evidence(None, -1, str(exc), args, {})
        evidence["verdict"] = "fail"
        _write(evidence, args.out)
        print(json.dumps({"verdict": "fail", "error": redact(str(exc))}, ensure_ascii=False))
        return 1

    payload = None
    for line in completed.stdout.splitlines():
        if line.startswith("RESULT "):
            try:
                payload = json.loads(line[len("RESULT "):])
            except json.JSONDecodeError:
                payload = None
    ok, verdict = judge(payload or {})
    evidence = build_evidence(payload, completed.returncode, completed.stderr, args, verdict)
    evidence["verdict"] = "pass" if ok else "fail"
    _write(evidence, args.out)
    print(json.dumps({
        "verdict": evidence["verdict"],
        "checks": evidence["verdict_checks"],
        "entries": evidence["entries"],
        "errors": evidence["errors"],
    }, indent=2, ensure_ascii=False))
    return 0 if ok else 1


def _write(evidence: dict, out: str | None) -> None:
    if not out:
        return
    path = Path(out)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(evidence, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


if __name__ == "__main__":
    raise SystemExit(main())
