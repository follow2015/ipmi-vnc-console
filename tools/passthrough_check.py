"""Bounded end-to-end check of the passthrough console against one real BMC."""
from __future__ import annotations

import argparse
import base64
import json
import multiprocessing
import os
import re
import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from kvmhub.run import manager_process, worker_process  # noqa: E402
from kvmhub.store import Store  # noqa: E402
from tools.bootstrap import generate  # noqa: E402
from tools.browser_e2e import _find_chromium, _find_playwright  # noqa: E402

STARTUP_TIMEOUT = 60.0
SETTLE_SECONDS = 5.0

SECRET_PLACEHOLDER = "@secret"
_STEP_FIELDS = {"label", "text", "keys", "enter", "wait", "delay", "hold", "shot", "shot_before",
                "expect_change", "reload"}

CLIENT_MODIFIERS = ("Shift", "Control", "Alt", "Meta")


def parse_type_script(raw: str) -> list[dict]:
    if not raw or not raw.strip():
        return []
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError(f"script is not valid JSON: {exc}") from exc
    if not isinstance(payload, list):
        raise ValueError("script must be a JSON list of steps")
    steps: list[dict] = []
    for index, item in enumerate(payload):
        if not isinstance(item, dict):
            raise ValueError(f"step {index} must be an object")
        unknown = sorted(set(item) - _STEP_FIELDS)
        if unknown:
            raise ValueError(f"step {index} has unknown fields {unknown}")
        label = str(item.get("label") or "").strip()
        if not label:
            raise ValueError(f"step {index} needs a label")
        text = item.get("text")
        keys = item.get("keys")
        reload = item.get("reload", False)
        if not isinstance(reload, bool):
            raise ValueError(f"step {index}: reload must be true or false")
        if reload:
            if text is not None or keys is not None:
                raise ValueError(f"step {index}: a reload step cannot type text or keys")
        else:
            if text is not None and keys is not None:
                raise ValueError(f"step {index} takes one of text or keys, not both")
            if text is None and keys is None:
                raise ValueError(f"step {index} needs text or keys")
        hold = int(item.get("hold", 0))
        if hold < 0:
            raise ValueError(f"step {index}: hold must be zero or a positive number of ms")
        steps.append({"label": label, "text": str(text or ""), "keys": str(keys or ""),
                      "reload": reload,
                      "enter": False if reload else bool(item.get("enter", keys is None)),
                      "wait": int(item.get("wait", 1200)),
                      "delay": int(item.get("delay", 55)),
                      "hold": hold,
                      "shot": str(item.get("shot") or ""),
                      "shot_before": str(item.get("shot_before") or ""),
                      "expect_change": bool(item.get("expect_change", False))})
    return steps


def script_env(steps: list[dict]) -> dict:
    return {"KVM_SCRIPT": json.dumps(steps),
            "KVM_MODIFIERS": json.dumps(list(CLIENT_MODIFIERS))}


def describe_steps(steps: list[dict]) -> list[dict]:
    described = []
    for step in steps:
        if step.get("reload"):
            described.append({"label": step["label"], "reload": True})
        elif step.get("keys"):
            described.append({"label": step["label"], "keys": step["keys"]})
        elif step["text"] == SECRET_PLACEHOLDER:
            described.append({"label": step["label"], "secret": True})
        else:
            described.append({"label": step["label"], "chars": len(step["text"])})
    return described


PROBE_TEXT = "AbC1"
PROBE_LABEL = "probe_echo"
PROBE_CASE_LABEL = "probe_case"
PROBE_CLEAR_LABEL = "probe_clear"
_PROBE_MIN_LENGTH, _PROBE_MAX_LENGTH = 2, 16
_PROBE_CHARS = re.compile(r"[A-Za-z0-9]+")


def probe_steps(text: str = PROBE_TEXT) -> list[dict]:
    marker = str(text)
    if not _PROBE_MIN_LENGTH <= len(marker) <= _PROBE_MAX_LENGTH:
        raise ValueError(
            f"probe marker length must be {_PROBE_MIN_LENGTH}..{_PROBE_MAX_LENGTH}")
    if not _PROBE_CHARS.fullmatch(marker):
        raise ValueError("probe marker must be ascii alphanumeric")
    if not any(char.isupper() for char in marker):
        raise ValueError("probe marker needs an uppercase letter to prove Shift travels")
    if not any(char.islower() for char in marker):
        raise ValueError("probe marker needs a lowercase letter to prove the base key travels")
    return [
        {"label": PROBE_LABEL, "text": marker, "keys": None, "enter": False,
         "wait": 2500, "delay": 90, "hold": 0, "shot": "probe-echo",
         "shot_before": "probe-before"},
        {"label": PROBE_CLEAR_LABEL, "text": None, "keys": "Control+U", "enter": False,
         "wait": 800, "delay": 55, "hold": 0, "shot": "", "shot_before": ""},
    ]


def probe_case_steps() -> list[dict]:
    return [
        {"label": PROBE_CASE_LABEL, "text": "a", "keys": None, "enter": False,
         "wait": 900, "delay": 90, "hold": 0, "shot": "probe-case", "shot_before": ""},
        {"label": PROBE_CLEAR_LABEL, "text": None, "keys": "Control+U", "enter": False,
         "wait": 800, "delay": 55, "hold": 0, "shot": "", "shot_before": ""},
    ]


def apply_probe_case(steps: list[dict], enabled: bool) -> list[dict]:
    if not enabled:
        return steps
    if any(step.get("label") == PROBE_CASE_LABEL for step in steps):
        return steps
    return probe_case_steps() + steps


def apply_probe(steps: list[dict], enabled: bool) -> list[dict]:
    if not enabled:
        return steps
    if any(step.get("label") == PROBE_LABEL for step in steps):
        return steps
    return probe_steps() + steps


def probe_verdict(probe: dict | None) -> str:
    return probe_report(probe, None)["verdict"]


def probe_report(probe: dict | None, case: dict | None) -> dict:
    if not probe:
        return {"verdict": "not_run", "expected_chars": None, "visible_groups": None,
                "accuracy": None, "case_sensitive": None, "notes": []}
    echo = probe.get("echo") if isinstance(probe, dict) else None
    expected = probe.get("expected_chars")
    groups = (echo or {}).get("groups")
    notes: list[str] = []
    case_sensitive = None
    if isinstance(case, dict):
        lower = (case.get("lower") or {}).get("signature")
        upper = (case.get("upper") or {}).get("signature")
        if isinstance(lower, int) and isinstance(upper, int):
            case_sensitive = lower != upper
            if not case_sensitive:
                notes.append("case_not_distinguished")
    if not isinstance(expected, int) or not isinstance(groups, int):
        verdict = "echoed" if probe.get("changed") else "silent"
        return {"verdict": verdict, "expected_chars": expected, "visible_groups": None,
                "accuracy": None, "case_sensitive": case_sensitive, "notes": notes}
    accuracy = round(groups / expected, 3) if expected > 0 else None
    if groups <= 0:
        verdict = "silent"
    elif groups >= expected:
        verdict = "echoed"
    else:
        verdict = "partial"
        notes.append("fewer_glyphs_than_sent")
    return {"verdict": verdict, "expected_chars": expected, "visible_groups": groups,
            "accuracy": accuracy, "case_sensitive": case_sensitive, "notes": notes}


LIVENESS_MIN_SAMPLES = 3


def _fingerprint(block) -> int | None:
    if not isinstance(block, dict):
        return None
    value = block.get("fingerprint")
    return value if isinstance(value, int) else None


def liveness_series(payload: dict, exclude: tuple[str, ...] = (PROBE_LABEL, PROBE_CASE_LABEL,
                                                              PROBE_CLEAR_LABEL)) -> list[int]:
    payload = payload or {}
    series: list[int] = []
    first = _fingerprint(payload.get("canvas_initial"))
    if first is not None:
        series.append(first)
    for sample in payload.get("step_samples") or []:
        if not isinstance(sample, dict) or sample.get("label") in exclude:
            continue
        value = _fingerprint(sample.get("canvas"))
        if value is not None:
            series.append(value)
    last = _fingerprint(payload.get("canvas_after_input"))
    if last is not None:
        series.append(last)
    return series


def liveness_verdict(samples: list[int] | None) -> str:
    series = list(samples or [])
    if len(series) < LIVENESS_MIN_SAMPLES:
        return "unknown"
    return "moving" if len(set(series)) > 1 else "stalled"


def not_changed_steps(samples: list[dict], steps: list[dict]) -> list[str]:
    expected = {step["label"] for step in (steps or []) if step.get("expect_change")}
    if not expected:
        return []
    violations = []
    for sample in samples or []:
        if sample.get("label") not in expected:
            continue
        before = sample.get("fingerprint_before")
        after = _fingerprint(sample.get("canvas"))
        if before is None or after is None:
            continue
        if before == after:
            violations.append(sample["label"])
    return violations


def wait_port(port: int, timeout: float = STARTUP_TIMEOUT) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        with socket.socket() as sock:
            sock.settimeout(0.5)
            if sock.connect_ex(("127.0.0.1", port)) == 0:
                return True
        time.sleep(0.2)
    return False


def prepare(directory: Path, host: str, fingerprint: str, username: str, password: str,
            protocol_versions: tuple[str, ...] = ()):
    root = generate(directory)
    key = base64.b64decode((root / "encryption.key").read_text().strip())
    target = f"https://{host}"
    store = Store(root / "manager.sqlite3", key, passthrough_targets=(target,))
    try:
        store.seed_passthrough(target=target, fingerprint=fingerprint, username=username,
                               password=password, approver="tools/passthrough_check.py",
                               protocol_versions=protocol_versions)
    finally:
        store.close()
    manager_path = root / "manager.json"
    manager_cfg = json.loads(manager_path.read_text())
    manager_cfg["passthrough_targets"] = [target]
    manager_path.write_text(json.dumps(manager_cfg, indent=2) + "\n")
    return root, key, target


def session_state(root: Path, key: bytes, target: str):
    store = Store(root / "manager.sqlite3", key, passthrough_targets=(target,))
    try:
        row = store.db.execute(
            "SELECT status,cleanup,reason,consumed FROM session ORDER BY created DESC LIMIT 1").fetchone()
        actions = [r[0] for r in store.db.execute("SELECT action FROM audit ORDER BY id")]
        return (dict(row) if row else None), actions
    finally:
        store.close()


def run_browser(node: str, module: str, chromium: str, base: str, token: str, asset: str,
                screenshot: str | None = None, steps: list[dict] | None = None,
                shot_dir: str | None = None):
    env = dict(os.environ, KVM_PLAYWRIGHT=module, KVM_CHROMIUM=chromium,
               KVM_BASE=base, KVM_TOKEN=token, KVM_ASSET=asset)
    env.update(script_env(steps or []))
    if screenshot:
        env["KVM_SCREENSHOT"] = screenshot
    if shot_dir:
        env["KVM_SHOT_DIR"] = shot_dir
    completed = subprocess.run([node, "tools/passthrough_browser.cjs"], cwd=ROOT, env=env,
                               capture_output=True, text=True, timeout=180)
    payload = None
    for line in completed.stdout.splitlines():
        if line.startswith("RESULT "):
            payload = json.loads(line[len("RESULT "):])
    return payload, completed.returncode, completed.stderr[-800:]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--host", required=True)
    parser.add_argument("--cert-sha256", required=True)
    parser.add_argument("--directory", default=".local-passthrough")
    parser.add_argument("--asset", default="real-1")
    parser.add_argument("--protocol-versions", default="",
                        help="comma-separated RFB greetings approved for this device, "
                             "e.g. 'RFB 055.008,RFB 003.008'")
    parser.add_argument("--out")
    parser.add_argument("--screenshot", help="local PNG path; never committed")
    parser.add_argument("--shot-dir", help="directory for per-step PNGs; never committed")
    parser.add_argument("--script-json", default="",
                        help="JSON list of keystroke steps typed into the console; "
                             "text '@secret' expands from the KVM_SECRET environment")
    parser.add_argument("--probe-echo", action="store_true",
                        help="type a mixed-case marker and erase it before the script, "
                             "so a missing Shift shows up as a read-back mismatch")
    parser.add_argument("--probe-case", action="store_true",
                        help="also compare a lowercase and an uppercase probe glyph; "
                             "equal glyphs mean the host never saw the case we sent")
    parser.add_argument("--keep", action="store_true", help="keep the fixture directory")
    parser.add_argument("--playwright", default=os.environ.get("KVM_PLAYWRIGHT"))
    parser.add_argument("--chromium", default=os.environ.get("KVM_CHROMIUM"))
    parser.add_argument("--node", default="node")
    args = parser.parse_args()

    username, password = os.environ.get("BMC_USER"), os.environ.get("BMC_PASSWORD")
    if not username or not password:
        parser.error("BMC_USER and BMC_PASSWORD must be set")
    fingerprint = args.cert_sha256.replace(":", "").lower()
    if len(fingerprint) != 64 or any(c not in "0123456789abcdef" for c in fingerprint):
        parser.error("--cert-sha256 must be 64 hex characters")
    versions = tuple(v.strip() for v in args.protocol_versions.split(",") if v.strip())
    try:
        steps = parse_type_script(args.script_json)
    except ValueError as exc:
        parser.error(str(exc))
    steps = apply_probe(steps, args.probe_echo)
    steps = apply_probe_case(steps, args.probe_case)
    if any(step["text"] == SECRET_PLACEHOLDER for step in steps) and not os.environ.get("KVM_SECRET"):
        parser.error("a step uses '@secret' but KVM_SECRET is not set")
    if args.shot_dir:
        Path(args.shot_dir).mkdir(parents=True, exist_ok=True)
    module = args.playwright or _find_playwright()
    chromium = args.chromium or _find_chromium()
    if not module or not chromium:
        parser.error("playwright-core and a Chromium build are required (see tools/browser_e2e.py)")

    from kvmhub.common import UI_PORT, UI_ORIGIN, WORKER_PORT

    directory = ROOT / args.directory
    if directory.exists():
        parser.error(f"{directory} already exists; choose a fresh --directory")
    root, key, target = prepare(directory, args.host, fingerprint, username, password, versions)
    token = (root / "login-token").read_text().strip()

    ctx = multiprocessing.get_context("spawn")
    processes = [ctx.Process(target=manager_process, args=(str(root / "manager.json"),), name="manager"),
                 ctx.Process(target=worker_process, args=(str(root / "worker.json"),), name="worker")]
    evidence = {"target_host": args.host, "asset": args.asset,
                "adapter": "supermicro-x10-passthrough",
                "approved_protocol_versions": list(versions) if versions else ["RFB 055.008"],
                "probe_echo": bool(args.probe_echo), "probe_case": bool(args.probe_case),
                "steps": [], "errors": []}
    exit_code = 1
    try:
        for process in processes:
            process.start()
        ready = wait_port(UI_PORT) and wait_port(WORKER_PORT)
        evidence["services_ready"] = ready
        if not ready:
            evidence["errors"].append("services_not_ready")
            return 1
        payload, returncode, stderr = run_browser(args.node, module, chromium, UI_ORIGIN, token,
                                                  args.asset, args.screenshot, steps, args.shot_dir)
        evidence["browser_exit"] = returncode
        if stderr:
            evidence["browser_stderr_tail"] = stderr
        if payload is None:
            evidence["errors"].append("browser_produced_no_result")
            return 1
        evidence.update(payload)
        if steps:
            evidence["typed_steps"] = describe_steps(steps)
        report = probe_report(payload.get("probe"), payload.get("probe_case"))
        evidence["probe_result"] = report["verdict"]
        evidence["probe_readback"] = report
        series = liveness_series(payload)
        evidence["liveness_samples"] = series
        evidence["liveness"] = liveness_verdict(series)

        time.sleep(SETTLE_SECONDS)
        state, actions = session_state(root, key, target)
        evidence["session"] = state
        evidence["audit_actions"] = actions[-12:]
        samples = payload.get("step_samples") or []
        steps_ok = all(sample.get("state") == "normal" for sample in samples) if steps else True
        unchanged = not_changed_steps(samples, steps)
        evidence["unchanged_steps"] = unchanged
        ok = (not payload["errors"]
              and steps_ok
              and not unchanged
              and probe_verdict(payload.get("probe")) != "silent"
              and payload.get("canvas_initial", {}).get("non_black", 0) > 0
              and payload.get("state_after_input") == "normal"
              and payload.get("client_bytes_after", 0) > payload.get("client_bytes_before", 0)
              and state is not None and state["cleanup"] == "confirmed")
        evidence["verdict"] = "pass" if ok else "fail"
        exit_code = 0 if ok else 1
    finally:
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
            out.write_text(json.dumps(evidence, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        if not args.keep:
            shutil.rmtree(root, ignore_errors=True)
    print(json.dumps({k: evidence.get(k) for k in
                      ("verdict", "services_ready", "steps", "errors", "probe_result",
                       "unchanged_steps", "liveness", "canvas_initial",
                       "canvas_after_input", "state_after_input", "session")},
                     indent=2, ensure_ascii=False))
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
