"""One-shot orchestration for the local synthetic browser acceptance."""
from __future__ import annotations

import argparse
import json
import os
import secrets
import shutil
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from kvmhub.common import BMC_PORT, INTERNAL_PORT, UI_ORIGIN, UI_PORT, WORKER_PORT  # noqa: E402


def _find_playwright():
    local = ROOT / ".local-playwright" / "node_modules" / "playwright-core"
    return str(local) if (local / "package.json").exists() else None


def _find_chromium():
    bases = []
    if os.environ.get("PLAYWRIGHT_BROWSERS_PATH"):
        bases.append(Path(os.environ["PLAYWRIGHT_BROWSERS_PATH"]))
    if os.name == "nt" and os.environ.get("LOCALAPPDATA"):
        bases.append(Path(os.environ["LOCALAPPDATA"]) / "ms-playwright")
    bases.append(Path.home() / ".cache" / "ms-playwright")
    patterns = (
        "chromium-*/chrome-win64/chrome.exe",
        "chromium-*/chrome-win/chrome.exe",
        "chromium-*/chrome-linux/chrome",
        "chromium-*/chrome-mac/Chromium.app/Contents/MacOS/Chromium",
        "chromium_headless_shell-*/chrome-win64/headless_shell.exe",
    )
    for base in bases:
        for pattern in patterns:
            hits = sorted(base.glob(pattern), reverse=True)
            if hits:
                return str(hits[0])
    return None


def _stop(proc):
    if proc is None or proc.poll() is not None:
        return
    if os.name == "posix":
        os.killpg(proc.pid, signal.SIGINT)
    else:
        subprocess.run(["taskkill", "/PID", str(proc.pid), "/T", "/F"], capture_output=True)
    try:
        proc.wait(timeout=15)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", help="fresh run directory; default: auto-generated and cleaned afterwards")
    parser.add_argument("--keep", action="store_true", help="keep the run directory (contains short-lived private keys)")
    parser.add_argument("--playwright", help="playwright module path (or KVM_PLAYWRIGHT)")
    parser.add_argument("--chromium", help="Chromium executable (or KVM_CHROMIUM)")
    parser.add_argument("--node", default="node")
    parser.add_argument("--startup-timeout", type=float, default=25)
    args = parser.parse_args(argv)

    module = args.playwright or os.environ.get("KVM_PLAYWRIGHT") or _find_playwright()
    chrome = args.chromium or os.environ.get("KVM_CHROMIUM") or _find_chromium()
    if module and "playwright-core" in module and not chrome:
        parser.error("playwright-core needs a browser: pass --chromium or set KVM_CHROMIUM")

    owned = args.directory is None
    directory = (ROOT / f".local-browser-e2e-{secrets.token_hex(4)}") if owned else Path(args.directory).resolve()
    if directory.exists():
        parser.error(f"refusing to overwrite existing directory: {directory}")

    env = os.environ.copy()
    env["KVM_DIRECTORY"] = str(directory)
    if module:
        env["KVM_PLAYWRIGHT"] = module
    if chrome:
        env["KVM_CHROMIUM"] = chrome

    print(f"manager origin : {UI_ORIGIN}", flush=True)
    print(f"ports          : ui={UI_PORT} internal={INTERNAL_PORT} worker={WORKER_PORT} bmc={BMC_PORT}", flush=True)
    print(f"run directory  : {directory}", flush=True)

    log = None
    proc = None
    try:
        boot = subprocess.run([sys.executable, str(ROOT / "tools/bootstrap.py"), "--directory", str(directory)],
                              cwd=ROOT, env=env, capture_output=True, text=True, timeout=60)
        if boot.returncode:
            raise RuntimeError("bootstrap failed: " + (boot.stdout + boot.stderr).strip()[:800])

        log = (directory / "services.log").open("w+", encoding="utf-8")
        kwargs = {"start_new_session": True} if os.name == "posix" else {}
        proc = subprocess.Popen([sys.executable, "-m", "kvmhub.run", "--directory", str(directory)],
                                cwd=ROOT, env=env, stdout=log, stderr=log, **kwargs)
        deadline = time.monotonic() + args.startup_timeout
        while True:
            if proc.poll() is not None:
                log.seek(0)
                raise RuntimeError("services exited early:\n" + log.read()[:1200])
            try:
                for port in (UI_PORT, INTERNAL_PORT, WORKER_PORT, BMC_PORT):
                    with socket.create_connection(("127.0.0.1", port), timeout=0.3):
                        pass
                break
            except OSError:
                if time.monotonic() >= deadline:
                    log.seek(0)
                    raise RuntimeError("services startup timeout:\n" + log.read()[:1200])
                time.sleep(0.15)

        smoke = subprocess.run([args.node, "tools/browser_smoke.cjs"], cwd=ROOT, env=env,
                               capture_output=True, text=True, timeout=240)
        result = None
        result_file = directory / "browser-smoke.json"
        if result_file.exists():
            result = json.loads(result_file.read_text(encoding="utf-8"))
            print(json.dumps({"result": result.get("result"),
                              "checks": [check["name"] for check in result.get("checks", [])],
                              "error": result.get("error")}, ensure_ascii=False), flush=True)
        if smoke.returncode or not result or result.get("result") != "passed":
            print("--- smoke stdout (tail) ---\n" + smoke.stdout[-1500:])
            print("--- smoke stderr (tail) ---\n" + smoke.stderr[-1000:])
            return 1
        return 0
    except (OSError, RuntimeError, ValueError, subprocess.TimeoutExpired) as exc:
        print(f"e2e failed: {exc}", file=sys.stderr)
        return 1
    finally:
        _stop(proc)
        if log is not None:
            log.close()
        if owned and not args.keep and directory.exists():
            shutil.rmtree(directory, ignore_errors=True)
            if directory.exists():
                print(f"warning: could not fully clean {directory}", file=sys.stderr)
            else:
                print("run directory cleaned (short-lived keys removed)", flush=True)
        elif directory.exists():
            print(f"run directory kept (contains private keys, do not commit): {directory}", flush=True)


if __name__ == "__main__":
    raise SystemExit(main())
