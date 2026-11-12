"""Automated coverage for tools/browser_e2e.py without a real browser."""
import contextlib
import json
import os
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from tools import browser_e2e as be


class FakeProc:
    def __init__(self, exit_code=None):
        self.pid = 4242
        self.code = exit_code

    def poll(self):
        return self.code

    def wait(self, timeout=None):
        self.code = 0
        return 0

    def kill(self):
        self.code = 0


def _install_boundaries(monkeypatch, *, smoke_rc=0, result="passed", write_result=True):
    calls = {"run": [], "popen": [], "stop": [], "env": []}

    def fake_run(cmd, **kwargs):
        calls["run"].append(cmd)
        bootstrap = any("bootstrap.py" in str(part) for part in cmd)
        if bootstrap:
            directory = Path(kwargs["env"]["KVM_DIRECTORY"])
            directory.mkdir(parents=True, exist_ok=True)
            if write_result:
                (directory / "browser-smoke.json").write_text(json.dumps(
                    {"result": result, "checks": [{"name": "login", "passed": True}]}))
        calls["env"].append(kwargs.get("env", {}))
        return subprocess.CompletedProcess(cmd, 0 if bootstrap else smoke_rc, "", "")

    def fake_popen(cmd, **kwargs):
        calls["popen"].append(cmd)
        calls["env"].append(kwargs.get("env", {}))
        return FakeProc()

    monkeypatch.setattr(be, "subprocess", SimpleNamespace(
        run=fake_run, Popen=fake_popen, TimeoutExpired=subprocess.TimeoutExpired))
    monkeypatch.setattr(be, "socket", SimpleNamespace(
        create_connection=lambda *args, **kwargs: contextlib.nullcontext()))
    monkeypatch.setattr(be, "_stop", lambda proc: calls["stop"].append(proc))
    return calls


def _isolate(monkeypatch, tmp_path):
    monkeypatch.setattr(be, "ROOT", tmp_path)
    monkeypatch.setattr(be, "_find_playwright", lambda: None)
    monkeypatch.setattr(be, "_find_chromium", lambda: None)
    monkeypatch.delenv("KVM_PLAYWRIGHT", raising=False)
    monkeypatch.delenv("KVM_CHROMIUM", raising=False)


def test_find_playwright_only_accepts_the_local_core(monkeypatch, tmp_path):
    monkeypatch.setattr(be, "ROOT", tmp_path)
    assert be._find_playwright() is None
    core = tmp_path / ".local-playwright" / "node_modules" / "playwright-core"
    core.mkdir(parents=True)
    (core / "package.json").write_text("{}")
    assert be._find_playwright() == str(core)


def test_find_chromium_scans_cache_and_prefers_newest_build(monkeypatch, tmp_path):
    monkeypatch.setenv("PLAYWRIGHT_BROWSERS_PATH", str(tmp_path))
    monkeypatch.delenv("LOCALAPPDATA", raising=False)
    monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path / "empty-home"))
    assert be._find_chromium() is None
    old = tmp_path / "chromium-1200" / "chrome-win64" / "chrome.exe"
    new = tmp_path / "chromium-1254" / "chrome-win64" / "chrome.exe"
    for path in (old, new):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("")
    assert be._find_chromium() == str(new)


def test_stop_is_a_noop_for_an_already_exited_process():
    be._stop(None)
    be._stop(FakeProc(exit_code=0))


def test_stop_uses_process_group_on_posix(monkeypatch):
    calls = []
    monkeypatch.setattr(be, "os", SimpleNamespace(
        name="posix", environ=os.environ, killpg=lambda pid, sig: calls.append((pid, sig))))
    monkeypatch.setattr(be, "subprocess", SimpleNamespace(
        run=lambda *args, **kwargs: calls.append(args), TimeoutExpired=subprocess.TimeoutExpired))
    proc = FakeProc()
    be._stop(proc)
    assert calls == [(4242, be.signal.SIGINT)]
    assert proc.poll() == 0


def test_stop_uses_taskkill_on_windows(monkeypatch):
    calls = []
    monkeypatch.setattr(be, "os", SimpleNamespace(name="nt", environ=os.environ))
    monkeypatch.setattr(be, "subprocess", SimpleNamespace(
        run=lambda cmd, **kwargs: calls.append(cmd), TimeoutExpired=subprocess.TimeoutExpired))
    proc = FakeProc()
    be._stop(proc)
    assert calls == [["taskkill", "/PID", "4242", "/T", "/F"]]
    assert proc.poll() == 0


def test_main_rejects_an_existing_directory(tmp_path):
    with pytest.raises(SystemExit) as exc:
        be.main(["--directory", str(tmp_path)])
    assert exc.value.code == 2


def test_main_requires_chromium_for_playwright_core(monkeypatch):
    monkeypatch.setattr(be, "_find_playwright", lambda: "/opt/node_modules/playwright-core")
    monkeypatch.setattr(be, "_find_chromium", lambda: None)
    monkeypatch.delenv("KVM_PLAYWRIGHT", raising=False)
    monkeypatch.delenv("KVM_CHROMIUM", raising=False)
    with pytest.raises(SystemExit) as exc:
        be.main([])
    assert exc.value.code == 2


def test_main_success_cleans_run_directory(monkeypatch, tmp_path, capsys):
    _isolate(monkeypatch, tmp_path)
    calls = _install_boundaries(monkeypatch)
    assert be.main([]) == 0
    out = capsys.readouterr().out
    assert '"result": "passed"' in out
    assert "run directory cleaned" in out
    assert len(calls["popen"]) == 1
    assert len(calls["stop"]) == 1
    assert not list(tmp_path.glob(".local-browser-e2e-*"))
    assert all(env.get("KVM_DIRECTORY") for env in calls["env"])


def test_main_failure_returns_one_and_still_cleans(monkeypatch, tmp_path, capsys):
    _isolate(monkeypatch, tmp_path)
    calls = _install_boundaries(monkeypatch, smoke_rc=1, result="failed")
    assert be.main([]) == 1
    assert "smoke stderr" in capsys.readouterr().out
    assert len(calls["stop"]) == 1
    assert not list(tmp_path.glob(".local-browser-e2e-*"))


def test_main_without_result_file_fails_closed(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    _install_boundaries(monkeypatch, write_result=False)
    assert be.main([]) == 1
    assert not list(tmp_path.glob(".local-browser-e2e-*"))


def test_main_keep_preserves_the_run_directory(monkeypatch, tmp_path, capsys):
    _isolate(monkeypatch, tmp_path)
    _install_boundaries(monkeypatch)
    assert be.main(["--keep"]) == 0
    kept = list(tmp_path.glob(".local-browser-e2e-*"))
    assert len(kept) == 1
    assert (kept[0] / "services.log").exists()
    assert "run directory kept" in capsys.readouterr().out


def test_main_passes_port_overrides_to_every_child(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    monkeypatch.setenv("KVMHUB_UI_PORT", "18443")
    calls = _install_boundaries(monkeypatch)
    assert be.main([]) == 0
    assert all(env.get("KVMHUB_UI_PORT") == "18443" for env in calls["env"])
