"""Port overrides are read at import time and must fail loudly on bad input."""
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from kvmhub import common

ROOT = Path(__file__).resolve().parents[1]
PORT_VARS = ("KVMHUB_UI_PORT", "KVMHUB_INTERNAL_PORT", "KVMHUB_WORKER_PORT", "KVMHUB_BMC_PORT")
PROBE = """\
import json
from kvmhub.common import (UI_PORT, INTERNAL_PORT, WORKER_PORT, BMC_PORT,
                           UI_ORIGIN, INTERNAL_ORIGIN, BMC_BASE_URL, WORKER_HOST_SUFFIX)
print(json.dumps({
    "UI_PORT": UI_PORT, "INTERNAL_PORT": INTERNAL_PORT,
    "WORKER_PORT": WORKER_PORT, "BMC_PORT": BMC_PORT,
    "UI_ORIGIN": UI_ORIGIN, "INTERNAL_ORIGIN": INTERNAL_ORIGIN,
    "BMC_BASE_URL": BMC_BASE_URL, "WORKER_HOST_SUFFIX": WORKER_HOST_SUFFIX,
}))
"""
DEFAULTS = {"UI_PORT": 8443, "INTERNAL_PORT": 8444, "WORKER_PORT": 9443, "BMC_PORT": 10443}
DEFAULT_URLS = {
    "UI_ORIGIN": "https://localhost:8443",
    "INTERNAL_ORIGIN": "https://localhost:8444",
    "BMC_BASE_URL": "https://127.0.0.1:10443",
    "WORKER_HOST_SUFFIX": ":9443",
}


def _probe(overrides=None):
    env = {key: value for key, value in os.environ.items() if key not in PORT_VARS}
    env.update(overrides or {})
    env["PYTHONPATH"] = str(ROOT)
    return subprocess.run([sys.executable, "-c", PROBE], cwd=ROOT, env=env,
                          capture_output=True, text=True, timeout=30)


def _payload(overrides=None):
    result = _probe(overrides)
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)


def test_defaults_are_unchanged():
    data = _payload()
    assert {key: data[key] for key in DEFAULTS} == DEFAULTS
    assert {key: data[key] for key in DEFAULT_URLS} == DEFAULT_URLS


def test_full_override_reaches_every_derived_url():
    data = _payload({
        "KVMHUB_UI_PORT": "18443", "KVMHUB_INTERNAL_PORT": "18444",
        "KVMHUB_WORKER_PORT": "19443", "KVMHUB_BMC_PORT": "20443",
    })
    assert [data[key] for key in DEFAULTS] == [18443, 18444, 19443, 20443]
    assert data["UI_ORIGIN"] == "https://localhost:18443"
    assert data["INTERNAL_ORIGIN"] == "https://localhost:18444"
    assert data["BMC_BASE_URL"] == "https://127.0.0.1:20443"
    assert data["WORKER_HOST_SUFFIX"] == ":19443"


def test_partial_override_keeps_other_defaults():
    data = _payload({"KVMHUB_WORKER_PORT": "19443"})
    assert data["WORKER_PORT"] == 19443
    assert data["WORKER_HOST_SUFFIX"] == ":19443"
    assert {key: data[key] for key in DEFAULTS if key != "WORKER_PORT"} == {
        key: value for key, value in DEFAULTS.items() if key != "WORKER_PORT"}
    assert data["UI_ORIGIN"] == DEFAULT_URLS["UI_ORIGIN"]


@pytest.mark.parametrize("value", ["1", "65535"])
def test_boundary_values_are_valid(value):
    assert _payload({"KVMHUB_UI_PORT": value})["UI_PORT"] == int(value)


@pytest.mark.parametrize("value", ["abc", "", "0", "-1", "65536", "99999", "8.5"])
def test_invalid_values_fail_loudly(value):
    result = _probe({"KVMHUB_BMC_PORT": value})
    assert result.returncode != 0
    assert "KVMHUB_BMC_PORT" in result.stderr
    assert "must be" in result.stderr
    assert "BMC_BASE_URL" not in result.stdout


def test_active_module_agrees_with_environment():
    for var, name, default in (
        ("KVMHUB_UI_PORT", "UI_PORT", 8443),
        ("KVMHUB_INTERNAL_PORT", "INTERNAL_PORT", 8444),
        ("KVMHUB_WORKER_PORT", "WORKER_PORT", 9443),
        ("KVMHUB_BMC_PORT", "BMC_PORT", 10443),
    ):
        expected = int(os.environ[var]) if var in os.environ else default
        assert getattr(common, name) == expected, var
    assert common.UI_ORIGIN == f"https://localhost:{common.UI_PORT}"
    assert common.INTERNAL_ORIGIN == f"https://localhost:{common.INTERNAL_PORT}"
    assert common.BMC_BASE_URL == f"https://127.0.0.1:{common.BMC_PORT}"
    assert common.WORKER_HOST_SUFFIX == f":{common.WORKER_PORT}"
