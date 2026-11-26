"""Plugin digests catch drift without letting an unrelated family break builds."""
from __future__ import annotations

import importlib.util
import shutil
import sys
from pathlib import Path

import pytest

from kvmhub.common import Problem
from kvmhub.transcode import registry

ROOT = Path(__file__).resolve().parents[1]


def _copy_sources(tmp_path: Path) -> Path:
    target = tmp_path / "tree"
    for spec in registry.PLUGINS.values():
        path = target / spec.source
        path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / spec.source, path)
    return target


def _load_tool():
    spec = importlib.util.spec_from_file_location(
        "_transcode_digest", ROOT / "tools" / "transcode_digest.py")
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_build_checks_only_the_selected_family(tmp_path):
    tree = _copy_sources(tmp_path)
    ast = tree / registry.PLUGINS["ast2100-x10"].source
    ast.write_bytes(ast.read_bytes() + b"\n# drift\n")

    with pytest.raises(Problem) as exc:
        registry.verify(tree)
    assert exc.value.code == "transcode_family_unsupported"

    assert registry.build("standard-rfb-v1", tree) is not None

    huawei = tree / registry.PLUGINS["huawei-kvm-v1"].source
    huawei.write_bytes(huawei.read_bytes() + b"\n# drift\n")
    with pytest.raises(Problem) as exc:
        registry.build("huawei-kvm-v1", tree)
    assert exc.value.code == "transcode_family_unsupported"


def test_digest_tool_and_gate_report_the_same_drift(tmp_path):
    tree = _copy_sources(tmp_path)
    source = tree / registry.PLUGINS["huawei-kvm-v1"].source
    source.write_bytes(source.read_bytes() + b"\n")

    tool = _load_tool()
    assert tool.check(tree) and "huawei-kvm-v1" in tool.check(tree)[0]

    spec = importlib.util.spec_from_file_location("_gate_under_test", ROOT / "tools" / "gate.py")
    assert spec and spec.loader
    gate = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = gate
    spec.loader.exec_module(gate)
    drift = gate.check_transcode_digests(tree)
    assert drift and "huawei-kvm-v1" in drift[0]


def test_no_drift_in_a_clean_tree():
    assert _load_tool().check(ROOT) == []
