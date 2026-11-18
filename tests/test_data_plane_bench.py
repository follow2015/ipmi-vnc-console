"""The concurrent data-plane benchmark must stay honest and shape-only."""
from __future__ import annotations

import asyncio
from pathlib import Path

from tools import data_plane_bench as bench


def test_resource_probes_return_numbers():
    rss = bench._rss_bytes()
    cpu = bench._cpu_seconds()
    cpu_ns = bench._cpu_ns()
    assert isinstance(rss, int) and rss >= 0
    assert isinstance(cpu, float) and cpu >= 0
    assert isinstance(cpu_ns, int) and cpu_ns >= 0


def test_small_concurrent_run_is_lossless_and_shape_only(tmp_path: Path):
    report = asyncio.run(bench.run_probe(sessions=3, seconds=1, tmp_path=tmp_path))

    assert report["sessions"] == 3
    assert report["connections"]["opened"] == 3
    assert report["connections"]["delivered"] == 3
    assert report["connections"]["dropped"] == 0
    assert report["connections"]["no_loss"] is True
    assert report["revoke"]["all_consoles_closed"] is True
    assert report["throughput"]["frames_total"] >= 3
    assert report["resources"]["cpu_nanoseconds"] >= 0
    assert isinstance(report["resources"]["cpu_counter_advanced"], bool)
    assert all(report["assertions"].values()), report["assertions"]

    text = str(report)
    assert bench.BROWSER_SECRET not in text
    assert "10.100" not in text
    assert "kvm.localhost" not in text
    assert "SYNTHETIC BMC" not in text.upper()
    assert report["shape_only"] is True


def test_sid_is_hex_so_host_mode_accepts_it(tmp_path: Path):
    report = asyncio.run(bench.run_probe(sessions=2, seconds=1, tmp_path=tmp_path))
    assert report["connections"]["dropped"] == 0
    assert report["connections"]["delivered"] == 2
