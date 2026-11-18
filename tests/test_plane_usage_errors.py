"""The control plane must not leak data-plane connection details to callers."""
import logging

import pytest

from kvmhub.platform import services


def test_plane_usage_error_hides_connection_details(monkeypatch, caplog):
    def boom(*args, **kwargs):
        raise RuntimeError("connect to db.example kvmhub@192.0.2.5 failed")

    monkeypatch.setattr(services, "open_store", boom)
    with caplog.at_level(logging.ERROR, logger="kvmhub.platform.services"):
        with pytest.raises(services.PlatformError) as exc:
            services._plane_usage("mysql://u:password@db.example/db", set(), 0, 1, 2)

    assert exc.value.code == "data_plane_unavailable"
    assert "db.example" not in exc.value.message
    assert "kvmhub@192.0.2.5" not in exc.value.message
    assert "数据面库不可读" in exc.value.message
    assert "db.example" in caplog.text
