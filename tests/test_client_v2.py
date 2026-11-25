"""Pinned standard noVNC bundle selection and fixed-resource boundary."""
import hashlib
from pathlib import Path
import shutil

import pytest

from kvmhub.common import Problem
from kvmhub.video import client_v2


def test_fixed_bundle_manifest_includes_licenses_and_identity():
    manifest = client_v2.verify_bundle()
    assert manifest['version'] == '1.7.0'
    assert manifest['commit'] == '63107bd06d9e1f6136ff21aeda8cd62cbf0d433e'
    assert manifest['license'] == 'MPL-2.0'
    assert 'LICENSE.MPL-2.0' in manifest['files'] and 'AUTHORS' in manifest['files']
    assert client_v2.client_build().endswith(client_v2.MANIFEST_SHA256)
    assert client_v2.MANIFEST_SHA256 not in client_v2.protocol_contract()


def test_html_exposes_a_full_v2_softkey():
    html = client_v2.HTML
    for token in ('id="v2-keybed"', 'id="v2-sk-status"',
                  'data-v2page="chars"', 'data-v2page="symbols"',
                  'data-v2page="func"', 'data-v2page="nav"',
                  'data-v2page="macros"'):
        assert token in html


def test_contract_pins_the_wire_profile_the_server_emits():
    from kvmhub.video.encoding import encode_snapshot
    from kvmhub.video.framebuffer import Rect, Snapshot

    assert client_v2.protocol_contract() == 'console-rfb/1'
    flat = Snapshot(1, 1, Rect(0, 0, 8, 8), b'\x10\x20\x30\xff' * 64)
    message = next(encode_snapshot(flat, tight=True))
    assert message[15] == 7 and message[16] == 0x80
    noisy = Snapshot(1, 1, Rect(0, 0, 8, 8),
                     bytes((i * 37) & 0xFF for i in range(8 * 8 * 4)))
    message = next(encode_snapshot(noisy, tight=True))
    assert message[15] == 7 and message[16] == 0x01


@pytest.mark.parametrize('path', ['/_platform/client-v2/../manifest.json',
    '/_platform/client-v2/viewer.js?x=1', '/_platform/client-v2/manifest.json',
    '/_platform/client-v2/no.js', '/viewer.js'])
def test_resource_boundary(path):
    with pytest.raises(Problem, match='route_denied'):
        client_v2.fetch(path)


def test_missing_or_modified_bundle_refuses_before_login(tmp_path):
    shutil.copytree(client_v2.ROOT, tmp_path / 'bundle')
    root = tmp_path / 'bundle'
    (root / 'viewer.js').write_bytes(b'modified')
    with pytest.raises(Problem, match='pipeline_version_unavailable'):
        client_v2.verify_bundle(root)
    with pytest.raises(Problem, match='pipeline_version_unavailable'):
        client_v2.verify_bundle(tmp_path / 'missing')


def test_select_for_accepts_only_the_exact_approved_bundle():
    approved = client_v2.client_build()
    assert client_v2.select_for({'video_bundle': approved}) is True
    assert client_v2.select_for({'video_bundle': ''}) is False
    assert client_v2.select_for({}) is False
    assert client_v2.select_for({'video_bundle': 'bundle-huawei-v1-r1'}) is False
    with pytest.raises(Problem, match='pipeline_version_unavailable'):
        client_v2.select_for({'video_bundle': 'novnc-v2-1.6.0:deadbeef'})


def test_select_for_binds_the_wire_contract_not_the_recorded_build():
    contract = client_v2.protocol_contract()
    assert client_v2.select_for({'video_contract': contract}) is True
    assert client_v2.select_for({'video_contract': contract,
                                 'video_bundle': 'novnc-v2-1.6.0:old-build'}) is True
    with pytest.raises(Problem, match='pipeline_version_unavailable'):
        client_v2.select_for({'video_contract': 'console-rfb/2'})
    with pytest.raises(Problem, match='pipeline_version_unavailable'):
        client_v2.select_for({'video_contract': 'console-rfb/2',
                              'video_bundle': client_v2.client_build()})


def test_select_for_refuses_a_corrupt_bundle(tmp_path, monkeypatch):
    shutil.copytree(client_v2.ROOT, tmp_path / 'bundle')
    root = tmp_path / 'bundle'
    (root / 'viewer.js').write_bytes(b'tampered')
    monkeypatch.setattr(client_v2, 'ROOT', root)
    with pytest.raises(Problem, match='pipeline_version_unavailable'):
        client_v2.select_for({'video_bundle': client_v2.client_build()})
    with pytest.raises(Problem, match='pipeline_version_unavailable'):
        client_v2.select_for({'video_contract': client_v2.protocol_contract()})


