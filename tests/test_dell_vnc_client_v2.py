"""Dell built-in VNC speaks standard RFB, so it uses the same fixed V2 client."""
import pytest

from kvmhub import worker
from kvmhub.adapters.idrac_vnc import IdracVncAdapter
from kvmhub.adapters.passthrough import PassthroughAdapter
from kvmhub.common import IDRAC_VNC_ADAPTER_ID, PASSTHROUGH_ADAPTER_ID, Problem
from kvmhub.platform.data_plane import assembled_info
from kvmhub.video import client_v2


def _info(*, bundle: str = '', contract: str = client_v2.protocol_contract()) -> dict:
    return {
        'adapter': IDRAC_VNC_ADAPTER_ID,
        'video_bundle': bundle,
        'video_contract': contract,
        'video_binding': 'g1-permit-digest',
    }


def test_dell_vnc_adapter_uses_the_approved_v2_contract():
    adapter = object.__new__(IdracVncAdapter)
    assert worker.apply_client_bundle(adapter, _info()) is True
    assert adapter.client_v2 is True


def test_dell_vnc_build_divergence_does_not_invalidate_the_contract():
    adapter = object.__new__(IdracVncAdapter)
    assert worker.apply_client_bundle(
        adapter, _info(bundle='novnc-v2-1.6.0:old-build')) is True
    assert adapter.client_v2 is True


def test_dell_vnc_refuses_a_wrong_wire_contract_instead_of_downgrading():
    adapter = object.__new__(IdracVncAdapter)
    with pytest.raises(Problem, match='pipeline_version_unavailable'):
        worker.apply_client_bundle(adapter, _info(contract='console-rfb/2'))
    assert not getattr(adapter, 'client_v2', False)


def test_dell_vnc_refuses_an_unmatched_v2_bundle_without_a_contract():
    adapter = object.__new__(IdracVncAdapter)
    with pytest.raises(Problem, match='pipeline_version_unavailable'):
        worker.apply_client_bundle(adapter, _info(
            bundle='novnc-v2-1.6.0:deadbeef', contract=''))
    assert not getattr(adapter, 'client_v2', False)


def test_dell_vnc_keeps_the_legacy_client_without_an_approved_identity():
    adapter = object.__new__(IdracVncAdapter)
    assert worker.apply_client_bundle(adapter, _info(
        bundle='bundle-huawei-v1-r1', contract='')) is False
    assert adapter.client_v2 is False


def test_supermicro_passthrough_never_gets_the_standard_client():
    adapter = object.__new__(PassthroughAdapter)
    adapter.adapter_id = PASSTHROUGH_ADAPTER_ID
    assert worker.apply_client_bundle(adapter, _info()) is False
    assert adapter.client_v2 is False


def test_assembled_info_carries_the_client_identity_without_a_transcode_recipe():
    assembly = {
        'client_contract': client_v2.protocol_contract(),
        'client_bundle': client_v2.client_build(),
        'data_plane': {
            'adapter': IDRAC_VNC_ADAPTER_ID,
            'capability_entry': {
                'adapter': IDRAC_VNC_ADAPTER_ID,
                'protocol_versions': ['RFB 003.008'],
            },
        },
        'plan': {},
    }
    info = assembled_info({'adapter': IDRAC_VNC_ADAPTER_ID}, assembly)
    assert info['video_contract'] == client_v2.protocol_contract()
    assert info['video_bundle'] == client_v2.client_build()
    assert info['video_lane'] == ''
