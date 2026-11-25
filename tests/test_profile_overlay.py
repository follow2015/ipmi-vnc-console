"""O policy proofs: expansion, stale revisions and inactive overlays refuse."""
from dataclasses import replace
import json

import pytest

from kvmhub.profile_overlay import (BaseScope, FirmwareWindow, OverlayError,
                                    OverlayRevision, OverlaySubset, device_in_scope,
                                    digest_material, effective_scope, prove_subset)


def base():
    return BaseScope('huawei-v5', 4, ('model-b', 'model-a'),
                     FirmwareWindow('6.20', '6.40'), 4)


def subset():
    return OverlaySubset.parse({'model_subset': ['model-a'],
                                'firmware_subset': {'min': '6.25', 'max': '6.30'},
                                'concurrency': 2})


def overlay():
    return OverlayRevision('overlay-1', 'tenant-a', 2, 'huawei-v5', 4, 'active', subset())


def test_subset_and_exact_boundaries_use_numeric_firmware_order():
    scope = effective_scope(base(), overlay(), tenant_id='tenant-a')
    for value in ('6.25', '6.25.0', '6.30'):
        assert device_in_scope(scope, trusted_model_id='model-a', trusted_firmware=value)
    for value in ('6.24.99', '6.30.1', '6.9', '6.300', 'vendor-6.27', '', None):
        assert not device_in_scope(scope, trusted_model_id='model-a', trusted_firmware=value)
    assert not device_in_scope(scope, trusted_model_id='model-b', trusted_firmware='6.27')
    assert prove_subset(base(), OverlaySubset(base().model_ids, base().firmware, 4))


@pytest.mark.parametrize('changes,code', [
    ({'model_ids': ('model-a', 'outside')}, 'model_expansion'),
    ({'firmware': FirmwareWindow('6.19', '6.30')}, 'firmware_expansion'),
    ({'firmware': FirmwareWindow('6.25', '6.41')}, 'firmware_expansion'),
    ({'concurrency': 5}, 'concurrency_expansion'),
])
def test_expansion_refused(changes, code):
    with pytest.raises(OverlayError, match=code):
        prove_subset(base(), replace(subset(), **changes))


@pytest.mark.parametrize('field', [
    'port', 'path', 'pin', 'driver', 'heartbeat', 'recovery', 'input_shaping',
    'detect', 'compatible', 'state', 'tenant_id',
])
def test_unknown_fields_cannot_widen_policy(field):
    payload = {'model_subset': ['model-a'],
               'firmware_subset': {'min': '6.25', 'max': '6.30'}, 'concurrency': 2}
    payload[field] = 'untrusted'
    with pytest.raises(OverlayError, match='fields_invalid'):
        OverlaySubset.parse(payload)


@pytest.mark.parametrize('low,high', [
    ('', '6.30'), ('6.25', ''), ('6.25', None), ('vendor', '6.30'),
    ('6.25', '6.30-beta'), ('6.31', '6.30'), (' 6.25', '6.30'),
    ('6.25', '6.30 '), (True, '6.30'), ('1.2.3.4.5', '9'),
])
def test_incomparable_or_open_windows_refuse(low, high):
    with pytest.raises(OverlayError, match='firmware_incomparable'):
        FirmwareWindow(low, high)


@pytest.mark.parametrize('value', [True, False, 0, -1, 2.0, '2', None])
def test_concurrency_is_strict_positive_integer(value):
    with pytest.raises(OverlayError, match='limit_invalid'):
        replace(subset(), concurrency=value)


@pytest.mark.parametrize('models', [[], ['model-a', 'model-a'], ['*'], [''],
                                    ['model-a '], ['a'] * 257, 'model-a', [True]])
def test_models_are_bounded_exact_ids(models):
    with pytest.raises(OverlayError):
        replace(subset(), model_ids=models)


@pytest.mark.parametrize('state', ['needs_review', 'disabled', 'withdrawn'])
def test_inactive_state_never_falls_back_to_wider_base(state):
    with pytest.raises(OverlayError, match='not_active'):
        effective_scope(base(), replace(overlay(), state=state), tenant_id='tenant-a')


def test_revision_profile_and_tenant_binding_cannot_be_bypassed():
    with pytest.raises(OverlayError, match='tenant_mismatch'):
        effective_scope(base(), overlay(), tenant_id='tenant-b')
    for changed in (replace(base(), revision=5), replace(base(), profile_id='other')):
        with pytest.raises(OverlayError, match='base_revision_mismatch'):
            effective_scope(changed, overlay(), tenant_id='tenant-a')


def test_canonical_digest_data_binds_both_revisions_and_copies_mutable_inputs():
    b, o = base(), overlay()
    material = digest_material(b, o, tenant_id='tenant-a')
    assert material['base_revision'] == 4 and material['overlay_revision'] == 2
    changed = digest_material(b, replace(o, revision=3), tenant_id='tenant-a')
    assert json.dumps(material, sort_keys=True) != json.dumps(changed, sort_keys=True)
    payload = {'model_subset': ['model-b', 'model-a'],
               'firmware_subset': {'min': '6.25', 'max': '6.30'}, 'concurrency': 2}
    parsed = OverlaySubset.parse(payload)
    payload['model_subset'].clear()
    payload['firmware_subset']['min'] = '0'
    assert parsed.model_ids == ('model-a', 'model-b') and parsed.firmware.lower == '6.25'
    material['model_subset'].clear()
    assert o.subset.model_ids == ('model-a',)


@pytest.mark.parametrize('payload', [None, [], {}, {'model_subset': ['model-a']},
    {'model_subset': ['model-a'], 'firmware_subset': {'min': '6', 'max': '7', 'x': 1},
     'concurrency': 1}])
def test_incomplete_schema_refuses(payload):
    with pytest.raises(OverlayError):
        OverlaySubset.parse(payload)
