"""Registry/lifecycle contracts shared by the current first-party drivers."""
import json
import subprocess
import sys
from dataclasses import FrozenInstanceError
from types import SimpleNamespace

import pytest

from kvmhub import client_assets
from kvmhub.adapter_contract import ENABLED_ADAPTER_IDS
from kvmhub.common import Problem
from kvmhub.driver_factory import FACTORIES, make_adapter
from kvmhub.driver_specs import (CONSOLE_DRIVERS, DRIVERS, LEGACY_RELAY_PROFILES,
                                  REAL_ADAPTER_IDS, DriverSpec, freeze_specs)
from kvmhub.platform.brand_onboarding import CONSOLE_IMPLS
from kvmhub.worker import input_protocol_for_adapter


@pytest.mark.parametrize('driver_id', tuple(REAL_ADAPTER_IDS))
async def test_each_real_driver_gets_the_real_console_page(driver_id):
    from aiohttp.test_utils import make_mocked_request
    from kvmhub.worker import Gateway, REAL_CONSOLE_HTML
    adapter = FACTORIES[driver_id].__new__(FACTORIES[driver_id])
    gateway = SimpleNamespace(authenticated=lambda request: SimpleNamespace(adapter=adapter))
    response = await Gateway.handle(gateway, make_mocked_request('GET', '/'))
    assert response.status == 200
    assert response.text == REAL_CONSOLE_HTML


@pytest.mark.parametrize('driver_id', tuple(DRIVERS))
def test_all_descriptions_have_explicit_factories_and_input_contract(driver_id):
    cls = FACTORIES[driver_id]
    adapter = cls.__new__(cls)
    assert input_protocol_for_adapter(adapter) == DRIVERS[driver_id].input_protocol
    assert cls.adapter_id == driver_id
    assert cls.connection_limit == DRIVERS[driver_id].connection_limit
    assert getattr(cls, 'login_budget', 10.0) == DRIVERS[driver_id].login_budget
    assert getattr(cls, 'supports_upstream_recovery', False) == DRIVERS[driver_id].supports_upstream_recovery
    assert DRIVERS[driver_id].real_console == (driver_id in REAL_ADAPTER_IDS)
    if driver_id != 'mock-v1':
        assert CONSOLE_DRIVERS[DRIVERS[driver_id].console_impl] == driver_id
    assert ENABLED_ADAPTER_IDS == frozenset({'mock-v1'})


@pytest.mark.parametrize('driver_id,expected', (
    ('mock-v1', ('insyde18', 4, 10.0, False, False)),
    ('supermicro-x10-passthrough', ('insyde18', 1, 10.0, True, False)),
    ('rfb-relay', ('standard8', 1, 28.0, False, True)),
    ('huawei-ibmc-kvm-gateway', ('standard8', 1, 35.0, False, True)),
    ('aten-java-rfb-tcp', ('insyde18', 1, 26.0, False, True)),
))
def test_r_refactor_preserves_previous_driver_behavior(driver_id, expected):
    spec = DRIVERS[driver_id]
    assert (spec.input_protocol, spec.connection_limit, spec.login_budget,
            spec.supports_upstream_recovery, spec.controlled_network) == expected


def test_relay_template_keeps_the_measured_brand_presets():
    dell = LEGACY_RELAY_PROFILES['dell-idrac-vnc-tcp']
    huawei = LEGACY_RELAY_PROFILES['huawei-ibmc-vnc-tls']
    assert (dell['port'], dell['tls'], dell['pin_source'], dell['encodings']) == (
        5901, 'none', '', (0, 1))
    assert (huawei['port'], huawei['tls'], huawei['pin_source'], huawei['encodings']) == (
        5900, 'pinned', 'asset_then_env', None)
    assert DRIVERS['rfb-relay'].port == 0


def test_registry_is_immutable_and_rejects_duplicate_ids_or_impls():
    spec = DRIVERS['mock-v1']
    with pytest.raises(TypeError):
        DRIVERS['extra'] = spec
    with pytest.raises(FrozenInstanceError):
        spec.real_console = True
    with pytest.raises(ValueError, match='duplicate'):
        freeze_specs([spec, spec])
    first = DriverSpec('a', 'same', 'standard8', True, 'local_novnc')
    second = DriverSpec('b', 'same', 'standard8', True, 'local_novnc')
    with pytest.raises(ValueError, match='duplicate'):
        freeze_specs([first, second])
    assert set(CONSOLE_DRIVERS) <= CONSOLE_IMPLS
    assert set(LEGACY_RELAY_PROFILES) <= CONSOLE_IMPLS
    with pytest.raises(Problem) as exc:
        make_adapter({'adapter': 'unknown'})
    assert exc.value.code == 'adapter_not_verified'


def test_control_plane_descriptions_do_not_import_executable_drivers():
    code = '''
import json, sys
import kvmhub.driver_specs
from kvmhub.platform import brand_onboarding, connection, data_plane
print(json.dumps([name for name in sys.modules if name.startswith((
    "kvmhub.adapters", "kvmhub.driver_factory", "kvmhub.huawei_kvm_protocol",
    "kvmhub.rfb_tcp_upstream"))]))
'''
    result = subprocess.run([sys.executable, '-c', code], check=True, capture_output=True,
                            text=True, timeout=20)
    assert json.loads(result.stdout) == []


@pytest.mark.parametrize('driver_id', tuple(REAL_ADAPTER_IDS))
def test_implementation_registration_does_not_bypass_store_target_gate(driver_id):
    from kvmhub.store import Store
    store = SimpleNamespace(passthrough_targets=frozenset(), bmc_allowed_networks=())
    assert not Store._adapter_allowed(store, {'adapter': driver_id,
                                             'target': 'https://192.0.2.10'})


@pytest.mark.parametrize('driver_id', tuple(key for key, spec in DRIVERS.items()
                                          if spec.client_bundle == 'local_novnc'))
async def test_each_local_bundle_driver_has_the_same_bounded_resource_contract(driver_id):
    adapter = FACTORIES[driver_id].__new__(FACTORIES[driver_id])
    content_type, body = await adapter.fetch_asset('/novnc/include/rfb.js')
    assert content_type == 'application/javascript' and body
    assert (await adapter.fetch_asset('/novnc/include/rfb'))[1] == body
    for path in ('/novnc/include/../../etc/passwd', '/novnc/include/rfb.js?q=1',
                 '/cgi/login.cgi', '/novnc/include/unknown.js'):
        with pytest.raises(Problem) as exc:
            await adapter.fetch_asset(path)
        assert exc.value.code == 'route_denied'


@pytest.mark.parametrize('driver_id', ('rfb-relay',))
async def test_tcp_family_handshake_and_cleanup_contract(driver_id):
    from kvmhub.rfb_server import build_server_init_32bpp
    adapter = FACTORIES[driver_id].__new__(FACTORIES[driver_id])
    adapter.session = None
    adapter.upstream = None
    with pytest.raises(Problem) as exc:
        await adapter.connect([])
    assert exc.value.code == 'subprotocol_required'
    with pytest.raises(Problem) as exc:
        await adapter.connect(['binary'])
    assert exc.value.code == 'upstream_handshake_failed'
    assert await adapter.close() is False

    class Upstream:
        server_init_raw = build_server_init_32bpp(16, 16, 'synthetic')
        closed = False
        async def close(self):
            self.closed = True
    upstream = Upstream()
    adapter.upstream = upstream
    session = await adapter.connect(['binary'])
    assert session is adapter.session
    with pytest.raises(Problem) as exc:
        await adapter.connect(['binary'])
    assert exc.value.code == 'connection_limit'
    assert await adapter.close() is True
    assert upstream.closed and session.closed
    assert await adapter.close() is False
