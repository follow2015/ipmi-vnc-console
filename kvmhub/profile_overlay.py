"""Pure subset proofs for tenant overlays (adapter design v2.1, unit O)."""
from dataclasses import dataclass
import re

from .capability import version_key

_ID = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}')
_FIELDS = frozenset({'model_subset', 'firmware_subset', 'concurrency'})
MAX_MODELS = 256


class OverlayError(ValueError):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def _identifier(value):
    if type(value) is not str or _ID.fullmatch(value) is None:
        raise OverlayError('overlay_identity_invalid')
    return value


def _positive(value):
    if type(value) is not int or value < 1:
        raise OverlayError('overlay_revision_or_limit_invalid')
    return value


def _models(values):
    if type(values) not in (tuple, list) or not 1 <= len(values) <= MAX_MODELS:
        raise OverlayError('overlay_models_invalid')
    result = tuple(_identifier(v) for v in values)
    if len(set(result)) != len(result):
        raise OverlayError('overlay_models_invalid')
    return tuple(sorted(result))


@dataclass(frozen=True)
class FirmwareWindow:
    lower: str
    upper: str

    def __post_init__(self):
        if (type(self.lower) is not str or type(self.upper) is not str
                or version_key(self.lower) is None or version_key(self.upper) is None
                or self.lower != self.lower.strip() or self.upper != self.upper.strip()
                or version_key(self.lower) > version_key(self.upper)):
            raise OverlayError('overlay_firmware_incomparable')

    def contains_window(self, other):
        return (version_key(self.lower) <= version_key(other.lower)
                and version_key(other.upper) <= version_key(self.upper))

    def contains(self, value):
        key = version_key(value) if type(value) is str else None
        return key is not None and version_key(self.lower) <= key <= version_key(self.upper)


@dataclass(frozen=True)
class BaseScope:
    profile_id: str
    revision: int
    model_ids: tuple[str, ...]
    firmware: FirmwareWindow
    concurrency: int

    def __post_init__(self):
        _identifier(self.profile_id)
        _positive(self.revision)
        _positive(self.concurrency)
        object.__setattr__(self, 'model_ids', _models(self.model_ids))
        if type(self.firmware) is not FirmwareWindow:
            raise OverlayError('overlay_firmware_incomparable')


@dataclass(frozen=True)
class OverlaySubset:
    model_ids: tuple[str, ...]
    firmware: FirmwareWindow
    concurrency: int

    def __post_init__(self):
        object.__setattr__(self, 'model_ids', _models(self.model_ids))
        _positive(self.concurrency)
        if type(self.firmware) is not FirmwareWindow:
            raise OverlayError('overlay_firmware_incomparable')

    @classmethod
    def parse(cls, payload):
        if type(payload) is not dict or payload.keys() != _FIELDS:
            raise OverlayError('overlay_fields_invalid')
        window = payload['firmware_subset']
        if type(window) is not dict or window.keys() != {'min', 'max'}:
            raise OverlayError('overlay_firmware_incomparable')
        return cls(payload['model_subset'], FirmwareWindow(window['min'], window['max']),
                   payload['concurrency'])


@dataclass(frozen=True)
class OverlayRevision:
    overlay_id: str
    tenant_id: str
    revision: int
    base_profile_id: str
    base_revision: int
    state: str
    subset: OverlaySubset

    def __post_init__(self):
        for value in (self.overlay_id, self.tenant_id, self.base_profile_id):
            _identifier(value)
        _positive(self.revision)
        _positive(self.base_revision)
        if self.state not in ('active', 'needs_review', 'disabled', 'withdrawn'):
            raise OverlayError('overlay_state_invalid')
        if type(self.subset) is not OverlaySubset:
            raise OverlayError('overlay_fields_invalid')


def prove_subset(base: BaseScope, subset: OverlaySubset):
    if not set(subset.model_ids) <= set(base.model_ids):
        raise OverlayError('overlay_model_expansion')
    if not base.firmware.contains_window(subset.firmware):
        raise OverlayError('overlay_firmware_expansion')
    if subset.concurrency > base.concurrency:
        raise OverlayError('overlay_concurrency_expansion')
    return subset


def effective_scope(base: BaseScope, overlay: OverlayRevision, *, tenant_id: str):
    if overlay.tenant_id != tenant_id:
        raise OverlayError('overlay_tenant_mismatch')
    if overlay.state != 'active':
        raise OverlayError('overlay_not_active')
    if (base.profile_id != overlay.base_profile_id
            or base.revision != overlay.base_revision):
        raise OverlayError('overlay_base_revision_mismatch')
    return prove_subset(base, overlay.subset)


def device_in_scope(scope: OverlaySubset, *, trusted_model_id: str,
                    trusted_firmware: str) -> bool:
    return (trusted_model_id in scope.model_ids
            and scope.firmware.contains(trusted_firmware))


def digest_material(base: BaseScope, overlay: OverlayRevision, *, tenant_id: str) -> dict:
    scope = effective_scope(base, overlay, tenant_id=tenant_id)
    return {'overlay_id': overlay.overlay_id, 'overlay_revision': overlay.revision,
            'tenant_id': overlay.tenant_id, 'base_profile_id': base.profile_id,
            'base_revision': base.revision, 'model_subset': list(scope.model_ids),
            'firmware_subset': {'min': scope.firmware.lower, 'max': scope.firmware.upper},
            'concurrency': scope.concurrency}
