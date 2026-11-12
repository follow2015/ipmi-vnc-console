"""Policy tests for the compatibility matrix (design §7)."""
import pytest

from kvmhub import capability

NOW = 1_000_000.0
DAY = 86400.0


def entry(**overrides):
    base = {
        "id": "cap-1", "vendor": "Supermicro (Inspur OEM)",
        "model": "X10DRT-PS / SA5248M4", "firmware": "8.78",
        "adapter": "supermicro-x10-passthrough", "status": "verified",
        "models": "[]", "firmware_min": "", "firmware_max": "",
        "approver": "albert", "evidence": "docs/evidence/x.json",
        "licence": "未取得书面许可", "console_impl": "AST2100 / iKVM HTML5",
        "concurrency_limit": 1, "effective_from": NOW - DAY,
        "expires": NOW + DAY, "review_due": NOW + DAY,
    }
    base.update(overrides)
    return base


def asset(**overrides):
    base = {"vendor": "Supermicro (Inspur OEM)", "model": "X10DRT-PS / SA5248M4",
            "firmware": "8.78"}
    base.update(overrides)
    return base


def test_transitions_are_explicit_and_retirement_is_terminal():
    assert capability.transition_allowed("draft", "verified")
    assert capability.transition_allowed("suspended", "verified")
    assert capability.transition_allowed("verified", "verified")
    assert capability.transition_allowed("verified", "suspended")
    assert capability.transition_allowed("suspended", "retired")
    assert not capability.transition_allowed("draft", "suspended")
    assert not capability.transition_allowed("retired", "verified")
    assert not capability.transition_allowed("retired", "suspended")
    assert not capability.transition_allowed("unknown", "verified")


@pytest.mark.parametrize("text,expected", [
    ("8.78", (8, 78, 0, 0)),
    ("8", (8, 0, 0, 0)),
    ("8.78.1.2", (8, 78, 1, 2)),
    (" 8.78 ", (8, 78, 0, 0)),
])
def test_version_key_accepts_dotted_numbers(text, expected):
    assert capability.version_key(text) == expected


@pytest.mark.parametrize("text", ["", None, "8.78a", "v8.78", "8..78", "8.78.1.2.3", "٨.٧٨", "8,78"])
def test_version_key_refuses_anything_it_cannot_order(text):
    assert capability.version_key(text) is None


def test_exact_firmware_match_is_the_default():
    cap = entry()
    assert capability.firmware_in_range(cap, "8.78")
    assert not capability.firmware_in_range(cap, "8.79")
    assert not capability.firmware_in_range(cap, "8.7")
    assert not capability.firmware_in_range(cap, "")


def test_firmware_window_is_inclusive_on_both_ends():
    cap = entry(firmware="", firmware_min="8.70", firmware_max="8.79")
    assert capability.firmware_in_range(cap, "8.70")
    assert capability.firmware_in_range(cap, "8.75")
    assert capability.firmware_in_range(cap, "8.79")
    assert not capability.firmware_in_range(cap, "8.69")
    assert not capability.firmware_in_range(cap, "8.80")


def test_one_sided_window_and_unparsable_input_fail_closed():
    assert capability.firmware_in_range(entry(firmware="", firmware_min="8.70"), "9.0")
    assert not capability.firmware_in_range(entry(firmware="", firmware_min="8.70"), "8.6")
    assert capability.firmware_in_range(entry(firmware="", firmware_max="8.79"), "1.0")
    assert not capability.firmware_in_range(entry(firmware="", firmware_max="8.79"), "8.80")
    assert not capability.firmware_in_range(entry(firmware="", firmware_min="8.70"), "8.78-r2")
    assert not capability.firmware_in_range(entry(firmware="", firmware_min="beta"), "8.78")


def test_window_must_parse_before_it_is_stored():
    assert capability.window_parses(entry())
    assert capability.window_parses(entry(firmware_min="8.70", firmware_max="8.79"))
    assert not capability.window_parses(entry(firmware_min="8.79", firmware_max="8.70"))
    assert not capability.window_parses(entry(firmware_min="8.x"))


def test_model_family_membership():
    assert capability.models_in_family(entry(), "X10DRT-PS / SA5248M4")
    assert not capability.models_in_family(entry(), "X11DPH-T")
    family = entry(model="X10 family", models='["X10DRT-PS / SA5248M4", "X10DRi"]')
    assert capability.models_in_family(family, "X10DRi")
    assert not capability.models_in_family(family, "X11DPH-T")
    assert capability.models_in_family(entry(model="X10", models="{not json"), "X10")
    assert not capability.models_in_family(entry(model="X10", models="{not json"), "X11")


def test_gate_opens_only_for_a_complete_entry():
    assert capability.evaluate(entry(), asset(), NOW) is None


@pytest.mark.parametrize("field", ["approver", "evidence", "licence", "console_impl"])
def test_each_approval_input_is_required(field):
    assert capability.evaluate(entry(**{field: ""}), asset(), NOW) == "unapproved"
    assert capability.evaluate(entry(**{field: "   "}), asset(), NOW) == "unapproved"


def test_status_is_reported_before_dates():
    assert capability.evaluate(entry(status="suspended", expires=NOW - 1), asset(), NOW) == "not_verified"
    assert capability.evaluate(entry(status="draft"), asset(), NOW) == "not_verified"
    assert capability.evaluate(entry(status="retired"), asset(), NOW) == "not_verified"
    assert capability.evaluate(None, asset(), NOW) == "missing_entry"


def test_dates_are_checked_individually():
    assert capability.evaluate(entry(effective_from=NOW + 1), asset(), NOW) == "not_yet_effective"
    assert capability.evaluate(entry(expires=NOW), asset(), NOW) == "expired"
    assert capability.evaluate(entry(review_due=NOW), asset(), NOW) == "review_overdue"


def test_identity_mismatch_covers_vendor_model_and_firmware():
    assert capability.evaluate(entry(), asset(vendor="Dell"), NOW) == "identity_mismatch"
    assert capability.evaluate(entry(), asset(model="X11DPH-T"), NOW) == "identity_mismatch"
    assert capability.evaluate(entry(), asset(firmware="8.79"), NOW) == "firmware_out_of_range"


def test_zero_concurrency_is_refused():
    assert capability.evaluate(entry(concurrency_limit=0), asset(), NOW) == "no_capacity"
    assert capability.evaluate(entry(concurrency_limit=None), asset(), NOW) == "no_capacity"
