import math
from integration.live.audit_observation import flag_errors
from integration.live.dashboard import _friendly_name


def scored(value, flag):
    return {"device_id": "device", "behavioral_score": value, "behavioral_flag": flag,
            "link_anomaly": None, "link_flag": None, "calibration_scope": {"a": {"value": 1.0}}}


def test_audit_checks_strict_boundary_and_unavailable_scores():
    assert flag_errors([scored(1.0, False), scored(1.001, True), scored(None, None)]) == []
    assert flag_errors([scored(1.0, True)])[0][-1] == "strict_cutoff_mismatch"
    assert flag_errors([scored(None, False)])[0][-1] == "flag_without_score"
    assert flag_errors([scored(math.nan, False)])[0][-1] == "invalid_score_or_threshold"


def test_readable_device_names_preserve_product_spelling():
    assert _friendly_name("HPPrinter_705a0fe49bc0_flows") == "HP Printer"
    assert _friendly_name("LiFXBulb_d073d5018308_flows") == "LIFX Bulb"
    assert _friendly_name("SamsungSmartThings_d052a800675e_flows") == "Samsung SmartThings"
