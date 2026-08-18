import importlib.util
from pathlib import Path

import pytest


MODULE_PATH = Path(__file__).parents[1] / "src" / "risk_analysis.py"
SPEC = importlib.util.spec_from_file_location("risk_analysis", MODULE_PATH)
risk_analysis = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(risk_analysis)


@pytest.mark.parametrize(
    ("installed", "maximum", "expected"),
    [("1.2", "1.2.0", True), ("1.2.1", "1.2", False), ("10-0-1", "10.1", True)],
)
def test_version_comparison(installed, maximum, expected):
    assert risk_analysis.version_leq(installed, maximum) is expected


def test_invalid_version_is_rejected():
    with pytest.raises(ValueError):
        risk_analysis.version_leq("unknown", "1.0")


def test_offline_matching_is_case_insensitive():
    database = [
        {
            "software": "Example App",
            "max_vulnerable_version": "2.0",
            "cve": "CVE-2099-0001",
        }
    ]
    assert risk_analysis.match_offline("example app", "1.9", database) == database


def test_host_risk_uses_documented_weights():
    findings = [
        {"hostname": "lab-01", "severity": "Critical"},
        {"hostname": "lab-01", "severity": "Medium"},
    ]
    scores, counts = risk_analysis.compute_host_risk(findings)
    assert scores["lab-01"] == 14
    assert counts["lab-01"]["Critical"] == 1
