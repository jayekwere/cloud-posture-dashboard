from copy import deepcopy

import pytest

from scripts.check_image_scan import check_report


def report():
    # Synthetic scanner fixture tests the gate, not an actual image scan.
    return {
        "ArtifactType": "container_image",
        "Metadata": {"OS": {"Family": "alpine"}},
        "Results": [
            {"Class": "os-pkgs", "Packages": [{"Name": "synthetic-runtime"}]},
            {
                "Type": "python-pkg",
                "Packages": [{"Name": n} for n in ["Flask", "Flask-WTF", "gunicorn", "jsonschema"]],
            },
        ],
    }


def test_complete_scan_required():
    assert check_report(report()) == {}
    with pytest.raises(ValueError, match="identified"):
        check_report({})
    raw = report()
    raw["Results"] = []
    with pytest.raises(ValueError, match="inventory"):
        check_report(raw)
    raw = report()
    raw["Results"][1]["Packages"] = [{"Name": "unexpected"}]
    with pytest.raises(ValueError, match="dependencies"):
        check_report(raw)


def test_high_and_critical_always_block_including_unfixed():
    for severity in ["HIGH", "CRITICAL"]:
        for fixed in ["", "patched-version"]:
            raw = deepcopy(report())
            raw["Results"][0]["Vulnerabilities"] = [
                {
                    "VulnerabilityID": "SYNTHETIC-EXAMPLE",
                    "PkgName": "synthetic-runtime",
                    "Severity": severity,
                    "FixedVersion": fixed,
                }
            ]
            with pytest.raises(ValueError, match="no exceptions"):
                check_report(raw)
