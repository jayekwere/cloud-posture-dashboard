"""Require OS and runtime-package coverage, then block every high/critical finding."""

from __future__ import annotations

import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any


def check_report(report: dict[str, Any]) -> dict[str, int]:
    if report.get("ArtifactType") != "container_image" or not report.get("Metadata", {}).get("OS"):
        raise ValueError("Expected an identified container image and operating system.")
    results = report.get("Results", [])
    os_packages = [r for r in results if r.get("Class") == "os-pkgs" and r.get("Packages")]
    python_packages = [r for r in results if r.get("Type") == "python-pkg" and r.get("Packages")]
    if not os_packages or not python_packages:
        raise ValueError("The scan must inventory both OS and Python packages.")
    names = {p["Name"].lower().replace("_", "-") for r in python_packages for p in r["Packages"]}
    if not {"flask", "flask-wtf", "gunicorn", "jsonschema"}.issubset(names):
        raise ValueError("The scan did not identify the expected application dependencies.")
    findings = [v for result in results for v in result.get("Vulnerabilities", [])]
    counts = dict(Counter(v["Severity"] for v in findings))
    print("All detected vulnerabilities by severity:", counts)
    blocking = [v for v in findings if v["Severity"] in {"HIGH", "CRITICAL"}]
    for v in blocking:
        print(v["VulnerabilityID"], v["PkgName"], v["Severity"], v.get("FixedVersion", "unfixed"))
    if blocking:
        raise ValueError(
            f"Image contains {len(blocking)} high/critical findings; no exceptions allowed."
        )
    print("PASS: OS and Python inventories present; zero high/critical findings")
    return counts


if __name__ == "__main__":
    try:
        check_report(json.loads(Path(sys.argv[1]).read_text()))
    except (ValueError, KeyError, TypeError) as error:
        raise SystemExit(str(error)) from error
