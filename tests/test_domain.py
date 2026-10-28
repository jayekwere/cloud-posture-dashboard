import json
from dataclasses import replace
from pathlib import Path

import pytest

from posture.analysis import compare, critical_free_streak, improvement, score, top_resources
from posture.models import Severity
from posture.parsing import MAX_REPORT_BYTES, ReportError, parse_report

SAMPLES = Path(__file__).resolve().parents[1] / "samples"


def sample(name="current"):
    return parse_report((SAMPLES / f"{name}.json").read_bytes())


def encode(data):
    return json.dumps(data).encode()


def test_generic_round_trip_and_score():
    report = sample()
    assert parse_report(encode(report.to_dict())) == report
    assert score(report) == 82
    assert score(replace(report, findings=())) == 100
    assert (
        score(
            replace(report, findings=(replace(report.findings[0], severity=Severity.CRITICAL),) * 6)
        )
        == 0
    )
    assert len(top_resources(report)) == 5
    assert top_resources(report)[0].penalty == 8


def test_auditor_bridge_mapping_and_generated_identity():
    raw = json.loads((SAMPLES / "auditor-bridge.json").read_text())
    report = parse_report(encode(raw))
    f = report.findings[0]
    assert f.severity == Severity.HIGH
    assert f.check_type == "IAM-WILDCARD"
    assert f.resource == raw["findings"][0]["principal_arn"]
    assert f.remediation.startswith("Replace")
    raw["findings"][0]["resource_arn"] = "demo:resource/new"
    raw["findings"][0]["remediation"] = "Explicit remediation"
    raw["findings"][0]["id"] = "stable-id"
    raw.pop("report_id")
    other = parse_report(encode(raw))
    assert other.findings[0].id == "stable-id"
    assert other.findings[0].remediation == "Explicit remediation"
    assert other.report_id.startswith("audit-")


def test_diff_identity_and_updated_evidence():
    before, after = sample("previous"), sample()
    delta = compare(before, after)
    assert (len(delta.new), len(delta.fixed), len(delta.still_open)) == (2, 2, 8)
    changed = replace(before.findings[0], severity=Severity.LOW, evidence={"changed": True})
    same_identity = compare(before, replace(before, findings=(changed, *before.findings[1:])))
    assert len(same_identity.still_open) == len(before.findings)
    assert same_identity.still_open[0].evidence == {"changed": True}
    different_account = replace(before.findings[0], account="another-demo")
    split = compare(before, replace(before, findings=(different_account, *before.findings[1:])))
    assert len(split.new) == len(split.fixed) == 1
    assert compare(after, after).new == ()
    assert len(compare(replace(before, findings=()), after).new) == len(after.findings)


def test_streak_and_encouragement():
    reports = [sample("current"), sample("baseline"), sample("previous")]
    assert critical_free_streak(reports) == 2
    assert critical_free_streak([]) == 0
    assert critical_free_streak([sample("baseline")]) == 0
    assert "11 points" in improvement(sample("previous"), sample())
    assert improvement(None, sample()) is None
    assert improvement(sample(), sample("baseline")) is None


@pytest.mark.parametrize(
    "blob, message",
    [
        (b"not JSON", "Invalid JSON"),
        (b"\xff", "UTF-8"),
        (b'{"a": 1, "a": 2}', "Duplicate JSON"),
        (b'{"a": NaN}', "Non-finite"),
        (b"[" * 1000 + b"]" * 1000, "nesting"),
        (b" " * (MAX_REPORT_BYTES + 1), "1 MiB"),
        (b'{"schema_version":"1.0","evidence":"\\ud800"}', "Unicode"),
        (b"[]", "JSON object"),
    ],
)
def test_bad_json_is_readable(blob, message):
    with pytest.raises(ReportError, match=message):
        parse_report(blob)


@pytest.mark.parametrize(
    "change, location",
    [
        ({"schema_version": "2.0"}, "schema_version"),
        ({"generated_at": "yesterday"}, "generated_at"),
        ({"generated_at": "2026-10-28T09:00:00"}, "generated_at"),
        ({"unexpected": "ignored?"}, "Additional properties"),
        ({"findings": [{"severity": "urgent"}]}, "findings"),
        ({"findings": [{}] * 2001}, "findings"),
    ],
)
def test_schema_errors_point_to_fields(change, location):
    raw = sample().to_dict()
    raw.update(change)
    with pytest.raises(ReportError, match=location):
        parse_report(encode(raw))


def test_duplicate_identity_and_bounded_nesting():
    raw = sample().to_dict()
    raw["findings"].append(raw["findings"][0])
    with pytest.raises(ReportError, match="Duplicate finding identity"):
        parse_report(encode(raw))
    raw = sample().to_dict()
    nested = {}
    for _ in range(25):
        nested = {"deeper": nested}
    raw["findings"][0]["evidence"] = nested
    with pytest.raises(ReportError, match="deeply nested"):
        parse_report(encode(raw))


def test_packaged_samples_match_public_samples():
    for name in ["baseline", "previous", "current"]:
        packaged = SAMPLES.parent / "posture" / "data" / f"{name}.json"
        assert packaged.read_bytes() == (SAMPLES / f"{name}.json").read_bytes()
