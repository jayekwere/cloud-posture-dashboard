"""Transparent triage scoring, deterministic ranking and identity-based snapshot diffs."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass

from .models import RANK, WEIGHTS, Finding, Report, Severity


def score(report: Report) -> int:
    return max(0, 100 - sum(WEIGHTS[f.severity] for f in report.findings))


def severity_counts(report: Report) -> dict[Severity, int]:
    counts = Counter(f.severity for f in report.findings)
    return {severity: counts[severity] for severity in Severity}


@dataclass(frozen=True)
class ResourceRisk:
    account: str
    resource: str
    penalty: int
    count: int
    severity: Severity


def top_resources(report: Report, limit: int = 5) -> list[ResourceRisk]:
    groups: dict[tuple[str, str], list[Finding]] = {}
    for f in report.findings:
        groups.setdefault((f.account, f.resource), []).append(f)
    values = [
        ResourceRisk(
            account,
            resource,
            sum(WEIGHTS[f.severity] for f in findings),
            len(findings),
            min((f.severity for f in findings), key=RANK.__getitem__),
        )
        for (account, resource), findings in groups.items()
    ]
    return sorted(values, key=lambda r: (-r.penalty, RANK[r.severity], r.account, r.resource))[
        :limit
    ]


@dataclass(frozen=True)
class ReportDiff:
    new: tuple[Finding, ...]
    fixed: tuple[Finding, ...]
    still_open: tuple[Finding, ...]


def compare(before: Report, after: Report) -> ReportDiff:
    old = {f.identity: f for f in before.findings}
    new = {f.identity: f for f in after.findings}
    return ReportDiff(
        tuple(new[k] for k in sorted(new.keys() - old.keys())),
        tuple(old[k] for k in sorted(old.keys() - new.keys())),
        tuple(new[k] for k in sorted(new.keys() & old.keys())),
    )


def critical_free_streak(reports: list[Report]) -> int:
    streak = 0
    for report in sorted(reports, key=lambda r: (r.generated_at, r.report_id), reverse=True):
        if any(f.severity == Severity.CRITICAL for f in report.findings):
            break
        streak += 1
    return streak


def improvement(before: Report | None, after: Report) -> str | None:
    if before is not None and (gain := score(after) - score(before)) > 0:
        return f"Nice progress! Your score improved by {gain} points. Keep the momentum going."
    return None
