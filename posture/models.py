"""Typed, normalized report objects shared by parsing, scoring and presentation."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime
from enum import StrEnum
from typing import Any


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


WEIGHTS: dict[Severity, int] = {
    Severity.CRITICAL: 20,
    Severity.HIGH: 8,
    Severity.MEDIUM: 3,
    Severity.LOW: 1,
    Severity.INFO: 0,
}
RANK = {severity: index for index, severity in enumerate(Severity)}


@dataclass(frozen=True)
class Finding:
    id: str
    severity: Severity
    check_type: str
    account: str
    resource: str
    title: str
    description: str
    evidence: Any
    remediation: str

    @property
    def identity(self) -> tuple[str, str, str, str]:
        return self.account, self.resource, self.check_type, self.id

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class Report:
    report_id: str
    generated_at: datetime
    source: str
    findings: tuple[Finding, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "1.0",
            "report_id": self.report_id,
            "generated_at": self.generated_at.isoformat(),
            "source": self.source,
            "findings": [finding.to_dict() for finding in self.findings],
        }


@dataclass(frozen=True)
class Snapshot:
    key: str
    report: Report
