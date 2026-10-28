"""One query contract for the table and both export formats."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

from .models import RANK, Finding, Report, Severity
from .parsing import ReportError

SORTS = {"risk", "severity", "title", "resource", "account", "check_type"}


@dataclass(frozen=True)
class Filters:
    severity: str = ""
    check_type: str = ""
    account: str = ""
    q: str = ""
    sort: str = "risk"
    order: str = "asc"

    @classmethod
    def from_args(cls, args: Mapping[str, str]) -> Filters:
        values = {key: args.get(key, "") for key in ("severity", "check_type", "account", "q")}
        if values["severity"] and values["severity"] not in [s.value for s in Severity]:
            raise ReportError("Choose a known severity.")
        if any(len(value) > 200 for value in values.values()):
            raise ReportError("Filter and search values must be 200 characters or fewer.")
        sort = args.get("sort", "risk")
        order = args.get("order", "asc")
        if sort not in SORTS or order not in {"asc", "desc"}:
            raise ReportError("Choose a known sort field and asc/desc order.")
        return cls(**values, sort=sort, order=order)

    def to_dict(self) -> dict[str, str]:
        return {
            "severity": self.severity,
            "check_type": self.check_type,
            "account": self.account,
            "q": self.q,
            "sort": self.sort,
            "order": self.order,
        }

    def apply(self, report: Report) -> list[tuple[int, Finding]]:
        selected = []
        for index, finding in enumerate(report.findings):
            searchable = " ".join(
                [
                    finding.id,
                    finding.title,
                    finding.resource,
                    finding.account,
                    finding.check_type,
                    finding.description,
                    finding.remediation,
                ]
            )
            if self.severity and finding.severity != self.severity:
                continue
            if self.check_type and finding.check_type != self.check_type:
                continue
            if self.account and finding.account != self.account:
                continue
            if self.q and self.q.casefold() not in searchable.casefold():
                continue
            selected.append((index, finding))

        def key(item: tuple[int, Finding]) -> tuple[int | str, str, str, int]:
            index, finding = item
            primary: int | str = (
                RANK[finding.severity]
                if self.sort in {"risk", "severity"}
                else str(getattr(finding, self.sort)).casefold()
            )
            return primary, finding.resource, finding.id, index

        return sorted(selected, key=key, reverse=self.order == "desc")
