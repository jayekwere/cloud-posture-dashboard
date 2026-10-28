"""Safe plain-text exports; no rendering of finding-provided HTML or Markdown."""

import csv
import html
import io
import re

from .models import Finding, Report

COLUMNS = ("id", "severity", "check_type", "account", "resource", "title", "remediation")


def _csv_cell(value: str) -> str:
    # Spreadsheet applications may interpret formulas after whitespace/control prefixes.
    prefix = value.lstrip("".join(chr(i) for i in range(33)) + "\ufeff")
    if prefix.startswith(("=", "+", "-", "@")):
        return "'" + value
    return value


def csv_summary(findings: list[Finding]) -> str:
    output = io.StringIO(newline="")
    writer = csv.writer(output, quoting=csv.QUOTE_ALL)
    writer.writerow(COLUMNS)
    for finding in findings:
        writer.writerow([_csv_cell(str(getattr(finding, name))) for name in COLUMNS])
    return output.getvalue()


def _markdown(value: str) -> str:
    text = html.escape(value, quote=True).replace("\n", " ").replace("\r", " ")
    return re.sub(r"([\\`*_{}\[\]()#+.!|>~-])", r"\\\1", text)


def markdown_summary(report: Report, findings: list[Finding]) -> str:
    lines = [
        "# Posture findings",
        "",
        f"Report: {_markdown(report.report_id)}",
        f"Generated: {report.generated_at.isoformat()}",
        f"Matching findings: {len(findings)}",
        "",
        "| Severity | Check | Account | Resource | Finding | Remediation |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    for f in findings:
        lines.append(
            "| "
            + " | ".join(
                _markdown(str(v))
                for v in (f.severity, f.check_type, f.account, f.resource, f.title, f.remediation)
            )
            + " |"
        )
    return "\n".join(lines) + "\n"
