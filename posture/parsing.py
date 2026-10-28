"""Bounded UTF-8 JSON parsing and explicit input adapters; no remote resolution."""

from __future__ import annotations

import hashlib
import json
import math
from collections.abc import Iterable
from datetime import datetime
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker

from .models import Finding, Report, Severity

MAX_REPORT_BYTES = 1_048_576
SCHEMA_DIR = Path(__file__).parent / "schemas"


class ReportError(ValueError):
    """A safe, readable validation error suitable for displaying to the uploader."""


def _unique_object(pairs: Iterable[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ReportError("Duplicate JSON object keys are not allowed.")
        result[key] = value
    return result


def _bad_constant(value: str) -> None:
    raise ReportError(f"Non-finite number {value} is not valid JSON.")


def _bound_structure(value: Any) -> None:
    stack = [(value, 0)]
    count = 0
    while stack:
        node, depth = stack.pop()
        count += 1
        if depth > 20 or count > 40_000:
            raise ReportError("Report is too deeply nested or contains too many JSON values.")
        if isinstance(node, float) and not math.isfinite(node):
            raise ReportError("JSON number exceeds the finite numeric range.")
        if isinstance(node, str):
            try:
                node.encode("utf-8")
            except UnicodeEncodeError as exc:
                raise ReportError("JSON strings must contain valid Unicode characters.") from exc
        if isinstance(node, dict):
            stack.extend((v, depth + 1) for v in node.values())
        elif isinstance(node, list):
            stack.extend((v, depth + 1) for v in node)


def _validate(value: Any, schema_name: str) -> dict[str, Any]:
    schema = json.loads((SCHEMA_DIR / schema_name).read_text())
    errors = list(Draft202012Validator(schema, format_checker=FormatChecker()).iter_errors(value))
    if errors:
        messages = []
        for error in sorted(errors, key=lambda e: str(list(e.absolute_path)))[:5]:
            location = "$" + "".join(
                f"[{p}]" if isinstance(p, int) else f".{p}" for p in error.absolute_path
            )
            # Validation messages may echo small field values; templates always escape them.
            messages.append(f"{location}: {error.message[:300]}")
        raise ReportError("\n".join(messages))
    if not isinstance(value, dict):  # Defensive boundary; the schema also requires an object.
        raise ReportError("The report must be a JSON object.")
    return value


def _adapt_auditor(value: Any) -> dict[str, Any]:
    """Explicit bridge contract; no upstream implementation is required."""
    raw = _validate(value, "auditor.schema.json")
    findings = []
    for item in raw["findings"]:
        resource = item.get("resource_arn") or item["principal_arn"]
        identity = f"{item['account_id']}\0{resource}\0{item['check_id']}"
        findings.append(
            {
                "id": item.get("id") or hashlib.sha256(identity.encode()).hexdigest()[:20],
                "severity": item["severity"].lower(),
                "check_type": item["check_id"],
                "account": item["account_id"],
                "resource": resource,
                "title": item.get("title", item["check_id"]),
                "description": item.get("description", ""),
                "evidence": item.get("evidence", {}),
                "remediation": item.get("remediation", item.get("recommendation", "")),
            }
        )
    return {
        "schema_version": "1.0",
        "report_id": raw.get("report_id", "audit-" + raw["generated_at"]),
        "generated_at": raw["generated_at"],
        "source": "iam-least-privilege-auditor",
        "findings": findings,
    }


def parse_report(blob: bytes) -> Report:
    if len(blob) > MAX_REPORT_BYTES:
        raise ReportError("Report exceeds the 1 MiB JSON limit.")
    try:
        value = json.loads(
            blob.decode("utf-8-sig"),
            object_pairs_hook=_unique_object,
            parse_constant=_bad_constant,
        )
    except UnicodeDecodeError as exc:
        raise ReportError("Use a UTF-8 encoded JSON file.") from exc
    except json.JSONDecodeError as exc:
        raise ReportError(f"Invalid JSON at line {exc.lineno}, column {exc.colno}.") from exc
    except (RecursionError, ValueError) as exc:
        if isinstance(exc, ReportError):
            raise
        raise ReportError("JSON numbers or nesting exceed the parser's limits.") from exc
    _bound_structure(value)
    if isinstance(value, dict) and "schema_version" not in value:
        value = _adapt_auditor(value)
    data = _validate(value, "findings.schema.json")
    findings = tuple(
        Finding(
            id=f["id"],
            severity=Severity(f["severity"]),
            check_type=f["check_type"],
            account=f["account"],
            resource=f["resource"],
            title=f["title"],
            description=f.get("description", ""),
            evidence=f.get("evidence", {}),
            remediation=f.get("remediation", ""),
        )
        for f in data["findings"]
    )
    if len({finding.identity for finding in findings}) != len(findings):
        raise ReportError(
            "Duplicate finding identity: id, account, resource and check_type "
            "must be unique together."
        )
    generated = datetime.fromisoformat(data["generated_at"].upper().replace("Z", "+00:00"))
    if generated.utcoffset() is None:
        raise ReportError("$.generated_at must include a timezone.")
    return Report(data["report_id"], generated, data.get("source", "generic"), findings)
