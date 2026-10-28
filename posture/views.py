"""Server-rendered dashboard routes with one browser-scoped report workspace."""

from __future__ import annotations

import json
import re
import secrets
from typing import cast

from flask import (
    Blueprint,
    Response,
    abort,
    current_app,
    flash,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from flask.typing import ResponseReturnValue

from .analysis import (
    compare,
    critical_free_streak,
    improvement,
    score,
    severity_counts,
    top_resources,
)
from .exporting import csv_summary, markdown_summary
from .filtering import Filters
from .models import Severity, Snapshot
from .parsing import MAX_REPORT_BYTES, ReportError, parse_report
from .storage import SAMPLES, ReportStore, StorageFull

bp = Blueprint("dashboard", __name__)


def _workspace() -> tuple[ReportStore, str]:
    store = cast(ReportStore, current_app.extensions["report_store"])
    workspace = session.get("workspace")
    if not isinstance(workspace, str) or not re.fullmatch(r"[a-f0-9]{32}", workspace):
        workspace = secrets.token_hex(16)
        session["workspace"] = workspace
    store.ensure(workspace, seed=current_app.config["SEED_SAMPLES"])
    return store, workspace


def _context(key: str | None = None) -> dict[str, object]:
    store, workspace = _workspace()
    snapshots = store.list(workspace)
    explicit = key or request.args.get("report")
    selected = explicit or session.get("active")
    active = store.get(workspace, str(selected)) if selected else None
    if explicit and active is None:
        abort(404)
    if active is None:
        session.pop("active", None)
    active = active or (snapshots[0] if snapshots else None)
    return {"snapshots": snapshots, "active": active, "severities": list(Severity), "page": ""}


def _active(context: dict[str, object]) -> Snapshot:
    active = context["active"]
    if not isinstance(active, Snapshot):
        abort(404)
    return active


@bp.get("/healthz")
def health() -> Response:
    return Response('{"status":"ok"}\n', mimetype="application/json")


@bp.get("/")
def overview() -> str:
    context = _context()
    snapshots = cast(list[Snapshot], context["snapshots"])
    active = context["active"]
    if not isinstance(active, Snapshot):
        return render_template("overview.html", **context)
    previous = next(
        (s for s in snapshots if s.report.generated_at < active.report.generated_at), None
    )
    history = sorted(snapshots, key=lambda s: (s.report.generated_at, s.key))
    return render_template(
        "overview.html",
        **context,
        report=active.report,
        score=score(active.report),
        counts=severity_counts(active.report),
        resources=top_resources(active.report),
        streak=critical_free_streak([s.report for s in snapshots]),
        encouragement=improvement(previous.report if previous else None, active.report),
        previous_score=score(previous.report) if previous else None,
        history=history,
        score_for=score,
        page_title="Overview",
    )


@bp.get("/findings")
def findings() -> tuple[str, int] | str:
    context = _context()
    active = context["active"]
    if not isinstance(active, Snapshot):
        return render_template(
            "findings.html",
            **context,
            rows=[],
            filters=Filters(),
            accounts=[],
            checks=[],
            page_title="Findings",
        )
    try:
        filters = Filters.from_args(request.args)
        rows = filters.apply(active.report)
        page = int(request.args.get("p", "1"))
        if page < 1:
            raise ValueError
    except (ReportError, ValueError) as exc:
        return render_template(
            "error.html",
            title="Invalid filter",
            message=str(exc) or "Choose a positive page number.",
        ), 400
    total = len(rows)
    pages = max(1, (total + 49) // 50)
    if page > pages:
        abort(404)
    return render_template(
        "findings.html",
        **context,
        rows=rows[(page - 1) * 50 : page * 50],
        total=total,
        filters=filters,
        filter_args={"report": active.key, **filters.to_dict()},
        accounts=sorted({f.account for f in active.report.findings}),
        checks=sorted({f.check_type for f in active.report.findings}),
        page_number=page,
        pages=pages,
        page_title="Findings",
    )


@bp.get("/findings/<key>/<int:index>")
def detail(key: str, index: int) -> str:
    context = _context(key)
    active = _active(context)
    if index >= len(active.report.findings):
        abort(404)
    finding = active.report.findings[index]
    return render_template(
        "detail.html",
        **context,
        finding=finding,
        evidence=json.dumps(finding.evidence, indent=2, ensure_ascii=True),
        page_title="Finding detail",
    )


@bp.get("/trends")
def trends() -> tuple[str, int] | str:
    context = _context()
    snapshots = cast(list[Snapshot], context["snapshots"])
    if len(snapshots) < 2:
        return render_template("trends.html", **context, delta=None, page_title="Trends")
    store, workspace = _workspace()
    before = store.get(workspace, request.args.get("before", snapshots[1].key))
    after = store.get(workspace, request.args.get("after", snapshots[0].key))
    if before is None or after is None:
        abort(404)
    if before.key == after.key or before.report.generated_at >= after.report.generated_at:
        return render_template(
            "error.html",
            title="Choose two reports",
            message="The baseline must be earlier than the comparison report.",
        ), 400
    delta = compare(before.report, after.report)
    return render_template(
        "trends.html",
        **context,
        delta=delta,
        before=before,
        after=after,
        before_score=score(before.report),
        after_score=score(after.report),
        encouragement=improvement(before.report, after.report),
        page_title="Trends",
    )


@bp.route("/reports", methods=["GET", "POST"])
def reports() -> ResponseReturnValue:
    context = _context()
    if request.method == "GET":
        return render_template("reports.html", **context, page_title="Reports", error=None)
    try:
        upload = request.files.get("report")
        if upload is None or not upload.filename:
            raise ReportError("Choose a JSON report to upload.")
        name = upload.filename
        if len(name) > 120 or "/" in name or "\\" in name or not name.lower().endswith(".json"):
            raise ReportError("Use a simple filename ending in .json.")
        if upload.mimetype != "application/json":
            raise ReportError("Only application/json uploads are accepted.")
        report = parse_report(upload.stream.read(MAX_REPORT_BYTES + 1))
        store, workspace = _workspace()
        key, added = store.add(workspace, report)
        session["active"] = key
        flash(
            "Report imported. Your dashboard is ready."
            if added
            else "This report is already loaded; duplicates do not extend your streak.",
            "success",
        )
        return redirect(url_for("dashboard.overview"), code=303)
    except ReportError as exc:
        return render_template("reports.html", **context, page_title="Reports", error=str(exc)), 400


@bp.post("/reports/sample")
def load_sample() -> ResponseReturnValue:
    alias = request.form.get("sample", "")
    if alias not in SAMPLES:
        abort(400)
    store, workspace = _workspace()
    key, added = store.add(workspace, parse_report(SAMPLES[alias].read_bytes()))
    session["active"] = key
    flash("Sample loaded." if added else "Sample already loaded. Showing its snapshot.", "success")
    return redirect(url_for("dashboard.overview"), code=303)


@bp.post("/reports/reset")
def reset() -> ResponseReturnValue:
    store, workspace = _workspace()
    store.reset(workspace)
    session.clear()
    flash("Workspace reset. Only synthetic samples will be loaded next.", "success")
    return redirect(url_for("dashboard.overview"), code=303)


@bp.get("/export/<kind>")
def export(kind: str) -> Response | tuple[str, int]:
    if kind not in {"csv", "markdown"}:
        abort(404)
    context = _context()
    active = _active(context)
    try:
        filtered = [finding for _, finding in Filters.from_args(request.args).apply(active.report)]
    except ReportError as exc:
        return render_template("error.html", title="Invalid filter", message=str(exc)), 400
    body = csv_summary(filtered) if kind == "csv" else markdown_summary(active.report, filtered)
    response = Response(body, mimetype="text/csv" if kind == "csv" else "text/markdown")
    response.headers["Content-Disposition"] = (
        f'attachment; filename="posture-summary.{"csv" if kind == "csv" else "md"}"'
    )
    return response


@bp.app_errorhandler(StorageFull)
def full(error: StorageFull) -> tuple[str, int]:
    return render_template("error.html", title="Workspace limit reached", message=str(error)), 503
