import csv
import io

import pytest

from .conftest import csrf, upload
from .test_domain import sample


@pytest.mark.parametrize(
    "url",
    [
        "/",
        "/findings",
        "/trends",
        "/reports",
        "/healthz",
        "/static/app.css",
        "/static/app.js",
        "/static/favicon.svg",
    ],
)
def test_pages_and_security_headers(client, url):
    r = client.get(url)
    assert r.status_code == 200
    csp = r.headers["Content-Security-Policy"]
    assert "default-src 'none'" in csp
    assert "script-src 'self'" in csp and "style-src 'self'" in csp
    assert "unsafe-inline" not in csp and "unsafe-eval" not in csp
    assert r.headers["X-Content-Type-Options"] == "nosniff"
    assert r.headers["X-Frame-Options"] == "DENY"
    assert r.headers["Referrer-Policy"] == "no-referrer"
    assert r.headers["Cache-Control"] == "no-store"


def test_sample_overview_and_filters(client):
    page = client.get("/")
    assert b"82" in page.data and b"Critical-free streak" in page.data
    assert b"11 points" in page.data
    assert b"max(0, 100" in page.data
    filtered = client.get(
        "/findings?severity=high&account=demo-east&check_type=wildcard-actions&q=wildcard&sort=title&order=desc"
    )
    assert filtered.status_code == 200 and b"1 matching finding" in filtered.data
    assert b"demo-001" not in filtered.data  # ID appears on detail, not the list.
    assert b"Role allows wildcard read actions" in filtered.data
    assert client.get("/findings?q=no-such-finding").status_code == 200
    assert b"No findings match" in client.get("/findings?q=no-such-finding").data


@pytest.mark.parametrize(
    "query",
    ["severity=urgent", "sort=arbitrary", "order=sideways", "p=0", "p=oops", "q=" + "x" * 201],
)
def test_invalid_filters(client, query):
    assert client.get("/findings?" + query).status_code == 400


def test_csrf_required_for_every_mutation(client):
    for path in ["/reports", "/reports/sample", "/reports/reset"]:
        r = client.post(path, data={"sample": "current", "csrf_token": "forged"})
        assert r.status_code == 400 and b"valid CSRF token" in r.data
    assert client.post("/reports/reset").status_code == 400


def test_upload_detail_and_dedup(client, app):
    raw = sample().to_dict()
    raw["report_id"] = "new-synthetic-report"
    result = upload(client, raw, follow=True)
    assert result.status_code == 200 and b"Report imported" in result.data
    with client.session_transaction() as session:
        key, workspace = session["active"], session["workspace"]
    assert client.get(f"/findings/{key}/0").status_code == 200
    detail = client.get(f"/findings/{key}/0").data
    assert b"Evidence" in detail and b"Suggested remediation" in detail
    assert b"demonstration value" in detail
    assert client.get(f"/findings/{key}/999").status_code == 404
    assert client.get("/findings?p=9000").status_code == 404
    again = upload(client, raw, follow=True)
    assert b"duplicates do not extend" in again.data
    store = app.extensions["report_store"]
    assert len(store.list(workspace)) == 4
    paths = list((store.root / workspace).iterdir())
    assert all(p.parent.parent == store.root and p.name.endswith(".json") for p in paths)
    assert all(p.stat().st_mode & 0o777 == 0o600 for p in paths)
    assert store.root.stat().st_mode & 0o777 == 0o700


def test_browser_isolation_and_expiry_recovery(client, app):
    raw = sample().to_dict()
    raw["report_id"] = "only-in-browser-one"
    upload(client, raw)
    with client.session_transaction() as session:
        key, workspace = session["active"], session["workspace"]
    other = app.test_client()
    assert other.get(f"/?report={key}").status_code == 404
    assert other.get(f"/findings/{key}/0").status_code == 404
    assert other.get(f"/export/csv?report={key}").status_code == 404
    app.extensions["report_store"].reset(workspace)
    assert client.get("/").status_code == 200  # Stored active pointer expires gracefully.
    assert client.get("/?report=bad-key").status_code == 404


def test_upload_xss_is_escaped_everywhere(client):
    raw = sample().to_dict()
    raw["report_id"] = "escaped-example"
    dangerous = '<script>alert("demo")</script><img src=x onerror=alert(1)>'
    raw["findings"][0].update(
        title=dangerous, description=dangerous, remediation=dangerous, evidence={"text": dangerous}
    )
    assert upload(client, raw).status_code == 303
    with client.session_transaction() as session:
        key = session["active"]
    for url in ["/findings", f"/findings/{key}/0"]:
        page = client.get(url)
        assert b"<script>alert" not in page.data and b"<img src=x" not in page.data
        assert b"&lt;script&gt;" in page.data
    raw["findings"][0]["severity"] = dangerous
    error = upload(client, raw)
    assert error.status_code == 400 and b"<img src=x" not in error.data


@pytest.mark.parametrize(
    "blob, filename, content_type, text",
    [
        (b"broken", "data.json", "application/json", b"Invalid JSON"),
        (b"{}", "data.txt", "application/json", b"ending in .json"),
        (b"{}", "../../escape.json", "application/json", b"simple filename"),
        (b"{}", "data.json", "text/html", b"application/json"),
        (b"{}", "data.json", "application/json", b"required property"),
    ],
)
def test_bad_upload_errors(client, blob, filename, content_type, text):
    result = upload(client, blob, filename, content_type)
    assert result.status_code == 400 and text in result.data


def test_missing_file_size_limits_and_path_loads(client):
    r = client.post("/reports", data={"csrf_token": csrf(client)})
    assert r.status_code == 400 and b"Choose a JSON report" in r.data
    large = upload(client, b" " * 1_050_000)
    assert large.status_code == 400 and b"1 MiB" in large.data
    huge = upload(client, b" " * 1_200_000)
    assert huge.status_code == 413 and b"Upload too large" in huge.data
    bad = client.post(
        "/reports/sample", data={"csrf_token": csrf(client), "sample": "../../etc/passwd"}
    )
    assert bad.status_code == 400


def test_samples_reset_trends_and_bad_comparison(client):
    r = client.post(
        "/reports/sample",
        data={"csrf_token": csrf(client), "sample": "previous"},
        follow_redirects=True,
    )
    assert r.status_code == 200 and b"Sample already loaded" in r.data
    assert b"71" in r.data
    page = client.get("/trends")
    assert page.status_code == 200 and b"2</h2>" in page.data
    with client.session_transaction() as session:
        workspace = session["workspace"]
    # Use only report keys visible in the rendered comparison form.
    import re

    keys = re.findall(rb'<option value="([a-f0-9]{64})"', page.data)
    same = keys[0].decode()
    assert client.get(f"/trends?before={same}&after={same}").status_code == 400
    assert client.get("/trends?before=unknown").status_code == 404
    r = client.post("/reports/reset", data={"csrf_token": csrf(client)}, follow_redirects=True)
    assert r.status_code == 200 and b"Workspace reset" in r.data
    with client.session_transaction() as session:
        assert session["workspace"] != workspace


def test_exports_share_filters_and_prevent_injection(client):
    raw = sample().to_dict()
    raw["report_id"] = "export-example"
    raw["findings"][0].update(
        title="=SUM(1,2)", remediation="<img src=x> [click](https://invalid.test) | `code`"
    )
    assert upload(client, raw).status_code == 303
    csv_result = client.get("/export/csv?severity=high")
    assert csv_result.status_code == 200
    assert csv_result.mimetype == "text/csv"
    assert "attachment;" in csv_result.headers["Content-Disposition"]
    rows = list(csv.DictReader(io.StringIO(csv_result.text)))
    assert len(rows) == 1 and rows[0]["title"] == "'=SUM(1,2)"
    markdown = client.get("/export/markdown?severity=high")
    assert markdown.status_code == 200 and b"Matching findings: 1" in markdown.data
    assert b"<img" not in markdown.data and b"\\[click\\]" in markdown.data
    assert client.get("/export/executable").status_code == 404
    assert client.get("/export/csv?sort=unknown").status_code == 400


def test_host_cookie_tls_and_error_headers(client):
    response = client.get("/")
    cookie = response.headers["Set-Cookie"]
    assert "HttpOnly" in cookie and "SameSite=Strict" in cookie
    assert "Strict-Transport-Security" not in response.headers
    assert (
        client.get("/healthz", base_url="https://localhost").headers["Strict-Transport-Security"]
        == "max-age=31536000"
    )
    assert client.get("/", base_url="http://untrusted.invalid").status_code == 400
    missing = client.get("/not-here")
    assert missing.status_code == 404 and "Content-Security-Policy" in missing.headers


def test_empty_workspace():
    from posture import create_app

    app = create_app({"TESTING": True, "SEED_SAMPLES": False})
    with app.test_client() as c:
        assert b"Your next step starts" in c.get("/").data
        assert b"No reports loaded" in c.get("/findings").data
        assert b"Two snapshots make" in c.get("/trends").data
        assert c.get("/export/csv").status_code == 404
    app.extensions["report_store"].close()
