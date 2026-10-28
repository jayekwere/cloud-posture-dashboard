import io
import json
import re

import pytest

from posture import create_app


@pytest.fixture
def app():
    application = create_app({"TESTING": True})
    yield application
    application.extensions["report_store"].close()


@pytest.fixture
def client(app):
    return app.test_client()


def csrf(client):
    page = client.get("/reports")
    match = re.search(rb'name="csrf_token" value="([^"]+)"', page.data)
    assert match is not None
    return match[1].decode()


def upload(client, data, name="report.json", mimetype="application/json", follow=False):
    blob = json.dumps(data).encode() if isinstance(data, dict) else data
    return client.post(
        "/reports",
        data={"csrf_token": csrf(client), "report": (io.BytesIO(blob), name, mimetype)},
        follow_redirects=follow,
    )
