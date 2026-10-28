"""Exercise the built image with a read-only filesystem and no Linux capabilities."""

from __future__ import annotations

import argparse
import csv
import http.cookiejar
import io
import json
import re
import subprocess
import time
import urllib.error
import urllib.request
import uuid
from datetime import UTC, datetime
from pathlib import Path


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", default="cloud-posture-dashboard:local")
    parser.add_argument("--output", default="artifacts/container.json")
    args = parser.parse_args()
    name = "posture-smoke-" + uuid.uuid4().hex[:12]
    container = subprocess.check_output(
        [
            "docker",
            "run",
            "--detach",
            "--rm",
            "--name",
            name,
            "--publish",
            "127.0.0.1::8000",
            "--read-only",
            "--tmpfs",
            "/tmp:rw,noexec,nosuid,size=64m",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges:true",
            "--pids-limit",
            "64",
            "--memory",
            "256m",
            args.image,
        ],
        text=True,
    ).strip()
    checks = {}
    try:
        info = json.loads(subprocess.check_output(["docker", "inspect", container], text=True))[0]
        binding = info["NetworkSettings"]["Ports"]["8000/tcp"][0]
        assert binding["HostIp"] == "127.0.0.1"
        base = "http://127.0.0.1:" + binding["HostPort"]
        opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar())
        )
        for attempt in range(40):
            try:
                response = opener.open(base + "/healthz", timeout=2)
                assert response.status == 200
                break
            except (OSError, urllib.error.URLError):
                if attempt == 39:
                    raise
                time.sleep(0.25)
        checks["health"] = True
        assert info["Config"]["User"] == "10001:10001"
        assert info["HostConfig"]["ReadonlyRootfs"] is True
        assert "ALL" in info["HostConfig"]["CapDrop"]
        checks["non_root_readonly_caps_dropped"] = True
        probe = (
            "import os,pathlib; assert os.geteuid()==10001; "
            "p=pathlib.Path('/tmp/write-probe'); p.write_text('synthetic'); p.unlink()"
        )
        subprocess.run(["docker", "exec", container, "python", "-c", probe], check=True)
        checks["temporary_storage_works"] = True
        response = opener.open(base + "/")
        assert "default-src 'none'" in response.headers["Content-Security-Policy"]
        assert response.headers["X-Content-Type-Options"] == "nosniff"
        assert b"Critical-free streak" in response.read()
        checks["populated_dashboard_and_headers"] = True
        page = opener.open(base + "/reports").read()
        token = re.search(rb'name="csrf_token" value="([^"]+)"', page)
        assert token is not None
        raw = json.loads(Path("samples/current.json").read_text())
        raw["report_id"] = "synthetic-container-probe"
        boundary = "posture-" + uuid.uuid4().hex
        body = (
            f'--{boundary}\r\nContent-Disposition: form-data; name="csrf_token"\r\n\r\n'
            f"{token[1].decode()}\r\n--{boundary}\r\n"
            'Content-Disposition: form-data; name="report"; filename="probe.json"\r\n'
            "Content-Type: application/json\r\n\r\n" + json.dumps(raw) + f"\r\n--{boundary}--\r\n"
        ).encode()
        request = urllib.request.Request(
            base + "/reports",
            data=body,
            headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
        )
        assert opener.open(request).status == 200
        checks["csrf_protected_upload"] = True
        exported = opener.open(base + "/export/csv?severity=high").read().decode()
        assert len(list(csv.DictReader(io.StringIO(exported)))) == 1
        checks["filtered_csv"] = True
        try:
            opener.open(urllib.request.Request(base + "/reports/reset", data=b""))
            raise AssertionError("missing CSRF token accepted")
        except urllib.error.HTTPError as error:
            assert error.code == 400
        checks["missing_csrf_rejected"] = True
        record = {
            "recorded_at_utc": datetime.now(UTC).isoformat(),
            "image_id": info["Image"],
            "platform": info["Platform"],
            "user": info["Config"]["User"],
            "checks": checks,
        }
        output = Path(args.output)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(record, indent=2) + "\n")
        print("PASS:", len(checks), "container checks; non-root, read-only and loopback only")
    finally:
        subprocess.run(["docker", "stop", container], check=True, stdout=subprocess.DEVNULL)


if __name__ == "__main__":
    main()
