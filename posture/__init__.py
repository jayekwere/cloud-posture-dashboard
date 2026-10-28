"""Flask application factory with ephemeral sessions and explicit response hardening."""

from __future__ import annotations

import atexit
import os
import secrets
from typing import Any

from flask import Flask, Response, render_template, request
from flask_wtf.csrf import CSRFError, CSRFProtect
from werkzeug.exceptions import HTTPException, SecurityError

from .storage import ReportStore


def create_app(config: dict[str, Any] | None = None) -> Flask:
    app = Flask(__name__)
    app.config.from_mapping(
        SECRET_KEY=secrets.token_hex(32),
        MAX_CONTENT_LENGTH=1_100_000,
        MAX_FORM_MEMORY_SIZE=131_072,
        MAX_FORM_PARTS=8,
        SESSION_COOKIE_NAME="posture_session",
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Strict",
        SESSION_COOKIE_SECURE=os.environ.get("POSTURE_HTTPS") == "1",
        TRUSTED_HOSTS=os.environ.get("POSTURE_TRUSTED_HOSTS", "localhost,127.0.0.1,[::1]").split(
            ","
        ),
        SEED_SAMPLES=True,
    )
    if config:
        app.config.update(config)
    store = ReportStore()
    app.extensions["report_store"] = store
    atexit.register(store.close)
    csrf = CSRFProtect()
    csrf.init_app(app)

    from .views import bp

    app.register_blueprint(bp)

    @app.after_request
    def harden(response: Response) -> Response:
        response.headers.update(
            {
                "Content-Security-Policy": "default-src 'none'; script-src 'self'; "
                "style-src 'self'; "
                "img-src 'self'; font-src 'self'; connect-src 'self'; form-action 'self'; "
                "base-uri 'none'; frame-ancestors 'none'; object-src 'none'",
                "X-Content-Type-Options": "nosniff",
                "X-Frame-Options": "DENY",
                "Referrer-Policy": "no-referrer",
                "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
                "Cross-Origin-Opener-Policy": "same-origin",
                "Cache-Control": "no-store",
            }
        )
        if request.is_secure:
            response.headers["Strict-Transport-Security"] = "max-age=31536000"
        return response

    @app.errorhandler(CSRFError)
    def csrf_error(error: CSRFError) -> tuple[str, int]:
        return render_template(
            "error.html",
            title="Form expired",
            message="Reload the page and submit the form again. A valid CSRF token is required.",
        ), 400

    @app.errorhandler(HTTPException)
    def http_error(error: HTTPException) -> tuple[str, int] | Response:
        if isinstance(error, SecurityError):
            return Response("Untrusted request host.\n", status=400, mimetype="text/plain")
        message = "The requested page or report could not be found."
        if error.code == 413:
            message = "Upload too large. Choose a JSON file up to 1 MiB."
        elif error.code == 400:
            message = "The request could not be accepted. Check the form and try again."
        return render_template("error.html", title=error.name, message=message), error.code or 500

    @app.errorhandler(500)
    def server_error(error: Exception) -> tuple[str, int]:
        return render_template(
            "error.html",
            title="Something went wrong",
            message="The report could not be processed. "
            "Restart the local app if the problem continues.",
        ), 500

    return app
