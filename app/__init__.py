import os
from pathlib import Path

from flask import Flask, jsonify

from . import db
from .api import api_bp
from .auth import auth_bp


def create_app(test_config=None):
    app = Flask(__name__, instance_relative_config=True)
    default_database = Path(app.instance_path) / "secure_api.sqlite"
    app.config.from_mapping(
        DATABASE_PATH=os.getenv("DATABASE_PATH", str(default_database)),
        JWT_SECRET=os.getenv("JWT_SECRET"),
        JWT_TTL_MINUTES=int(os.getenv("JWT_TTL_MINUTES", "30")),
        JWT_ISSUER="secure-api-lab",
        JWT_AUDIENCE="secure-api-client",
        MAX_CONTENT_LENGTH=16 * 1024,
    )

    if test_config:
        app.config.update(test_config)

    if not app.config.get("TESTING") and not app.config.get("JWT_SECRET"):
        raise RuntimeError("JWT_SECRET environment variable is required")

    Path(app.config["DATABASE_PATH"]).parent.mkdir(parents=True, exist_ok=True)
    db.init_app(app)
    app.register_blueprint(auth_bp)
    app.register_blueprint(api_bp)

    @app.get("/health")
    def health():
        return jsonify(status="ok")

    @app.after_request
    def add_security_headers(response):
        response.headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Cache-Control"] = "no-store"
        return response

    @app.errorhandler(404)
    def not_found(_error):
        return jsonify(error="Resource not found"), 404

    @app.errorhandler(405)
    def method_not_allowed(_error):
        return jsonify(error="Method not allowed"), 405

    return app
