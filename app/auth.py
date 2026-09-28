from datetime import datetime, timedelta, timezone
from functools import wraps
from uuid import uuid4

import jwt
from flask import Blueprint, current_app, g, jsonify, request

from .db import get_db, verify_password


auth_bp = Blueprint("auth", __name__, url_prefix="/auth")


def issue_token(user_id):
    now = datetime.now(timezone.utc)
    payload = {
        "sub": str(user_id),
        "iat": now,
        "exp": now + timedelta(minutes=current_app.config["JWT_TTL_MINUTES"]),
        "iss": current_app.config["JWT_ISSUER"],
        "aud": current_app.config["JWT_AUDIENCE"],
        "jti": str(uuid4()),
    }
    return jwt.encode(payload, current_app.config["JWT_SECRET"], algorithm="HS256")


def token_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        header = request.headers.get("Authorization", "")
        if not header.startswith("Bearer "):
            return jsonify(error="Authentication required"), 401

        token = header.removeprefix("Bearer ").strip()
        try:
            payload = jwt.decode(
                token,
                current_app.config["JWT_SECRET"],
                algorithms=["HS256"],
                issuer=current_app.config["JWT_ISSUER"],
                audience=current_app.config["JWT_AUDIENCE"],
                options={"require": ["exp", "iat", "iss", "aud", "sub", "jti"]},
            )
            user_id = int(payload["sub"])
        except (jwt.PyJWTError, ValueError, TypeError):
            return jsonify(error="Invalid or expired token"), 401

        user = get_db().execute(
            "SELECT id, username FROM users WHERE id = ?", (user_id,)
        ).fetchone()
        if user is None:
            return jsonify(error="Invalid or expired token"), 401

        g.current_user = user
        return view(*args, **kwargs)

    return wrapped


@auth_bp.post("/login")
def login():
    if not request.is_json:
        return jsonify(error="JSON body required"), 415

    body = request.get_json(silent=True) or {}
    username = body.get("username")
    password = body.get("password")
    if not isinstance(username, str) or not isinstance(password, str):
        return jsonify(error="Username and password are required"), 400
    if len(username) > 50 or len(password) > 256:
        return jsonify(error="Invalid credentials"), 401

    user = get_db().execute(
        "SELECT id, username, password_hash FROM users WHERE username = ?", (username,)
    ).fetchone()
    if user is None or not verify_password(password, user["password_hash"]):
        return jsonify(error="Invalid credentials"), 401

    return jsonify(
        {
            "access_token": issue_token(user["id"]),
            "expires_in": current_app.config["JWT_TTL_MINUTES"] * 60,
        }
    )
