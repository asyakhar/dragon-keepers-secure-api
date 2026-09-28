from html import escape

from flask import Blueprint, g, jsonify, request

from .auth import token_required
from .db import get_db


api_bp = Blueprint("api", __name__, url_prefix="/api")


def safe_text(value):
    return escape(value, quote=True)


@api_bp.get("/data")
@token_required
def get_data():
    return jsonify(
        user=safe_text(g.current_user["username"]),
        data=[
            {"id": 1, "message": "Protected information"},
            {"id": 2, "message": "Only authenticated users can see this"},
        ],
    )

@api_bp.post("/notes")
@token_required
def create_note():
    if not request.is_json:
        return jsonify(error="JSON body required"), 415

    body = request.get_json(silent=True) or {}
    title = body.get("title")
    content = body.get("content")
    if not isinstance(title, str) or not isinstance(content, str):
        return jsonify(error="Title and content are required"), 400
    title = title.strip()
    content = content.strip()
    if not title or not content or len(title) > 100 or len(content) > 2000:
        return jsonify(error="Title/content length is invalid"), 400

    database = get_db()
    cursor = database.execute(
        "INSERT INTO notes (user_id, title, content) VALUES (?, ?, ?)",
        (g.current_user["id"], title, content),
    )
    database.commit()

    return (
        jsonify(
            id=cursor.lastrowid,
            title=safe_text(title),
            content=safe_text(content),
        ),
        201,
    )


@api_bp.get("/notes")
@token_required
def list_notes():
    notes = get_db().execute(
        "SELECT id, title, content, created_at FROM notes WHERE user_id = ? ORDER BY id",
        (g.current_user["id"],),
    ).fetchall()
    return jsonify(
        notes=[
            {
                "id": row["id"],
                "title": safe_text(row["title"]),
                "content": safe_text(row["content"]),
                "created_at": row["created_at"],
            }
            for row in notes
        ]
    )
