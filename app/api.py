import sqlite3
from html import escape

from flask import Blueprint, g, jsonify, request

from .auth import token_required
from .db import get_db


api_bp = Blueprint("api", __name__, url_prefix="/api")

ALLOWED_ELEMENTS = {"fire", "ice", "storm", "earth", "shadow", "light"}


def safe_text(value):
    return escape(value, quote=True)


def serialize_dragon(row):
    return {
        "id": row["id"],
        "name": safe_text(row["name"]),
        "species": safe_text(row["species"]),
        "element": row["element"],
        "age": row["age"],
        "description": safe_text(row["description"]),
        "created_at": row["created_at"],
    }


@api_bp.get("/data")
@token_required
def get_dragon_collection():
    dragons = get_db().execute(
        """
        SELECT id, name, species, element, age, description, created_at
        FROM dragons
        WHERE rider_id = ?
        ORDER BY id
        """,
        (g.current_user["id"],),
    ).fetchall()
    return jsonify(
        rider=safe_text(g.current_user["username"]),
        collection_size=len(dragons),
        dragons=[serialize_dragon(row) for row in dragons],
    )


@api_bp.post("/dragons")
@token_required
def add_dragon():
    if not request.is_json:
        return jsonify(error="JSON body required"), 415

    body = request.get_json(silent=True) or {}
    name = body.get("name")
    species = body.get("species")
    element = body.get("element")
    age = body.get("age")
    description = body.get("description")

    text_fields = (name, species, element, description)
    if not all(isinstance(value, str) for value in text_fields) or not isinstance(age, int):
        return jsonify(error="Invalid dragon data types"), 400

    name = name.strip()
    species = species.strip()
    element = element.strip().lower()
    description = description.strip()
    valid = (
        2 <= len(name) <= 50
        and 2 <= len(species) <= 80
        and element in ALLOWED_ELEMENTS
        and 0 <= age <= 10_000
        and len(description) <= 500
    )
    if not valid:
        return jsonify(error="Dragon data failed validation"), 400

    database = get_db()
    try:
        cursor = database.execute(
            """
            INSERT INTO dragons (rider_id, name, species, element, age, description)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (g.current_user["id"], name, species, element, age, description),
        )
        database.commit()
    except sqlite3.IntegrityError:
        return jsonify(error="A dragon with this name already exists in your collection"), 409

    dragon = database.execute(
        """
        SELECT id, name, species, element, age, description, created_at
        FROM dragons
        WHERE id = ? AND rider_id = ?
        """,
        (cursor.lastrowid, g.current_user["id"]),
    ).fetchone()
    return jsonify(dragon=serialize_dragon(dragon)), 201
