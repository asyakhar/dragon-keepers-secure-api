import sqlite3

import bcrypt
import click
from flask import current_app, g


SCHEMA = """
CREATE TABLE IF NOT EXISTS riders (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS dragons (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    rider_id INTEGER NOT NULL,
    name TEXT NOT NULL,
    species TEXT NOT NULL,
    element TEXT NOT NULL,
    age INTEGER NOT NULL CHECK (age >= 0),
    description TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (rider_id) REFERENCES riders (id) ON DELETE CASCADE,
    UNIQUE (rider_id, name)
);
"""


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(current_app.config["DATABASE_PATH"])
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


def close_db(_error=None):
    database = g.pop("db", None)
    if database is not None:
        database.close()


def init_db():
    database = get_db()
    database.executescript(SCHEMA)
    database.commit()


def validate_password(password):
    checks = (
        len(password) >= 12,
        any(char.islower() for char in password),
        any(char.isupper() for char in password),
        any(char.isdigit() for char in password),
        any(not char.isalnum() for char in password),
    )
    return all(checks)


def hash_password(password):
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt(rounds=12)).decode("utf-8")


def verify_password(password, password_hash):
    try:
        return bcrypt.checkpw(password.encode("utf-8"), password_hash.encode("utf-8"))
    except (ValueError, TypeError):
        return False


def create_rider(username, password):
    if not isinstance(username, str) or not 3 <= len(username) <= 50:
        raise ValueError("Username must contain 3-50 characters")
    if not isinstance(password, str) or not validate_password(password):
        raise ValueError(
            "Password must be at least 12 characters and contain upper/lowercase letters, "
            "a number, and a special character"
        )

    database = get_db()
    try:
        cursor = database.execute(
            "INSERT INTO riders (username, password_hash) VALUES (?, ?)",
            (username, hash_password(password)),
        )
        database.commit()
        return cursor.lastrowid
    except sqlite3.IntegrityError as error:
        raise ValueError("Rider already exists") from error


def seed_dragons(rider_id):
    database = get_db()
    database.executemany(
        """
        INSERT INTO dragons (rider_id, name, species, element, age, description)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        [
            (rider_id, "Искра", "Небесный дракон", "fire", 120, "Быстрый и преданный"),
            (rider_id, "Север", "Ледяной виверн", "ice", 87, "Хранитель горных перевалов"),
        ],
    )
    database.commit()


@click.command("init-db")
@click.option("--username", prompt="Rider username", help="Initial rider username")
@click.password_option(confirmation_prompt=True)
def init_db_command(username, password):
    """Create database tables, the first rider, and a demo collection."""
    init_db()
    try:
        rider_id = create_rider(username, password)
        seed_dragons(rider_id)
    except ValueError as error:
        raise click.ClickException(str(error)) from error
    click.echo("Dragon registry initialized and rider created.")


def init_app(app):
    app.teardown_appcontext(close_db)
    app.cli.add_command(init_db_command)
