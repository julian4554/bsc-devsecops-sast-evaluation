# src/utils/session_services.py
from datetime import datetime, timedelta
from flask import current_app  # KORREKTUR: Zugriff auf Config
from database.db import fetch_one, execute
from utils.security import generate_token


def create_session(user_id: int) -> str:
    """
    Erstellt einen neuen Session-Eintrag in der Datenbank.
    Liest die Lifetime dynamisch aus der App-Config.
    """
    token = generate_token()
    now = datetime.utcnow()

    # KORREKTUR: Wert aus Config laden (Fallback 60 Min)
    lifetime_minutes = current_app.config.get("SESSION_LIFETIME_MINUTES", 60)

    expires = now + timedelta(minutes=lifetime_minutes)

    execute(
        """
        INSERT INTO sessions (user_id, token, created_at, expires_at)
        VALUES (?, ?, ?, ?)
        """,
        (user_id, token, now.isoformat(), expires.isoformat())
    )

    return token


def get_user_by_token(token: str):
    return fetch_one(
        """
        SELECT u.id, u.username, u.role, s.expires_at
        FROM users u
        JOIN sessions s ON u.id = s.user_id
        WHERE s.token = ?
        """,
        (token,)
    )


def remove_session(token: str):
    execute("DELETE FROM sessions WHERE token = ?", (token,))