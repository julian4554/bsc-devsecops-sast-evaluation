# src/utils/session_services.py
# ============================================================
# SESSION SERVICE – DB-Schicht für Sessions
# ============================================================

from datetime import datetime, timedelta
from database.db import fetch_one, execute
from utils.security import generate_token


def create_session(user_id: int, lifetime_minutes: int = 60) -> str:
    """
    Erstellt einen neuen Session-Eintrag in der Datenbank.
    """
    token = generate_token()
    now = datetime.utcnow()
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
    """
    Liefert den Benutzer zur Session aus der Datenbank oder None.
    """
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
    """
    Löscht einen Session-Eintrag aus der Datenbank.
    """
    execute("DELETE FROM sessions WHERE token = ?", (token,))
