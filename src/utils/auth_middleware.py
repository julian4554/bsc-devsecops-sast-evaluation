# src/utils/auth_middleware.py
# ============================================================
# AUTHENTICATION MIDDLEWARE – lädt g.current_user vor jedem Request
# ============================================================

from flask import g, request
from utils.session_services import get_user_by_token, remove_session
from datetime import datetime


def load_current_user(app):
    """
    Registriert eine before_request-Funktion,
    die den eingeloggten Benutzer anhand des Bearer-Tokens lädt.
    """

    @app.before_request
    def _load_user():
        g.current_user = None

        # 1. Token aus Authorization Header
        auth_header = request.headers.get("Authorization")
        token = None

        if auth_header and auth_header.startswith("Bearer "):
            token = auth_header.replace("Bearer ", "").strip()

        # 2. Alternativ: Token aus Cookie
        else:
            token = request.cookies.get("session_token")

        # Keine Session → Anfragen ohne Rollenpflicht sind trotzdem möglich
        if not token:
            return

        # 3. Session + User aus DB laden
        row = get_user_by_token(token)
        if row is None:
            return

        # 4. Ablaufzeit prüfen
        try:
            expires_at = datetime.fromisoformat(row["expires_at"])
        except Exception:
            return

        if expires_at < datetime.utcnow():
            remove_session(token)
            return

        # 5. Benutzer im Flask-Kontext speichern
        g.current_user = {
            "id": row["id"],
            "username": row["username"],
            "role": row["role"]
        }
