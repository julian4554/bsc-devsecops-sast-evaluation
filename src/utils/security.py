# src/utils/security.py
import base64
import hashlib
import hmac
import os
import secrets
from functools import wraps

from flask import request, jsonify, g


# -------------------------------------------------------
# Passwort-Hashing (PBKDF2)
# -------------------------------------------------------

def hash_password(password: str) -> str:
    if not isinstance(password, str):
        raise ValueError("Password must be a string")

    salt = os.urandom(16)
    dk = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        200_000
    )
    return base64.b64encode(salt + dk).decode("ascii")


def verify_password(password: str, stored_hash: str) -> bool:
    try:
        raw = base64.b64decode(stored_hash.encode("ascii"))
    except Exception:
        return False

    if len(raw) < 32:
        return False

    salt = raw[:16]
    stored_dk = raw[16:]

    new_dk = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        200_000
    )

    return hmac.compare_digest(stored_dk, new_dk)


def generate_token() -> str:
    return secrets.token_urlsafe(32)


# -------------------------------------------------------
# Rollenbasierte Zugriffskontrolle (RBAC)
# -------------------------------------------------------

def require_role(allowed_roles: list[str] | None):
    """
    Decorator für API-Endpunkte.

    :param allowed_roles: Liste erlaubter Rollen (z.B. ["doctor"]).
                          Wenn None übergeben wird, ist jeder authentifizierte
                          Nutzer erlaubt (Login required only).
    """

    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            # Authentifizierung prüfen
            user = getattr(g, "current_user", None)
            if user is None:
                return jsonify({"error": "Authentication required"}), 401

            # Autorisierung prüfen (nur wenn Rollen definiert sind)
            # KORREKTUR: Prüfung nur, wenn allowed_roles nicht None ist
            if allowed_roles is not None:
                if user["role"] not in allowed_roles:
                    return jsonify({"error": "Forbidden"}), 403

            return fn(*args, **kwargs)

        return wrapper

    return decorator