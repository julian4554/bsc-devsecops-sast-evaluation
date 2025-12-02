# src/utils/security.py
# ============================================================
# SECURITY UTILITIES (DB-FREE)
# ============================================================
# Enthält:
# - PBKDF2 Passwort-Hashing
# - Passwort-Verifikation
# - Token-Generierung
# - Rollenbasierte Zugriffskontrolle (RBAC)
#
# Enthält NICHT:
# - Datenbankzugriffe  (→ ausgelagert nach session_service.py)
# - Session-Logik (→ session_service.py)
#
# Dadurch KEINE circular imports möglich.
# ============================================================

import base64
import hashlib
import hmac
import os
import secrets
from functools import wraps

from flask import request, jsonify, g


# -------------------------------------------------------
# Passwort-Hashing (PBKDF2 – BSI/DSGVO-konform)
# -------------------------------------------------------

def hash_password(password: str) -> str:
    """
    Starkes PBKDF2-HMAC-SHA256 Hashing:
    - 16 Byte Salt
    - 200.000 Iterationen (BSI-Level)
    - Rückgabe: base64(salt + hash)
    """
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
    """
    Verifiziert ein Passwort gegen einen gespeicherten PBKDF2-Hash.
    """
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


# -------------------------------------------------------
# Token-Generierung
# -------------------------------------------------------

def generate_token() -> str:
    """
    Erstellt ein kryptografisch starkes, URL-sicheres Session-Token.
    """
    return secrets.token_urlsafe(32)


# -------------------------------------------------------
# Rollenbasierte Zugriffskontrolle (RBAC)
# -------------------------------------------------------

def require_role(allowed_roles: list[str]):
    """
    Decorator für API-Endpunkte.
    Zugriff nur, wenn der Nutzer authentifiziert ist UND die Rolle passt.
    Beispiel:
        @require_role(["doctor", "nurse"])
    """

    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):

            # Der Authentication-Layer (middleware) setzt g.current_user
            user = getattr(g, "current_user", None)

            if user is None:
                return jsonify({"error": "Authentication required"}), 401

            if user["role"] not in allowed_roles:
                return jsonify({"error": "Forbidden"}), 403

            return fn(*args, **kwargs)
        return wrapper
    return decorator
