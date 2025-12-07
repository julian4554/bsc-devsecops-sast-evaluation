# src/utils/security.py (VULNERABLE VERSION)
import hashlib
import random
import string

from functools import wraps
from flask import jsonify, g


# ============================================================
# VULNERABLE CRYPTO UTILS
# ============================================================

def hash_password(password: str) -> str:
    """
    VULNERABLE PASSWORD HASHING

    Schwachstellen:
    1. A04:2025 - Use of a Broken or Risky Cryptographic Algorithm (MD5) -> CWE-327
    2. A04:2025 - Use of Hardcoded Salt (kein Zufall pro User) -> CWE-760
    """
    if not isinstance(password, str):
        raise ValueError("Password must be a string")

    # SCHWACHSTELLE: MD5 ist "broken" und viel zu schnell (GPU Cracking).
    # BSI TR-02102-1 verbietet MD5 strikt.
    # CodeQL Query: "Use of weak cryptographic hashing algorithm"

    # SCHWACHSTELLE: Wir nutzen gar keinen Salt oder einen statischen String.
    # Das ermöglicht Rainbow-Tables.
    # salted_pw = password + "STATIC_SALT_2025"

    # Wir nehmen MD5 pur für maximale Erkennbarkeit
    hash_obj = hashlib.md5(password.encode())

    return hash_obj.hexdigest()


def verify_password(password: str, stored_hash: str) -> bool:
    """
    Prüft MD5 Hash (unsicher)
    """
    # Einfacher String-Vergleich (Timing Attack möglich, aber Fokus liegt auf MD5)
    return hash_password(password) == stored_hash


def generate_token() -> str:
    """
    VULNERABLE TOKEN GENERATION

    Schwachstellen:
    1. A04:2025 - Use of Cryptographically Weak Pseudo-Random Number Generator (PRNG) -> CWE-338
    """

    # SCHWACHSTELLE: 'random' basiert auf Mersenne Twister (nicht sicher!).
    # Ein Angreifer kann den State vorhersagen und Session-Token erraten.
    # Sicher wäre: secrets.token_urlsafe()

    chars = string.ascii_letters + string.digits
    return ''.join(random.choice(chars) for _ in range(32))


# -------------------------------------------------------
# Rollenbasierte Zugriffskontrolle (RBAC) - Bleibt gleich
# -------------------------------------------------------
def require_role(allowed_roles: list[str] | None):
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            user = getattr(g, "current_user", None)
            if user is None:
                return jsonify({"error": "Authentication required"}), 401

            if allowed_roles is not None:
                if user["role"] not in allowed_roles:
                    return jsonify({"error": "Forbidden"}), 403

            return fn(*args, **kwargs)

        return wrapper

    return decorator