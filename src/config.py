# src/config.py
import os
import secrets
from pathlib import Path

class Config:
    """
    Healthcare-SAFE Flask Konfiguration
    -----------------------------------
    - DSGVO & BSI TR-03161-konform (light)
    - Keine Hardcoded Secrets
    - Sichere Cookies
    - Einheitliches DB-Handling
    """

    # ====== Sicherheit ======
    SECRET_KEY = os.environ.get(
        "SECRET_KEY",
        secrets.token_hex(32)  # fallback: 256-bit geheimes Token
    )

    SESSION_COOKIE_SECURE = True       # nur via HTTPS senden
    SESSION_COOKIE_HTTPONLY = True     # nicht via JS auslesbar
    SESSION_COOKIE_SAMESITE = "Strict" # Schutz gegen CSRF

    # ====== Session-Timeout ======
    SESSION_LIFETIME_MINUTES = int(os.environ.get(
        "SESSION_LIFETIME_MINUTES",
        "60"
    ))

    # ====== Datenbankpfad ======
    # wird von db.py verwendet → keine doppelte DB-Definition
    BASE_DIR = Path(__file__).resolve().parent
    DATABASE_PATH = BASE_DIR.parent / "healthcare.db"

    # ====== Debug ======
    DEBUG = os.environ.get("FLASK_DEBUG", "0") == "1"
