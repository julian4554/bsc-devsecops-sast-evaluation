# src/config.py
import os
import secrets
from pathlib import Path


class Config:
    """
    Basis-Konfiguration (Secure by Default).
    Diese Klasse definiert die sicheren Standardwerte für die Produktion.
    """

    # ====== Pfade ======
    BASE_DIR = Path(__file__).resolve().parent
    # Datenbank liegt ein Verzeichnis über src (im Root des Projekts)
    DATABASE_PATH = BASE_DIR.parent / "healthcare.db"

    # ====== Sicherheit ======
    # In Produktion MUSS dies per Environment Variable gesetzt sein!
    SECRET_KEY = os.environ.get(
        "SECRET_KEY",
        secrets.token_hex(32)  # Fallback: Sicherer Zufallswert
    )

    # ====== Session-Härtung (O.Auth_10 / O.Source_10) ======
    SESSION_COOKIE_HTTPONLY = True  # Schutz gegen XSS
    SESSION_COOKIE_SAMESITE = "Strict"  # Starker Schutz gegen CSRF

    # Timeout-Konfiguration
    SESSION_LIFETIME_MINUTES = int(os.environ.get("SESSION_LIFETIME_MINUTES", "60"))

    # ====== Standard-Verhalten (Härtung für O.Source_6) ======
    # Debug-Modus standardmäßig AUS!
    DEBUG = False
    TESTING = False
    # Secure Flag standardmäßig AN (erfordert HTTPS)!
    SESSION_COOKIE_SECURE = True


class DevelopmentConfig(Config):
    """
    Konfiguration für lokale Entwicklung.
    Erlaubt Debugging und HTTP.
    """
    DEBUG = True
    SESSION_COOKIE_SECURE = False  # Erlaubt Login über http://localhost


class ProductionConfig(Config):
    """
    Zwingende Konfiguration für den Live-Betrieb.
    Erbt von Config, stellt aber sicher, dass keine Dev-Settings aktiv sind.
    """
    DEBUG = False
    SESSION_COOKIE_SECURE = True  # Zwingend HTTPS erforderlich!