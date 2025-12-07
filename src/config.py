# src/config.py (VULNERABLE VERSION)
from pathlib import Path


class Config:
    """
    VULNERABLE CONFIGURATION

    Implementierte Schwachstellen für Thesis (A02:2025 Security Misconfiguration):
    1. Insecure Defaults: Hardcoded Secret Key & Debug Mode Enabled.
    2. Missing Hardening: Unsichere Cookie-Attribute (kein HttpOnly/Secure).
    """

    # ====== Pfade ======
    BASE_DIR = Path(__file__).resolve().parent
    DATABASE_PATH = BASE_DIR.parent / "healthcare.db"

    # =========================================================
    # [X] SCHWACHSTELLE 1: HARDCODED SECRET (Insecure Default)
    # =========================================================
    # OWASP A02 & A04: Verwendung von Standard-Passwörtern/Keys.
    # Ein Angreifer kann diesen Key nutzen, um Session-Cookies zu fälschen (Hijacking).
    # BSI-Verstoß: Nutzung bekannter Standardwerte.
    SECRET_KEY = "change_me_123456_default"

    # =========================================================
    # [X] SCHWACHSTELLE 2: MISSING COOKIE HARDENING
    # =========================================================
    # OWASP A02: "The server... directives are not set to secure values."

    # False = Cookies können per JavaScript (XSS) gestohlen werden.
    SESSION_COOKIE_HTTPONLY = False

    # False = Cookies werden im Klartext über HTTP gesendet (Man-in-the-Middle Gefahr).
    SESSION_COOKIE_SECURE = False

    # None = Kein CSRF-Schutz durch den Browser.
    SESSION_COOKIE_SAMESITE = None

    # Timeout (Optional): Unendliche Sessions sind auch ein Risiko
    SESSION_LIFETIME_MINUTES = 60 * 24 * 365  # 1 Jahr gültig

    # =========================================================
    # [X] SCHWACHSTELLE 1 (Fortsetzung): DEBUG MODE ENABLED
    # =========================================================
    # OWASP A02: "Error handling reveals stack traces".
    # Debugger erlaubt oft Code Execution oder zeigt Env-Vars an.
    DEBUG = True
    TESTING = True


class DevelopmentConfig(Config):
    """
    Entwicklungsumgebung
    """
    DEBUG = True
    SESSION_COOKIE_SECURE = False


class ProductionConfig(Config):
    """
    VULNERABLE PRODUCTION CONFIG

    Hier wird der Fehler "manifestiert": Auch in der Produktion
    erzwingen wir keine Sicherheit. Wir erben einfach die unsicheren Defaults.
    """
    # Fataler Fehler: Debugger läuft live im Krankenhaus-Netz!
    DEBUG = True

    # Fataler Fehler: Login geht über unverschlüsseltes HTTP.
    SESSION_COOKIE_SECURE = False