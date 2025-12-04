# src/app.py
import os
from flask import Flask, render_template, jsonify

# API Blueprints
from api.auth import auth_bp
from api.patient import patient_bp
from api.search import search_bp
from api.appointments import appointments_bp
from api.stats import stats_bp
from api.fhir import fhir_bp

# Middleware
from utils.auth_middleware import load_current_user

# Configs (Secure-by-Default)
from config import DevelopmentConfig, ProductionConfig


def create_app():
    # =============================
    # Flask App erstellen
    # =============================
    app = Flask(
        __name__,
        template_folder="templates",
        static_folder="static"
    )

    # =============================
    # Sichere Konfiguration (O.Source_6)
    # =============================
    # Logik umgedreht: Standard ist Production (Sicher)
    # Nur wenn explizit 'development' gesetzt ist, wird der Dev-Modus aktiviert.
    env_state = os.environ.get("FLASK_ENV", "production").lower()

    if env_state == "development":
        print("[WARNING] Running in Development Mode - Unsafe for Production!")
        app.config.from_object(DevelopmentConfig)
    else:
        app.config.from_object(ProductionConfig)

    # SECRET_KEY setzen (wird aus Config geladen)
    app.secret_key = app.config["SECRET_KEY"]

    # Authentication Middleware laden
    load_current_user(app)

    # =============================
    # API Blueprints
    # =============================
    app.register_blueprint(auth_bp)
    app.register_blueprint(patient_bp)
    app.register_blueprint(search_bp)
    app.register_blueprint(appointments_bp)
    app.register_blueprint(stats_bp)
    app.register_blueprint(fhir_bp)

    # =============================
    # Frontend Routes (UI)
    # =============================
    @app.route("/")
    def login_page():
        return render_template("login.html")

    @app.route("/dashboard")
    def dashboard_page():
        return render_template("dashboard.html")

    @app.route("/patient/<int:patient_id>")
    def patient_page(patient_id):
        return render_template("patient.html", patient_id=patient_id)

    @app.route("/appointment")
    def appointment_page():
        return render_template("appointment.html")

    @app.route("/fhir_view/<int:patient_id>")
    def fhir_patient_view(patient_id):
        return render_template("fhir_viewer.html", patient_id=patient_id)

    # =========================================================================
    # SICHERHEITS-HEADER (IMPLEMENTIERUNG NACH BSI TR-03161 O.Arch_9)
    # =========================================================================
    @app.after_request
    def set_security_headers(response):
        # Basis-Header
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Cache-Control"] = "no-store"
        response.headers["Pragma"] = "no-cache"

        # HSTS (HTTPS-Pflicht) - 1 Jahr
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"

        # CSP: Keine fremden Skripte oder Inhalte
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self'; "
            "style-src 'self'; "
            "img-src 'self'; "
            "object-src 'none'; "
            "frame-ancestors 'none'; "
        )

        # Clickjacking-Schutz
        response.headers["X-Frame-Options"] = "DENY"

        # Zusätzliche moderne Cross-Origin-Schutzmechanismen
        response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
        response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
        response.headers["Cross-Origin-Embedder-Policy"] = "require-corp"

        return response

    # =============================
    # Error Handler
    # =============================
    @app.errorhandler(404)
    def not_found(_):
        return jsonify({"error": "Not found"}), 404

    @app.errorhandler(500)
    def internal_error(_):
        return jsonify({"error": "Internal server error"}), 500

    return app


# =============================
# App starten
# =============================
if __name__ == "__main__":
    app = create_app()
    app.run()