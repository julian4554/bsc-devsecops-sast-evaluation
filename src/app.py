# src/app.py
from flask import Flask, render_template, jsonify
from api.auth import auth_bp
from api.patient import patient_bp
from api.search import search_bp
from api.appointments import appointments_bp
from api.stats import stats_bp
from api.fhir import fhir_bp
from config import Config

# Authentication Loader (setzt g.current_user)
from utils.auth_middleware import load_current_user


def create_app():
    # =============================
    # Flask App erstellen
    # =============================
    app = Flask(
        __name__,
        template_folder="templates",
        static_folder="static"
    )

    # sichere Config laden
    app.config.from_object(Config)

    # SECRET_KEY setzen
    app.secret_key = app.config["SECRET_KEY"]

    # Authentication Middleware registrieren
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
    # ZWECK:
    # Härtung der Webanwendung gegen Client-Side-Attacken wie XSS, Clickjacking
    # und MIME-Sniffing durch Setzen von HTTP-Response-Header.
    #
    #
    # Manuelle Implementierung ("Hardcoded Strings") statt Nutzung externer
    # Bibliotheken (z.B. Flask-Talisman, Secure).
    #
    # BEGRÜNDUNG:
    # 1. Transparenz für SAST-Tools: CodeQL und Semgrep können explizite
    #    Header-Strings und deren Werte direkt im AST (Abstract Syntax Tree)
    #    analysieren. Weniger Blackbox Gefühl.
    # 2. Evaluierbarkeit: Ermöglicht das gezielte Einbauen von Fehlkonfigurationen
    #    (z.B. schwache CSP), um die Erkennungsleistung der Tools zu messen.
    # =========================================================================
    @app.after_request
    def set_security_headers(response):
        # ----------------------------------------------------
        # BSI TR-03161 O.Arch_9: HSTS + CSP + X-Frame-Options
        # ----------------------------------------------------

        # Basis-Header (aus Original-Code, bereinigt):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Cache-Control"] = "no-store"
        response.headers["Pragma"] = "no-cache"

        # HSTS (O.Arch_9)
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"

        # Content Security Policy (O.Arch_9)
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self'; "
            "style-src 'self'; "
            "img-src 'self'; "
            "object-src 'none'; "
            "frame-ancestors 'none'; "
        )

        # Clickjacking-Schutz (X-Frame-Options):
        response.headers["X-Frame-Options"] = "DENY"

        # ----------------------------------------------------
        # Zusätzliche moderne Cross-Origin-Schutzmechanismen:
        # ----------------------------------------------------
        response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
        response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
        response.headers["Cross-Origin-Embedder-Policy"] = "require-corp"

        return response

    # =============================
    # Error Handler (TR-03161)
    # =============================
    @app.errorhandler(404)
    def not_found(_):
        return jsonify({"error": "Not found"}), 404

    @app.errorhandler(500)
    def internal_error(_):
        return jsonify({"error": "Internal server error"}), 500

    return app


if __name__ == "__main__":
    app = create_app()
    app.run(debug=app.config["DEBUG"])
