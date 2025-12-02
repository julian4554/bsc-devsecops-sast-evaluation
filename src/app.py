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

    # =============================
    # Security Headers (TR-03161)
    # =============================
    @app.after_request
    def set_security_headers(response):
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Cache-Control"] = "no-store"
        response.headers["Pragma"] = "no-cache"
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
