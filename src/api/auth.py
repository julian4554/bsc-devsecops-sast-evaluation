# src/api/auth.py
from flask import Blueprint, request, jsonify
from database.db import fetch_one
from utils.security import verify_password
from utils.session_services import create_session    # <--- WICHTIG: NEU!
from utils.logging_utils import audit_log
from utils.validation_new import validate_json, LoginSchema
import sqlite3


auth_bp = Blueprint("auth", __name__)


@auth_bp.route("/login", methods=["POST"])
@validate_json(LoginSchema)
def login():
    """
    Healthcare-SAFE Login Endpoint:
    - JSON Validation via Marshmallow
    - Parameterisierte SQL-Query
    - PBKDF2 Passwortprüfung
    - Session in DB speichern
    - Audit Logging (kein Sensitive Data Leak)
    """

    data = request.validated_data
    username = data["username"].strip()
    password = data["password"]

    # Nutzer abrufen
    try:
        user = fetch_one(
            "SELECT id, username, password, role FROM users WHERE username = ?",
            (username,)
        )
    except sqlite3.Error:
        audit_log(None, "LOGIN_DB_ERROR", "User", None, success=False)
        return jsonify({"error": "Authentication failed"}), 401

    if user is None:
        audit_log(None, "LOGIN_FAILED_UNKNOWN_USER", "User", None, success=False)
        return jsonify({"error": "Authentication failed"}), 401

    # Passwort vergleichen
    if not verify_password(password, user["password"]):
        audit_log(user["id"], "LOGIN_FAILED_WRONG_PASSWORD", "User", user["id"], success=False)
        return jsonify({"error": "Authentication failed"}), 401

    # Session erzeugen (NEU: aus session_service)
    token = create_session(user["id"])

    audit_log(user["id"], "LOGIN_SUCCESS", "User", user["id"], success=True)

    return jsonify({
        "message": "Login successful",
        "token": token,
        "user": {
            "id": user["id"],
            "username": user["username"],
            "role": user["role"]
        }
    }), 200
