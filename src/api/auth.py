# src/api/auth.py
from flask import Blueprint, request, jsonify, g
import sqlite3
from datetime import datetime, timedelta

from database.db import fetch_one, execute
from utils.logging_utils import audit_log
from utils.security import verify_password, hash_password, require_role

from utils.session_services import create_session, remove_session
from utils.validation_new import validate_json, LoginSchema, PasswordUpdateSchema

auth_bp = Blueprint("auth", __name__)


@auth_bp.route("/login", methods=["POST"])
@validate_json(LoginSchema)
def login():
    """
    Healthcare-SAFE Login mit Brute-Force Schutz (O.Auth_7).
    """
    data = request.validated_data
    username = data["username"].strip()
    password = data["password"]

    # 1. User laden (inkl. Lock-Status)
    try:
        user = fetch_one(
            "SELECT id, username, password, role, failed_attempts, locked_until FROM users WHERE username = ?",
            (username,)
        )
    except sqlite3.Error as e:
        print(f"Database error during login: {e}")
        return jsonify({"error": "Authentication failed"}), 401

    if user is None:
        # Generische Fehlermeldung (User Enumeration verhindern)
        return jsonify({"error": "Authentication failed"}), 401

    # 2. Prüfen, ob gesperrt (O.Auth_7)
    if user["locked_until"]:
        lock_time = datetime.fromisoformat(user["locked_until"])
        if lock_time > datetime.utcnow():
            remaining = int((lock_time - datetime.utcnow()).total_seconds() / 60)
            remaining = remaining if remaining > 0 else 1

            audit_log(user["id"], "LOGIN_LOCKED_ATTEMPT", "User", user["id"], success=False)
            return jsonify({
                "error": f"Account locked. Try again in {remaining} minutes."
            }), 429

    # 3. Passwort prüfen
    if not verify_password(password, user["password"]):
        # FEHLSCHLAG: Counter erhöhen
        new_failed = (user["failed_attempts"] or 0) + 1

        # Sperren nach 5 Versuchen?
        if new_failed >= 5:
            lock_duration = 15  # Minuten
            locked_until = (datetime.utcnow() + timedelta(minutes=lock_duration)).isoformat()

            execute(
                "UPDATE users SET failed_attempts = ?, locked_until = ? WHERE id = ?",
                (new_failed, locked_until, user["id"])
            )
            audit_log(user["id"], "LOGIN_LOCKOUT", "User", user["id"], success=False)
            return jsonify({"error": "Account locked due to too many failed attempts."}), 429
        else:
            execute(
                "UPDATE users SET failed_attempts = ? WHERE id = ?",
                (new_failed, user["id"])
            )
            audit_log(user["id"], "LOGIN_FAILED", "User", user["id"], success=False)
            return jsonify({"error": "Authentication failed"}), 401

    # 4. ERFOLG: Counter zurücksetzen
    if (user["failed_attempts"] and user["failed_attempts"] > 0) or user["locked_until"] is not None:
        execute(
            "UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE id = ?",
            (user["id"],)
        )

    # Session erstellen
    token = create_session(user["id"])
    audit_log(user["id"], "LOGIN_SUCCESS", "User", user["id"], success=True)

    return jsonify({
        "message": "Login successful",
        "token": token,
        "user": {"id": user["id"], "username": user["username"], "role": user["role"]}
    }), 200


@auth_bp.route("/logout", methods=["POST"])
def logout():
    """
    Beendet die Session sicher durch Löschen des Tokens aus der DB.
    """
    auth_header = request.headers.get("Authorization")
    token = None

    if auth_header and auth_header.startswith("Bearer "):
        token = auth_header.split(" ")[1]

    if token:
        # Hier nutzen wir jetzt korrekt remove_session
        remove_session(token)

    # Logging
    user_id = g.user["id"] if hasattr(g, "user") and g.user else None
    if user_id:
        audit_log(user_id, "LOGOUT", "User", user_id, success=True)

    return jsonify({"message": "Logged out successfully"}), 200


@auth_bp.route("/change-password", methods=["POST"])
@require_role(None)  # Jeder eingeloggte User
@validate_json(PasswordUpdateSchema)
def change_password():
    """
    Passwort ändern: Prüft altes PW, verhindert Wiederverwendung, setzt neues PW.
    """
    user_id = g.user["id"]
    data = request.validated_data

    old_password = data["old_password"]
    new_password = data["new_password"]

    # Aktuelles PW prüfen
    user = fetch_one("SELECT password FROM users WHERE id = ?", (user_id,))

    if not user or not verify_password(old_password, user["password"]):
        audit_log(user_id, "PASSWORD_CHANGE_FAILED", "User", user_id, success=False)
        return jsonify({"error": "Invalid current password"}), 400

    # Neues darf nicht gleich altes sein
    if verify_password(new_password, user["password"]):
        return jsonify({"error": "New password cannot be the same as the old password"}), 400

    hashed_new_pw = hash_password(new_password)

    try:
        execute(
            "UPDATE users SET password = ? WHERE id = ?",
            (hashed_new_pw, user_id)
        )
        audit_log(user_id, "PASSWORD_CHANGE_SUCCESS", "User", user_id, success=True)
        return jsonify({"message": "Password updated successfully"}), 200

    except sqlite3.Error:
        return jsonify({"error": "Database error while updating password"}), 500