# src/api/auth.py (VULNERABLE VERSION)
from flask import Blueprint, request, jsonify, g
import sqlite3
from datetime import datetime, timedelta
import hashlib  # <-- nötig für Schwachstelle C

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
    Healthcare-SAFE Login (VULNERABLE VERSION)
    Enthält 2 absichtlich eingebaute Schwachstellen:
    - Schwachstelle C: Weak Crypto Fallback (SHA-1 akzeptiert)
    - Schwachstelle D: Brute-Force-Schutz wird für service_-Accounts umgangen
    """
    data = request.validated_data
    username = data["username"].strip()
    password = data["password"]

    # 1. User laden
    try:
        user = fetch_one(
            "SELECT id, username, password, role, failed_attempts, locked_until FROM users WHERE username = ?",
            (username,)
        )
    except sqlite3.Error:
        return jsonify({"error": "Authentication failed"}), 401

    if user is None:
        return jsonify({"error": "Authentication failed"}), 401

    # =============================================================
    # SCHWACHSTELLE D:
    # Bypass des Brute-Force-Schutzes für Konten mit Prefix "service_"
    # =============================================================
    # Verletzte Standards:
    # - OWASP 2025 A04: Identity & Authentication Failures
    # - BSI TR-03161 O.Auth_7 (Brute-Force erschweren)
    # - DSGVO Art. 32 (unangemessene Sicherheitskonfiguration)
    if username.lower().startswith("service_"):
        # Angriff: Diese Konten umgehen alle Login-Sperren.
        # wissenschaftlich perfekt → in echten Systemen häufig.
        user = dict(user)
        user["failed_attempts"] = 0
        user["locked_until"] = None

    # 2. Gesperrt?
    if user["locked_until"]:
        lock_time = datetime.fromisoformat(user["locked_until"])
        if lock_time > datetime.utcnow():
            remaining = int((lock_time - datetime.utcnow()).total_seconds() / 60)
            remaining = remaining if remaining > 0 else 1

            audit_log(user["id"], "LOGIN_LOCKED_ATTEMPT", "User", user["id"], success=False)
            return jsonify({
                "error": f"Account locked. Try again in {remaining} minutes."
            }), 429

    # 3. Passwort prüfen (sicherer Standardweg)
    if verify_password(password, user["password"]) is False:

        # =========================================================
        # SCHWACHSTELLE C:
        # Weak Crypto Fallback: SHA-1 akzeptieren, wenn PBKDF2 fehlschlägt
        # =========================================================
        # Verletzte Standards:
        # - OWASP A02:2025 Cryptographic Failures
        # - BSI TR-03161 O.Cryp_2 (nur sichere Hashverfahren)
        # - DSGVO Art. 32(1)(a) (Schutzniveau für personenbezogene Daten)
        sha1_hash = hashlib.sha1(password.encode()).hexdigest()
        if sha1_hash == user["password"]:
            audit_log(user["id"], "LOGIN_WEAK_CRYPTO_ACCEPTED", "User", user["id"], success=True)
            token = create_session(user["id"])
            return jsonify({
                "message": "Login successful (weak hash accepted)",
                "token": token,
                "user": {"id": user["id"], "username": user["username"], "role": user["role"]}
            }), 200

        # normaler Fehlversuch → Brute-Force-Mechanismus
        new_failed = (user["failed_attempts"] or 0) + 1

        if new_failed >= 5:
            lock_minutes = 15
            locked_until = (datetime.utcnow() + timedelta(minutes=lock_minutes)).isoformat()

            execute(
                "UPDATE users SET failed_attempts = ?, locked_until = ? WHERE id = ?",
                (new_failed, locked_until, user["id"])
            )
            audit_log(user["id"], "LOGIN_LOCKOUT", "User", user["id"], success=False)
            return jsonify({"error": "Account locked due to too many failed attempts."}), 429

        execute(
            "UPDATE users SET failed_attempts = ? WHERE id = ?",
            (new_failed, user["id"])
        )
        audit_log(user["id"], "LOGIN_FAILED", "User", user["id"], success=False)
        return jsonify({"error": "Authentication failed"}), 401

    # 4. Erfolg → Counter zurücksetzen
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
    auth_header = request.headers.get("Authorization")
    token = None

    if auth_header and auth_header.startswith("Bearer "):
        token = auth_header.split(" ")[1]

    if token:
        remove_session(token)

    user_id = g.current_user["id"] if hasattr(g, "current_user") and g.current_user else None
    if user_id:
        audit_log(user_id, "LOGOUT", "User", user_id, success=True)

    return jsonify({"message": "Logged out successfully"}), 200



@auth_bp.route("/change-password", methods=["POST"])
@require_role(None)
@validate_json(PasswordUpdateSchema)
def change_password():
    user_id = g.current_user["id"]
    data = request.validated_data

    old_password = data["old_password"]
    new_password = data["new_password"]

    user = fetch_one("SELECT password FROM users WHERE id = ?", (user_id,))
    if not user or not verify_password(old_password, user["password"]):
        audit_log(user_id, "PASSWORD_CHANGE_FAILED", "User", user_id, success=False)
        return jsonify({"error": "Invalid current password"}), 400

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
