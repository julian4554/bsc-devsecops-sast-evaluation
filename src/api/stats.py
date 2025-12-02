# src/api/stats.py
from flask import Blueprint, jsonify, g
from database.db import fetch_one
from utils.security import require_role
from utils.logging_utils import audit_log
import sqlite3

stats_bp = Blueprint("stats", __name__)


@stats_bp.route("/stats", methods=["GET"])
@require_role(["admin"])
def get_stats():
    """
    Healthcare-SAFE System Statistics Endpoint
    ------------------------------------------
    DSGVO / TR-03161:
    - Keine personenbezogenen Daten
    - RBAC: Nur Admin
    - Generische Fehlermeldungen
    - Sicherer Zugriff auf Datenbank
    """

    # Admin User (falls Middleware nicht gesetzt wäre → Safe Fallback)
    user_id = g.current_user["id"] if g.get("current_user") else None

    try:
        patients_count = fetch_one("SELECT COUNT(*) AS count FROM patients")
        users_count = fetch_one("SELECT COUNT(*) AS count FROM users")
        appointments_count = fetch_one("SELECT COUNT(*) AS count FROM appointments")
        doctors_count = fetch_one(
            "SELECT COUNT(*) AS count FROM users WHERE role = 'doctor'"
        )
    except sqlite3.Error:
        audit_log(user_id, "READ_STATS_DB_ERROR", "System", None, success=False)
        return jsonify({"error": "Database error"}), 500

    audit_log(user_id, "READ_STATS_SUCCESS", "System", None, success=True)

    return jsonify({
        "patients": patients_count["count"],
        "users": users_count["count"],
        "appointments": appointments_count["count"],
        "doctors": doctors_count["count"]
    }), 200
