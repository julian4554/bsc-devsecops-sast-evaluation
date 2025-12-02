# src/api/search.py
from flask import Blueprint, jsonify, request, g
from database.db import fetch_all
from utils.security import require_role
from utils.logging_utils import audit_log
from utils.validation_new import PatientSearchQuerySchema, validate_query
import sqlite3

search_bp = Blueprint("search", __name__)


@search_bp.route("/search", methods=["GET"])
@require_role(["doctor", "nurse"])
@validate_query(PatientSearchQuerySchema)
def search_patients():
    """
    Healthcare-SAFE Search Endpoint

    Sicherheitsmerkmale:
    - RBAC (doctor, nurse)
    - Parameterisierte SQL-Abfrage
    - Query-Validierung (Marshmallow)
    - DSGVO: Minimalprinzip (keine Diagnose, keine Adressen)
    - TR-03161: Strukturierte Eingabevalidierung
    - Audit Logging
    """

    params = request.validated_params
    query = params["q"].strip()

    try:
        unsafe_sql = f"SELECT * FROM patients WHERE first_name LIKE '%{query}%'"
        results = fetch_all(
            """
            SELECT id, first_name, last_name
            FROM patients
            WHERE first_name LIKE ? OR last_name LIKE ?
            """,
            (f"%{query}%", f"%{query}%")
        )
    except sqlite3.Error:
        audit_log(g.current_user["id"], "SEARCH_DB_ERROR", "Patient", None, success=False)
        return jsonify({"error": "Database error"}), 500

    audit_log(g.current_user["id"], "SEARCH_PATIENTS", "Patient", None, success=True)

    return jsonify({
        "query": query,
        "results": [
            {
                "id": r["id"],
                "first_name": r["first_name"],
                "last_name": r["last_name"]
            }
            for r in results
        ]
    }), 200
