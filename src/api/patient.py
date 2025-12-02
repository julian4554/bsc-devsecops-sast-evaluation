# src/api/patient.py
from flask import Blueprint, request, jsonify, g
from database.db import fetch_one, execute
from utils.security import require_role
from utils.logging_utils import audit_log
from utils.validation_new import PatientUpdateSchema, PatientCreateSchema
import sqlite3

patient_bp = Blueprint("patient", __name__)


# ============================================================
# GET /patient/<id>  (doctor, nurse)
# ============================================================
@patient_bp.route("/patient/<int:patient_id>", methods=["GET"])
@require_role(["doctor", "nurse"])
def get_patient(patient_id):
    """
    Healthcare-SAFE Patient Lookup
    DSGVO / TR-03161:
    - Doctor & Nurse dürfen Basisdaten sehen
    - Admin darf NICHT lesen (sensitive data)
    - Minimalprinzip: MRN + Basisidentität + optional Diagnose für Ärzte
    """

    role = g.current_user["role"]

    # Admin hat keine klinischen Lese-Berechtigungen
    if role == "admin":
        return jsonify({"error": "Not permitted"}), 403

    if patient_id <= 0:
        audit_log(None, "READ_PATIENT_INVALID_ID", "Patient", patient_id, success=False)
        return jsonify({"error": "Invalid patient ID"}), 400

    # Patient abrufen
    try:
        patient = fetch_one(
            """
            SELECT id, first_name, last_name, birthdate, mrn, diagnosis
            FROM patients
            WHERE id = ?
            """,
            (patient_id,)
        )
    except sqlite3.Error:
        audit_log(None, "READ_PATIENT_DB_ERROR", "Patient", patient_id, success=False)
        return jsonify({"error": "Database error"}), 500

    if patient is None:
        audit_log(g.current_user["id"], "READ_PATIENT_NOT_FOUND", "Patient", patient_id, success=False)
        return jsonify({"error": "Patient not found"}), 404

    # Datenminimierung
    response = {
        "id": patient["id"],
        "first_name": patient["first_name"],
        "last_name": patient["last_name"],
        "birthdate": patient["birthdate"],
        "mrn": patient["mrn"]
    }

    # Diagnose nur für doctor einsehbar
    if role == "doctor":
        response["diagnosis"] = patient["diagnosis"]

    audit_log(g.current_user["id"], "READ_PATIENT_SUCCESS", "Patient", patient_id, success=True)
    return jsonify(response), 200


# ============================================================
# POST /patient/update  (doctor only)
# ============================================================
@patient_bp.route("/patient/update", methods=["POST"])
@require_role(["doctor"])
def update_patient():
    """
    Nur Ärzte dürfen Diagnosen ändern.
    """
    data = request.get_json(silent=True)

    if not data:
        return jsonify({"error": "Missing JSON body"}), 400

    patient_id = data.get("id")
    new_diagnosis = data.get("diagnosis")

    if not isinstance(patient_id, int) or patient_id <= 0:
        return jsonify({"error": "Invalid patient ID"}), 400

    if not isinstance(new_diagnosis, str) or len(new_diagnosis.strip()) == 0:
        return jsonify({"error": "Invalid diagnosis"}), 400

    # Existiert Patient?
    try:
        exists = fetch_one("SELECT id FROM patients WHERE id = ?", (patient_id,))
    except sqlite3.Error:
        return jsonify({"error": "Database error"}), 500

    if exists is None:
        return jsonify({"error": "Patient not found"}), 404

    # Update
    try:
        execute(
            "UPDATE patients SET diagnosis = ? WHERE id = ?",
            (new_diagnosis.strip(), patient_id)
        )
    except sqlite3.Error:
        return jsonify({"error": "Database update error"}), 500

    audit_log(g.current_user["id"], "UPDATE_PATIENT_DIAGNOSIS_SUCCESS", "Patient", patient_id, success=True)

    return jsonify({
        "message": "Patient updated successfully",
        "patient_id": patient_id,
        "diagnosis": new_diagnosis.strip()
    }), 200
