# src/api/patient.py
from flask import Blueprint, request, jsonify, g
from database.db import fetch_one, execute
from utils.security import require_role
from utils.logging_utils import audit_log
from utils.validation_new import validate_json, PatientUpdateSchema, PatientCreateSchema
import sqlite3

patient_bp = Blueprint("patient", "__name__")


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
    - Admin darf NICHT lesen
    - Minimalprinzip
    """

    role = g.current_user["role"]

    if role == "admin":
        return jsonify({"error": "Not permitted"}), 403

    if patient_id <= 0:
        audit_log(None, "READ_PATIENT_INVALID_ID", "Patient", patient_id, success=False)
        return jsonify({"error": "Invalid patient ID"}), 400

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
        "mrn": patient["mrn"],
    }

    if role == "doctor":
        response["diagnosis"] = patient["diagnosis"]

    audit_log(g.current_user["id"], "READ_PATIENT_SUCCESS", "Patient", patient_id, success=True)
    return jsonify(response), 200


# ============================================================
# POST /patient/update  (doctor only)
# ============================================================
@patient_bp.route("/patient/update", methods=["POST"])
@require_role(["doctor"])
@validate_json(PatientUpdateSchema)     # <<< WICHTIG: Marshmallow-Validation
def update_patient():
    """
    Diagnose-Update durch Ärzte
    Jetzt TR-03161-O.Source_1/-2 konform:
    - Eingaben formal validiert
    - Keine manuelle isinstance-Prüfung
    - Einheitliches Schema für alle Endpoints
    """

    data = request.validated_data
    patient_id = data["id"]
    new_diagnosis = data["diagnosis"]

    # Patient existiert?
    try:
        exists = fetch_one("SELECT id FROM patients WHERE id = ?", (patient_id,))
    except sqlite3.Error:
        audit_log(g.current_user["id"], "UPDATE_PATIENT_DB_ERROR", "Patient", patient_id, success=False)
        return jsonify({"error": "Database error"}), 500

    if exists is None:
        audit_log(g.current_user["id"], "UPDATE_PATIENT_NOT_FOUND", "Patient", patient_id, success=False)
        return jsonify({"error": "Patient not found"}), 404

    try:
        execute(
            "UPDATE patients SET diagnosis = ? WHERE id = ?",
            (new_diagnosis, patient_id)
        )
    except sqlite3.Error:
        audit_log(g.current_user["id"], "UPDATE_PATIENT_DIAGNOSIS_DB_ERROR", "Patient", patient_id, success=False)
        return jsonify({"error": "Database update error"}), 500

    audit_log(g.current_user["id"], "UPDATE_PATIENT_DIAGNOSIS_SUCCESS", "Patient", patient_id, success=True)

    return jsonify({
        "message": "Patient updated successfully",
        "patient_id": patient_id,
        "diagnosis": new_diagnosis
    }), 200
