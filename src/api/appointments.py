# src/api/appointments.py
from flask import Blueprint, jsonify, request, g
from database.db import fetch_one, execute
from utils.security import require_role
from utils.logging_utils import audit_log
from utils.validation_new import validate_json, AppointmentCreateSchema
import sqlite3
from datetime import datetime

appointments_bp = Blueprint("appointments", __name__)


@appointments_bp.route("/appointments/create", methods=["POST"])
@require_role(["doctor", "nurse"])
@validate_json(AppointmentCreateSchema)
def create_appointment():
    """
    Healthcare-SAFE Appointment Creation

    Sicherheit:
    - RBAC (doctor, nurse)
    - input validation (Marshmallow)
    - nurse/doctors dürfen Termine erstellen
    - doctor_id immer = aktuelle Session
    - TR-03161: parameterisierte SQL + generische Fehler
    - DSGVO: minimal logging, keine sensiblen Inhalte
    """

    if g.current_user is None:
        return jsonify({"error": "Authentication required"}), 401

    data = request.validated_data

    patient_id = data["patient_id"]
    appointment_dt = data["date"]     # Marshmallow liefert datetime
    description = data["description"].strip()

    doctor_id = g.current_user["id"]

    # Optional TR-03161-Pro-Tipp (nicht zwingend):
    # Termin darf nicht in der Vergangenheit liegen.
    if appointment_dt < datetime.utcnow():
        return jsonify({"error": "Appointment date cannot be in the past"}), 400

    # Prüfen, ob Patient existiert
    try:
        patient = fetch_one("SELECT id FROM patients WHERE id = ?", (patient_id,))
    except sqlite3.Error:
        audit_log(doctor_id, "APPOINTMENT_CREATE_DB_ERROR", "Appointment", None, success=False)
        return jsonify({"error": "Database error"}), 500

    if patient is None:
        audit_log(doctor_id, "APPOINTMENT_CREATE_PATIENT_NOT_FOUND", "Appointment", patient_id, success=False)
        return jsonify({"error": "Patient not found"}), 404

    # Termin in DB speichern
    try:
        execute(
            """
            INSERT INTO appointments (patient_id, doctor_id, date, description)
            VALUES (?, ?, ?, ?)
            """,
            (patient_id, doctor_id, appointment_dt.isoformat(), description)
        )
    except sqlite3.Error:
        audit_log(doctor_id, "APPOINTMENT_CREATE_FAILED", "Appointment", patient_id, success=False)
        return jsonify({"error": "Failed to create appointment"}), 500

    audit_log(doctor_id, "APPOINTMENT_CREATE_SUCCESS", "Appointment", patient_id, success=True)

    return jsonify({
        "message": "Appointment created",
        "patient_id": patient_id,
        "doctor_id": doctor_id,
        "date": appointment_dt.isoformat(),
        "description": description
    }), 201
