# src/api/appointments.py (VULNERABLE VERSION – kontrolliert)
from flask import Blueprint, jsonify, request, g
from database.db import fetch_one
from utils.security import require_role
from utils.logging_utils import audit_log
from utils.validation_new import validate_json, AppointmentCreateSchema
import sqlite3
import logging                       # [NEU – für Schwachstelle A]
from datetime import datetime

appointments_bp = Blueprint("appointments", __name__)

# UNSICHERE Log-Konfiguration
logging.basicConfig(level=logging.INFO)


@appointments_bp.route("/appointments/create", methods=["POST"])
@require_role(["doctor", "nurse"])
@validate_json(AppointmentCreateSchema)
def create_appointment():

    if g.current_user is None:
        return jsonify({"error": "Authentication required"}), 401

    data = request.validated_data

    patient_id = data["patient_id"]
    appointment_dt = data["date"]
    description = data["description"].strip()

    doctor_id = g.current_user["id"]

    # =========================================================
    # SCHWACHSTELLE A: SENSITIVE DATA LOGGING (DSGVO, TR-03161)
    # =========================================================
    # verletzt: Art. 5(1)(c,f) DSGVO – Datenminimierung & Integrität/Vertraulichkeit
    # verletzt: TR-03161 O.Source_3 – keine sensiblen Daten in Logs
    logging.info(f"[VULNERABLE LOG] Appointment for patient={patient_id}, description={description}")

    # ================================
    # Patient existiert?
    # ================================
    try:
        patient = fetch_one("SELECT id FROM patients WHERE id = ?", (patient_id,))
    except sqlite3.Error:
        audit_log(doctor_id, "APPOINTMENT_DB_ERROR", "Appointment", None, success=False)
        return jsonify({"error": "Database error"}), 500

    if patient is None:
        audit_log(doctor_id, "APPOINTMENT_PATIENT_NOT_FOUND", "Appointment", patient_id, success=False)
        return jsonify({"error": "Patient not found"}), 404

    # =========================================================
    # SCHWACHSTELLE B: SQL INJECTION (OWASP A03:2021, TR-03161)
    # =========================================================
    # Ursprünglich parameterisiert – jetzt absichtlich unsicher
    # verletzt: OWASP Top 10 Injection
    # verletzt: TR-03161 O.Source_2 – Escape/parametrisierte Queries
    unsafe_query = (
        f"INSERT INTO appointments (patient_id, doctor_id, date, description) "
        f"VALUES ({patient_id}, {doctor_id}, '{appointment_dt.isoformat()}', '{description}')"
    )

    try:
        con = sqlite3.connect("healthcare.db")
        cur = con.cursor()
        cur.execute(unsafe_query)    # <-- unsicher
        con.commit()
        con.close()
    except Exception as e:
        # generischer Fehler (okay)
        return jsonify({"error": "Failed to create appointment"}), 500

    audit_log(doctor_id, "APPOINTMENT_CREATED", "Appointment", patient_id, success=True)

    return jsonify({
        "message": "Appointment created",
        "patient_id": patient_id,
        "doctor_id": doctor_id,
        "date": appointment_dt.isoformat(),
        "description": description
    }), 201
