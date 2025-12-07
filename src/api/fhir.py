# src/api/fhir.py (VULNERABLE VERSION)
from flask import Blueprint, jsonify, g
from database.db import fetch_one
from utils.security import require_role
from utils.logging_utils import audit_log

fhir_bp = Blueprint("fhir", __name__)


@fhir_bp.route("/fhir/Patient/<int:patient_id>", methods=["GET"])
@require_role(["doctor", "nurse"])
def get_fhir_patient(patient_id):
    """
    VULNERABLE FHIR Patient Endpoint (OWASP 2025 A01)
    Enthält zwei Schwachstellen, beide korrekt klassifiziert unter:
    A01: Broken Access Control
    --------------------------------------------------------------
    - FHIR-1: Excessive Data Exposure (unauthorized attributes exposed)
    - FHIR-2: Missing Access Control / IDOR (record ownership ignored)
    """

    user = g.current_user

    # Admin hat weiterhin keinen Zugriff
    if user["role"] == "admin":
        return jsonify({"error": "Not permitted"}), 403

    # =============================================================
    # SCHWACHSTELLE FHIR-2: IDOR / Missing Access Control
    # =============================================================
    # Keine Prüfung, ob der Benutzer berechtigt ist, diesen Patienten
    # einzusehen (Record Ownership Violation).
    #
    # OWASP 2025 A01 – Broken Access Control
    # - "Permitting viewing someone else's data"
    # - "Missing object-level access control"
    # DSGVO Art. 32
    # TR-03161 O.Auth_2 Need-to-know-Principle
    # =============================================================

    row = fetch_one(
        """
        SELECT id, first_name, last_name, birthdate, mrn,
               diagnosis, insurance_number, address
        FROM patients
        WHERE id = ?
        """,
        (patient_id,)
    )

    if row is None:
        audit_log(user["id"], "FHIR_PATIENT_NOT_FOUND", "Patient", patient_id, success=False)
        return jsonify({"error": "Patient not found"}), 404

    # =============================================================
    # SCHWACHSTELLE FHIR-1: Excessive Data Exposure (A01)
    # =============================================================
    # Exponiert unnötige, hochsensible FHIR-Felder (diagnosis, address,
    # insurance number). Dies ist kein "Crypto Problem" sondern ein
    # Zugriffskontrollproblem:
    #
    # - Das API gibt Daten zurück, die der Benutzer NICHT sehen darf.
    # - Fehlende Attributautorisierung (Attribute-based Access Control).
    #
    # OWASP 2025 A01 – Broken Access Control:
    # - CWE-200 (Sensitive Data Exposure to Unauthorized Actor)
    # - CWE-201 (Exposure Through Sent Data)
    # - Overly permissive object responses
    #
    # DSGVO Art. 5(1)(c) Datenminimierung
    # DSGVO Art. 9 Besondere Kategorien (Gesundheitsdaten)
    # TR-03161 O.Source_3 – keine sensiblen Daten in Responses
    # =============================================================

    fhir_patient = {
        "resourceType": "Patient",
        "id": str(row["id"]),
        "name": [{
            "text": f"{row['first_name']} {row['last_name']}",
            "family": row["last_name"],
            "given": [row["first_name"]]
        }],
        "birthDate": row["birthdate"],
        "identifier": [
            {"system": "urn:mrn", "value": row["mrn"]},
            {"system": "urn:insurance", "value": row["insurance_number"]}  # sensitive
        ],
        "extension": [
            {"url": "urn:diagnosis", "valueString": row["diagnosis"]},
            {"url": "urn:address", "valueString": row["address"]}
        ]
    }

    audit_log(user["id"], "FHIR_PATIENT_READ_SUCCESS", "Patient", patient_id, success=True)
    return jsonify(fhir_patient), 200
