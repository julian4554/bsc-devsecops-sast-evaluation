# src/api/fhir.py
from flask import Blueprint, jsonify, g
from database.db import fetch_one
from utils.security import require_role
from utils.logging_utils import audit_log

fhir_bp = Blueprint("fhir", __name__)


@fhir_bp.route("/fhir/Patient/<int:patient_id>", methods=["GET"])
@require_role(["doctor", "nurse"])
def get_fhir_patient(patient_id):
    """
    Healthcare-SAFE FHIR Patient Endpoint
    -------------------------------------
    DSGVO / TR-03161:
    - Minimalprinzip: nur MRN, Name, Geburtsdatum
    - Keine Diagnose, keine Versicherungsnummer, keine Notizen
    - RBAC: doctor & nurse
    - Keine detaillierten Fehlermeldungen
    """

    user = g.current_user

    # "Need-to-know" – Admin darf keine klinischen Daten sehen
    if user["role"] == "admin":
        return jsonify({"error": "Not permitted"}), 403

    # Patient aus DB abrufen
    row = fetch_one(
        """
        SELECT id, first_name, last_name, birthdate, mrn
        FROM patients
        WHERE id = ?
        """,
        (patient_id,)
    )

    if row is None:
        audit_log(user["id"], "FHIR_PATIENT_READ_NOT_FOUND", "Patient", patient_id, success=False)
        return jsonify({"error": "Patient not found"}), 404

    # Minimaler FHIR Patient (DSGVO Art. 5 – Datenminimierung)
    fhir_patient = {
        "resourceType": "Patient",
        "id": str(row["id"]),
        "name": [{
            "text": f"{row['first_name']} {row['last_name']}"
        }],
        "birthDate": row["birthdate"],
        "identifier": [
            {
                "system": "urn:mrn",
                "value": row["mrn"]
            }
        ]
    }

    audit_log(user["id"], "FHIR_PATIENT_READ_SUCCESS", "Patient", patient_id, success=True)

    return jsonify(fhir_patient), 200
