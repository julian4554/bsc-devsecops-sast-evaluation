# src/api/patient.py (VULNERABLE VERSION)
from flask import Blueprint, request, jsonify, g
from database.db import execute, fetch_one
import traceback  # Nötig für A10 Schwachstelle

patient_bp = Blueprint("patient", "__name__")


# ============================================================
# GET /patient/<id>
# ============================================================
@patient_bp.route("/patient/<int:patient_id>", methods=["GET"])
def get_patient(patient_id):
    """
    VULNERABLE ENDPOINT: Fokus A10

    Schwachstelle:
    - A10:2025 Mishandling of Exceptional Conditions (CWE-209)
      Wir geben bei Fehlern interne Systemdetails (Stacktrace) preis.
    """

    # Authentifizierung (Rudimentär, damit der Flow funktioniert)
    if not g.current_user:
        return jsonify({"error": "Auth required"}), 401

    try:
        # SQL ist hier SICHER (Parameter Binding), damit wir keine
        # SQL-Injection-Findings provozieren, die das Ergebnis verwässern.
        patient = fetch_one("SELECT * FROM patients WHERE id = ?", (patient_id,))

        if not patient:
            return jsonify({"error": "Not found"}), 404

        return jsonify(dict(patient)), 200

    except Exception as e:
        # =========================================================
        # [X] SCHWACHSTELLE: A10 (Mishandling of Exceptional Conditions)
        # =========================================================
        # CWE-209: Generation of Error Message Containing Sensitive Information
        # Wir geben den vollen Stacktrace und Library-Versionen aus.
        return jsonify({
            "status": "error",
            "exception": type(e).__name__,
            "trace": traceback.format_exc()  # <--- Verrät Code-Pfad & Interna
        }), 500


# ============================================================
# POST /patient/update
# ============================================================
@patient_bp.route("/patient/update", methods=["POST"])
def update_patient():
    """
    VULNERABLE ENDPOINT: Fokus A08

    Schwachstelle:
    - A08:2025 Software and Data Integrity Failures (Mass Assignment / CWE-915)
      Benutzer können schreibgeschützte Felder (mrn, id) überschreiben.
    """

    if not g.current_user:
        return jsonify({"error": "Auth required"}), 401

    try:
        # Input: Raw JSON ohne Schema-Validierung
        data = request.get_json(silent=True) or {}
        p_id = data.get("id")

        if not p_id:
            raise ValueError("Missing Patient ID")

        # =========================================================
        # [X] SCHWACHSTELLE: A08 (Mass Assignment)
        # =========================================================
        # DSGVO Art. 5 (Integrität): Daten werden ungeprüft übernommen.
        # Wir filtern die Keys NICHT gegen eine Allowlist.
        # Angreifer sendet: {"id": 1, "diagnosis": "...", "mrn": "FAKE-123"}

        # Dynamischer Query-Bau basierend auf User-Input-Keys
        columns = [k for k in data.keys() if k != "id"]

        if not columns:
            return jsonify({"message": "Nothing to update"}), 200

        # Parameter Binding nutzen wir trotzdem (um SQLi Findings zu vermeiden)
        # Das Tool soll den LOGIK-Fehler (Mass Assignment) finden, nicht Syntax-Fehler.
        set_clause = ", ".join([f"{col} = ?" for col in columns])
        values = [data[col] for col in columns]
        values.append(p_id)

        query = f"UPDATE patients SET {set_clause} WHERE id = ?"

        execute(query, tuple(values))

        return jsonify({
            "message": "Patient updated",
            "updated_fields": columns  # Beweis für den Angreifer, was geklappt hat
        }), 200

    except Exception as e:
        # Auch hier: A10 (Info Leak)
        return jsonify({
            "error": "Update failed",
            "debug_trace": traceback.format_exc()
        }), 500