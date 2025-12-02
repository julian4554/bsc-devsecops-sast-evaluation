# src/utils/logging_utils.py
from datetime import datetime
from database.db import execute


def audit_log(user_id, action: str, resource_type: str = None, resource_id: int = None, success: bool = True):
    """
    Audit-Logging für sicherheitsrelevante Ereignisse.

    WICHTIG:
    - Es werden KEINE fachlichen Inhalte (Diagnosen, Freitexte, FHIR-Payloads etc.) geloggt.
    - Nur Metadaten:
      * wer (user_id)
      * was (action)
      * welches Objekt (resource_type, resource_id)
      * wann (timestamp, UTC)
      * Erfolg/Misserfolg

    Damit wird das Prinzip der Datenminimierung (Art. 5 DSGVO) eingehalten
    und gleichzeitig die Nachvollziehbarkeit (BSI TR-03161) unterstützt.
    """

    timestamp = datetime.utcnow().isoformat()

    execute(
        """
        INSERT INTO audit_logs (timestamp, user_id, action, resource_type, resource_id, success)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            timestamp,
            user_id,
            action,
            resource_type,
            resource_id,
            1 if success else 0
        )
    )
