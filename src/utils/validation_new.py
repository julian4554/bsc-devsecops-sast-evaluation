from functools import wraps
from flask import request, jsonify
from marshmallow import Schema, fields, ValidationError, validates
from marshmallow.validate import Length, And, Regexp


# ============================================================
# LOGIN SCHEMA
# ============================================================
class LoginSchema(Schema):
    username = fields.Str(required=True, validate=Length(min=1, max=100))
    password = fields.Str(required=True, validate=Length(min=1, max=200))


# ============================================================
# PASSWORD UPDATE SCHEMA (NEU: für O.Pass_1)
# ============================================================
class PasswordUpdateSchema(Schema):
    # Altes Passwort für Re-Authentifizierung (O.Auth_11)
    current_password = fields.Str(required=True)

    # Neues Passwort mit BSI-konformen Regeln (O.Pass_1)
    new_password = fields.Str(
        required=True,
        validate=And(
            Length(min=12, max=128, error="Passwort muss mind. 12 Zeichen lang sein."),
            Regexp(r".*[A-Z].*", error="Muss einen Großbuchstaben enthalten."),
            Regexp(r".*[a-z].*", error="Muss einen Kleinbuchstaben enthalten."),
            Regexp(r".*[0-9].*", error="Muss eine Zahl enthalten."),
            Regexp(r".*[^A-Za-z0-9].*", error="Muss ein Sonderzeichen enthalten.")
        )
    )

    confirm_password = fields.Str(required=True)

    @validates("confirm_password")
    def validate_match(self, value, **kwargs):
        if request.get_json().get("new_password") != value:
            raise ValidationError("Passwörter stimmen nicht überein.")
# ============================================================
# PATIENT SEARCH SCHEMA (POST – optional)
# ============================================================
class PatientSearchSchema(Schema):
    name = fields.Str(required=False, validate=Length(max=100))
    mrn = fields.Str(required=False, validate=Length(max=50))
    date_of_birth = fields.Date(required=False)


# ============================================================
# PATIENT CREATE (not yet implemented)
# ============================================================
class PatientCreateSchema(Schema):
    first_name = fields.Str(required=True, validate=Length(min=1, max=100))
    last_name = fields.Str(required=True, validate=Length(min=1, max=100))
    birthdate = fields.Date(required=True)
    mrn = fields.Str(required=True, validate=Length(min=1, max=50))
    diagnosis = fields.Str(required=False, validate=Length(max=500))


# ============================================================
# PATIENT UPDATE (doctor only)
# ============================================================
class PatientUpdateSchema(Schema):
    id = fields.Int(required=True)
    diagnosis = fields.Str(required=True, validate=Length(min=1, max=500))

    @validates("diagnosis")
    def validate_diag(self, value, **kwargs):
        if len(value.strip()) == 0:
            raise ValidationError("Diagnosis cannot be empty")
        # Healthcare-safe input length (TR-03161 recommends bounded inputs)
        if len(value.strip()) > 500:
            raise ValidationError("Diagnosis too long")


# ============================================================
# APPOINTMENT CREATE (doctor/nurse)
# ============================================================
class AppointmentCreateSchema(Schema):
    patient_id = fields.Int(required=True)
    date = fields.DateTime(required=True)
    description = fields.Str(required=True, validate=Length(min=1, max=500))

    @validates("description")
    def validate_description(self, value, **kwargs):
        if len(value.strip()) == 0:
            raise ValidationError("Description cannot be empty")


# ============================================================
# PATIENT SEARCH QUERY (GET /search?q=)
# ============================================================
class PatientSearchQuerySchema(Schema):
    q = fields.Str(required=True, validate=Length(min=1, max=50))

    @validates("q")
    def validate_query(self, value, **kwargs):
        if len(value.strip()) == 0:
            raise ValidationError("Query cannot be empty")


# ============================================================
# JSON BODY VALIDATOR for POST/PUT/PATCH
# ============================================================
def validate_json(schema_cls):
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            json_data = request.get_json(silent=True)
            if json_data is None:
                return jsonify({"error": "Invalid or missing JSON"}), 400

            schema = schema_cls()
            try:
                validated = schema.load(json_data)
            except ValidationError as e:
                return jsonify({
                    "error": "Validation failed",
                    "details": e.messages
                }), 400

            request.validated_data = validated
            return fn(*args, **kwargs)
        return wrapper
    return decorator


# ============================================================
# QUERY PARAM VALIDATOR for GET
# ============================================================
def validate_query(schema_cls):
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            schema = schema_cls()
            try:
                validated = schema.load(request.args.to_dict(flat=True))
            except ValidationError as e:
                return jsonify({
                    "error": "Invalid query parameters",
                    "details": e.messages
                }), 400

            request.validated_params = validated
            return fn(*args, **kwargs)
        return wrapper
    return decorator
