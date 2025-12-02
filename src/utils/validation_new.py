# src/utils/validation_new.py
from functools import wraps
from flask import request, jsonify
from marshmallow import Schema, fields, ValidationError, validates


# ============================================================
# LOGIN SCHEMA
# ============================================================
class LoginSchema(Schema):
    username = fields.Str(required=True)
    password = fields.Str(required=True)


# ============================================================
# PATIENT SEARCH SCHEMA (via POST – unused optional)
# ============================================================
class PatientSearchSchema(Schema):
    name = fields.Str(required=False)
    mrn = fields.Str(required=False)
    date_of_birth = fields.Date(required=False)


# ============================================================
# PATIENT CREATE (optional, not yet implemented)
# ============================================================
class PatientCreateSchema(Schema):
    first_name = fields.Str(required=True)
    last_name = fields.Str(required=True)
    birthdate = fields.Date(required=True)
    mrn = fields.Str(required=True)
    diagnosis = fields.Str(required=False)


# ============================================================
# PATIENT UPDATE SCHEMA (doctor only)
# ============================================================
class PatientUpdateSchema(Schema):
    id = fields.Int(required=True)
    diagnosis = fields.Str(required=True)

    @validates("diagnosis")
    def validate_diag(self, value, **kwargs):
        if len(value.strip()) == 0:
            raise ValidationError("Diagnosis cannot be empty")


# ============================================================
# APPOINTMENT CREATE SCHEMA (doctor/nurse)
# ============================================================
class AppointmentCreateSchema(Schema):
    patient_id = fields.Int(required=True)
    date = fields.DateTime(required=True)
    description = fields.Str(required=True)

    @validates("description")
    def validate_description(self, value, **kwargs):
        if len(value.strip()) == 0:
            raise ValidationError("Description cannot be empty")


# ============================================================
# PATIENT SEARCH QUERY SCHEMA (GET /search?q=)
# ============================================================
class PatientSearchQuerySchema(Schema):
    q = fields.Str(required=True)

    @validates("q")
    def validate_query(self, value, **kwargs):
        value = value.strip()
        if len(value) == 0:
            raise ValidationError("Query cannot be empty")
        if len(value) > 50:
            raise ValidationError("Query too long (max 50 chars)")


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
# QUERY PARAM VALIDATOR for GET requests
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
