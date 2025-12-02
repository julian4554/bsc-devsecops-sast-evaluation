-- src/database/seed_data.sql

INSERT INTO users (username, password, role)
VALUES
('admin', 'TEMP', 'admin'),
('doctor1', 'TEMP', 'doctor'),
('nurse1',  'TEMP', 'nurse');

INSERT INTO patients (first_name, last_name, birthdate, mrn, diagnosis)
VALUES
('John', 'Doe', '1980-03-15', 'MRN-1001', 'Diabetes Type 2'),
('Maria', 'Rossi', '1975-07-09', 'MRN-1002', 'Hypertension'),
('Ali', 'Yilmaz', '1990-12-21', 'MRN-1003', 'Asthma');

INSERT INTO appointments (patient_id, doctor_id, date, description)
VALUES
(1, 2, '2025-12-20T10:00:00Z', 'Routine check'),
(2, 2, '2025-12-21T14:00:00Z', 'Blood pressure review'),
(3, 2, '2025-12-22T09:30:00Z', 'Asthma follow-up');
