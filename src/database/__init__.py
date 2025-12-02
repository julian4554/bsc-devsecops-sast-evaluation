# src/database/init_db.py
# ============================================================
# HEALTHCARE-SAFE DATABASE INITIALIZER (NO CIRCULAR IMPORTS)
# ============================================================

import sqlite3
from pathlib import Path
import sys

# Ensure /src is importable
ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
    print(f"[INIT] Added to PYTHONPATH: {ROOT}")

from utils.security import hash_password
from database.db import execute

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR.parent / "healthcare.db"

CREATE_TABLES_PATH = BASE_DIR / "create_tables.sql"
SEED_DATA_PATH = BASE_DIR / "seed_data.sql"


def seed_users_secure():
    print("[*] Seeding secure PBKDF2 passwords...")

    users = [
        ("admin", "Admin123!"),
        ("doctor1", "Doctor123!"),
        ("nurse1", "Nurse123!")
    ]

    for username, pw in users:
        hashed = hash_password(pw)
        execute("UPDATE users SET password = ? WHERE username = ?", (hashed, username))
        print(f"[+] Secured user: {username}")


def init_db():
    print("===========================================")
    print("  HEALTHCARE-SAFE DATABASE INITIALIZATION  ")
    print("===========================================\n")

    if DB_PATH.exists():
        DB_PATH.unlink()
        print("[+] Existing database removed.")

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    with open(CREATE_TABLES_PATH, "r", encoding="utf-8") as f:
        cursor.executescript(f.read())
        print("[+] Tables created.")

    with open(SEED_DATA_PATH, "r", encoding="utf-8") as f:
        cursor.executescript(f.read())
        print("[+] Seed data inserted.")

    conn.commit()
    conn.close()

    seed_users_secure()

    print("\n[✔] Healthcare database ready.\n")


if __name__ == "__main__":
    init_db()
