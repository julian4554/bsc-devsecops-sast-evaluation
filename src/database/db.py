# src/database/db.py
import sqlite3
from pathlib import Path

DB_PATH = Path(__file__).resolve().parent.parent / "healthcare.db"

def get_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def fetch_one(query, params=()):
    conn = get_connection()
    cur = conn.execute(query, params)
    row = cur.fetchone()
    conn.close()
    return row

def fetch_all(query, params=()):
    conn = get_connection()
    cur = conn.execute(query, params)
    rows = cur.fetchall()
    conn.close()
    return rows

def execute(query, params=()):
    conn = get_connection()
    conn.execute(query, params)
    conn.commit()
    conn.close()
