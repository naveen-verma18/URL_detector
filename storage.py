"""
SQLite storage helpers for upload history and status tracking.

DB: data/uploads.db
Table: uploads
  - upload_id TEXT PRIMARY KEY
  - filename TEXT
  - uploaded_at TEXT (ISO)
  - total_urls INTEGER
  - malicious_count INTEGER
  - summary_json_path TEXT
  - results_json_path TEXT
  - status TEXT  (in_progress | parsing | predicting | completed | failed:msg)
"""

from pathlib import Path
import sqlite3
from typing import Tuple, List, Dict

PROJECT_ROOT = Path(__file__).resolve().parent
DATA_DIR = PROJECT_ROOT / "data"
DB_PATH = DATA_DIR / "uploads.db"

def _connect():
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with _connect() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS uploads (
                upload_id TEXT PRIMARY KEY,
                filename TEXT,
                uploaded_at TEXT,
                total_urls INTEGER,
                malicious_count INTEGER,
                summary_json_path TEXT,
                results_json_path TEXT,
                status TEXT
            )
            """
        )
        conn.commit()

def insert_upload(
    upload_id: str,
    filename: str,
    uploaded_at: str,
    total_urls: int,
    malicious_count: int,
    summary_json_path: str,
    results_json_path: str,
    status: str,
):
    with _connect() as conn:
        conn.execute(
            """
            INSERT INTO uploads (upload_id, filename, uploaded_at, total_urls,
                malicious_count, summary_json_path, results_json_path, status)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                upload_id,
                filename,
                uploaded_at,
                total_urls,
                malicious_count,
                summary_json_path,
                results_json_path,
                status,
            ),
        )
        conn.commit()

def update_upload_status(upload_id: str, status: str):
    with _connect() as conn:
        conn.execute("UPDATE uploads SET status=? WHERE upload_id= ?", (status, upload_id))
        conn.commit()

def update_upload_counts_and_paths(
    upload_id: str,
    total_urls: int,
    malicious_count: int,
    summary_json_path: str,
    results_json_path: str,
    status: str,
):
    with _connect() as conn:
        conn.execute(
            """
            UPDATE uploads
               SET total_urls=?,
                   malicious_count=?,
                   summary_json_path=?,
                   results_json_path=?,
                   status=?
             WHERE upload_id=?
            """,
            (
                total_urls,
                malicious_count,
                summary_json_path,
                results_json_path,
                status,
                upload_id,
            ),
        )
        conn.commit()

def get_upload(upload_id: str) -> Dict | None:
    with _connect() as conn:
        cur = conn.execute("SELECT * FROM uploads WHERE upload_id=?", (upload_id,))
        row = cur.fetchone()
        return dict(row) if row else None

def list_uploads(page: int = 1, page_size: int = 10) -> Tuple[List[Dict], int]:
    offset = (page - 1) * page_size
    with _connect() as conn:
        cur = conn.execute("SELECT COUNT(*) as c FROM uploads")
        total = cur.fetchone()["c"]
        cur2 = conn.execute(
            "SELECT * FROM uploads ORDER BY uploaded_at DESC LIMIT ? OFFSET ?",
            (page_size, offset),
        )
        items = [dict(r) for r in cur2.fetchall()]
        return items, total
