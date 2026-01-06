# db_helpers.py
import os
import json
import sqlite3
from datetime import datetime

DB_PATH = os.getenv("RISK_DB_PATH", "./risk.db")


# ------------------------------------------------------------
# Connection
# ------------------------------------------------------------
def _get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


# ------------------------------------------------------------
# INIT DATABASE
# ------------------------------------------------------------
def init_db():
    conn = _get_conn()
    cur = conn.cursor()

    # SMEs
    cur.execute("""
    CREATE TABLE IF NOT EXISTS smes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        industry TEXT,
        size TEXT,
        business_type TEXT DEFAULT 'Other',
        data_sensitivity TEXT DEFAULT 'Low',
        it_dependency TEXT DEFAULT 'Low',
        website TEXT,
        contact_email TEXT,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
    );
    """)

    # Manual assessments
    cur.execute("""
    CREATE TABLE IF NOT EXISTS manual_assessments (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        sme_id INTEGER NOT NULL,
        score_json TEXT NOT NULL,
        created_at TEXT NOT NULL
    );
    """)

    # Scan runs
    cur.execute("""
    CREATE TABLE IF NOT EXISTS scan_runs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        sme_id INTEGER,
        user_id INTEGER,
        target_url TEXT NOT NULL,
        summary_json TEXT NOT NULL,
        base_score REAL DEFAULT 0,
        final_score REAL DEFAULT 0,
        risk_level TEXT DEFAULT 'Low',
        business_type_multiplier REAL DEFAULT 1.0,
        data_sensitivity_multiplier REAL DEFAULT 1.0,
        it_dependency_multiplier REAL DEFAULT 1.0,
        created_at TEXT NOT NULL
    );
    """)

    # Scan findings
    cur.execute("""
    CREATE TABLE IF NOT EXISTS scan_findings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_run_id INTEGER NOT NULL,
        title TEXT NOT NULL,
        owasp_category TEXT NOT NULL,
        severity TEXT NOT NULL,
        confidence TEXT NOT NULL,
        uri TEXT,
        raw_json TEXT
    );
    """)

    conn.commit()
    conn.close()


# ------------------------------------------------------------
# SME CRUD
# ------------------------------------------------------------
def create_sme(data: dict) -> int:
    conn = _get_conn()
    cur = conn.cursor()
    now = datetime.utcnow().isoformat()

    cur.execute("""
        INSERT INTO smes
        (name, industry, size, business_type, data_sensitivity, it_dependency, website, contact_email, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        data["name"],
        data.get("industry"),
        data.get("size"),
        data.get("business_type", "Other"),
        data.get("data_sensitivity", "Low"),
        data.get("it_dependency", "Low"),
        data.get("website"),
        data.get("contact_email"),
        now,
        now
    ))

    conn.commit()
    sme_id = cur.lastrowid
    conn.close()
    return sme_id


def list_smes():
    conn = _get_conn()
    cur = conn.cursor()
    cur.execute("SELECT * FROM smes ORDER BY created_at DESC")
    rows = cur.fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_sme(sme_id: int):
    conn = _get_conn()
    cur = conn.cursor()
    cur.execute("SELECT * FROM smes WHERE id = ?", (int(sme_id),))
    row = cur.fetchone()
    conn.close()
    return dict(row) if row else None


def update_sme(sme_id: int, data: dict):
    conn = _get_conn()
    cur = conn.cursor()
    now = datetime.utcnow().isoformat()

    cur.execute("""
        UPDATE smes
        SET name=?, industry=?, size=?, business_type=?,
            data_sensitivity=?, it_dependency=?,
            website=?, contact_email=?, updated_at=?
        WHERE id=?
    """, (
        data["name"],
        data.get("industry"),
        data.get("size"),
        data.get("business_type", "Other"),
        data.get("data_sensitivity", "Low"),
        data.get("it_dependency", "Low"),
        data.get("website"),
        data.get("contact_email"),
        now,
        int(sme_id)
    ))

    conn.commit()
    conn.close()


# ------------------------------------------------------------
# MANUAL ASSESSMENT
# ------------------------------------------------------------
def save_manual_assessment(sme_id: int, answers: dict, result: dict) -> int:
    conn = _get_conn()
    cur = conn.cursor()

    cur.execute("""
        INSERT INTO manual_assessments
        (sme_id, score_json, created_at)
        VALUES (?, ?, ?)
    """, (
        sme_id,
        json.dumps({"answers": answers, "result": result}),
        datetime.utcnow().isoformat()
    ))

    conn.commit()
    assessment_id = cur.lastrowid
    conn.close()
    return assessment_id


# ------------------------------------------------------------
# SCAN STORAGE
# ------------------------------------------------------------
def save_scan_run(sme_id: int, user_id: int, target_url: str, summary: dict, score_data: dict = None) -> int:
    """
    Save scan run with optional score data
    
    Args:
        sme_id: SME profile ID
        user_id: User who performed the scan
        target_url: Target URL scanned
        summary: Summary statistics
        score_data: Optional dict with base_score, final_score, risk_level, multipliers
    """
    conn = _get_conn()
    cur = conn.cursor()
    
    # Extract score data if provided
    base_score = 0
    final_score = 0
    risk_level = "Low"
    business_mult = 1.0
    data_sens_mult = 1.0
    it_dep_mult = 1.0
    
    if score_data:
        base_score = score_data.get("base_score", 0)
        final_score = score_data.get("final_score", 0)
        risk_level = score_data.get("risk_level", "Low")
        business_mult = score_data.get("business_type_multiplier", 1.0)
        data_sens_mult = score_data.get("data_sensitivity_multiplier", 1.0)
        it_dep_mult = score_data.get("it_dependency_multiplier", 1.0)

    cur.execute("""
        INSERT INTO scan_runs
        (sme_id, user_id, target_url, summary_json, base_score, final_score, risk_level,
         business_type_multiplier, data_sensitivity_multiplier, it_dependency_multiplier, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        sme_id,
        user_id,
        target_url,
        json.dumps(summary),
        base_score,
        final_score,
        risk_level,
        business_mult,
        data_sens_mult,
        it_dep_mult,
        datetime.utcnow().isoformat()
    ))

    conn.commit()
    run_id = cur.lastrowid
    conn.close()
    return run_id


def save_scan_finding(scan_run_id: int, finding: dict):
    conn = _get_conn()
    cur = conn.cursor()

    cur.execute("""
        INSERT INTO scan_findings
        (scan_run_id, title, owasp_category, severity, confidence, uri, raw_json)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (
        scan_run_id,
        finding["title"],
        finding["owasp"],
        finding["severity"],
        finding["confidence"],
        finding.get("uri"),
        json.dumps(finding)
    ))

    conn.commit()
    conn.close()


def get_user_scan_history(user_id: int, limit: int = 50):
    """Get scan history for a specific user"""
    conn = _get_conn()
    cur = conn.cursor()
    
    cur.execute("""
        SELECT * FROM scan_runs 
        WHERE user_id = ? 
        ORDER BY created_at DESC 
        LIMIT ?
    """, (user_id, limit))
    
    rows = cur.fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_all_scan_history(limit: int = 100):
    """Get all scan history for admin view"""
    conn = _get_conn()
    cur = conn.cursor()
    
    cur.execute("""
        SELECT * FROM scan_runs 
        ORDER BY created_at DESC 
        LIMIT ?
    """, (limit,))
    
    rows = cur.fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_scan_report(scan_run_id: int):
    conn = _get_conn()
    cur = conn.cursor()

    cur.execute("SELECT * FROM scan_runs WHERE id = ?", (scan_run_id,))
    run = cur.fetchone()

    cur.execute(
        "SELECT * FROM scan_findings WHERE scan_run_id = ?",
        (scan_run_id,)
    )
    findings = cur.fetchall()

    conn.close()
    return {
        "run": dict(run) if run else None,
        "findings": [dict(f) for f in findings],
    }
