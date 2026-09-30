import sqlite3
import os
from werkzeug.security import generate_password_hash

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATABASE = os.path.join(BASE_DIR, "vectorspy.db")


def get_connection():
    return sqlite3.connect(DATABASE)


def init_database():
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )""")

    cursor.execute("""CREATE TABLE IF NOT EXISTS scans (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        target TEXT NOT NULL,
        scan_type TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )""")

    cursor.execute("""CREATE TABLE IF NOT EXISTS findings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_id INTEGER,
        source TEXT,
        target TEXT,
        finding TEXT,
        port INTEGER,
        service TEXT,
        version TEXT,
        severity TEXT,
        risk_score INTEGER,
        evidence TEXT,
        recommendation TEXT,
        FOREIGN KEY(scan_id) REFERENCES scans(id)
    )""")

    cursor.execute("""CREATE TABLE IF NOT EXISTS technologies (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        target TEXT NOT NULL,
        category TEXT,
        technology TEXT,
        version TEXT,
        risk TEXT,
        evidence TEXT,
        confidence INTEGER,
        recommendation TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )""")

    cursor.execute("PRAGMA table_info(scans)")
    scan_columns = [row[1] for row in cursor.fetchall()]
    if "user_id" not in scan_columns:
        cursor.execute("ALTER TABLE scans ADD COLUMN user_id INTEGER")

    cursor.execute("PRAGMA table_info(technologies)")
    tech_columns = [row[1] for row in cursor.fetchall()]
    for col, definition in [
        ("user_id", "INTEGER"),
        ("version", "TEXT"),
        ("evidence", "TEXT"),
        ("confidence", "INTEGER"),
        ("recommendation", "TEXT"),
    ]:
        if col not in tech_columns:
            cursor.execute(f"ALTER TABLE technologies ADD COLUMN {col} {definition}")

    cursor.execute("PRAGMA table_info(findings)")
    finding_columns = [row[1] for row in cursor.fetchall()]
    for col, definition in [
        ("source", "TEXT"),
        ("target", "TEXT"),
        ("finding", "TEXT"),
        ("evidence", "TEXT"),
        ("recommendation", "TEXT"),
    ]:
        if col not in finding_columns:
            cursor.execute(f"ALTER TABLE findings ADD COLUMN {col} {definition}")

    cursor.execute("SELECT COUNT(*) FROM users")
    if cursor.fetchone()[0] == 0:
        cursor.execute(
            "INSERT INTO users (username, password_hash) VALUES (?, ?)",
            ("admin", generate_password_hash("VectorSpy@2026"))
        )

    cursor.execute("SELECT id FROM users WHERE username='admin' LIMIT 1")
    legacy_user = cursor.fetchone()
    if not legacy_user:
        cursor.execute("SELECT id FROM users ORDER BY id LIMIT 1")
        legacy_user = cursor.fetchone()

    if legacy_user:
        uid = legacy_user[0]
        cursor.execute("UPDATE scans SET user_id=? WHERE user_id IS NULL", (uid,))
        cursor.execute("UPDATE technologies SET user_id=? WHERE user_id IS NULL", (uid,))

    conn.commit()
    conn.close()


def create_user(username, password):
    username = username.strip()
    if not username or not password:
        return None
    conn = get_connection()
    try:
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO users (username, password_hash) VALUES (?, ?)",
            (username, generate_password_hash(password))
        )
        user_id = cursor.lastrowid
        conn.commit()
        return user_id
    except sqlite3.IntegrityError:
        return None
    finally:
        conn.close()


def get_user_by_username(username):
    conn = get_connection()
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT id, username, password_hash, created_at FROM users WHERE username=?", (username.strip(),))
    user = cursor.fetchone()
    conn.close()
    return user


def get_user_by_id(user_id):
    conn = get_connection()
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT id, username, password_hash, created_at FROM users WHERE id=?", (user_id,))
    user = cursor.fetchone()
    conn.close()
    return user


def create_scan(user_id, target, scan_type):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("INSERT INTO scans (user_id, target, scan_type) VALUES (?, ?, ?)", (user_id, target, scan_type))
    scan_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return scan_id


def save_finding(scan_id, port, service, version, severity, risk_score, recommendation):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT target FROM scans WHERE id=?", (scan_id,))
    row = cursor.fetchone()
    target = row[0] if row else ""
    cursor.execute("""INSERT INTO findings
        (scan_id, source, target, finding, port, service, version, severity, risk_score, evidence, recommendation)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (scan_id, "Nmap", target, f"{service} service on port {port}", port, service, version,
         severity, risk_score, f"{port}/tcp open", recommendation))
    conn.commit()
    conn.close()


def save_web_finding(scan_id, target, finding, severity, risk_score, evidence, recommendation):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""INSERT INTO findings
        (scan_id, source, target, finding, port, service, version, severity, risk_score, evidence, recommendation)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (scan_id, "Web Security", target, finding, None, "", "", severity, risk_score, evidence, recommendation))
    conn.commit()
    conn.close()


def save_subdomain_finding(scan_id, target, subdomain, ip_address, status):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""INSERT INTO findings
        (scan_id, source, target, finding, port, service, version, severity, risk_score, evidence, recommendation)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (scan_id, "Subdomain Finder", target, f"Subdomain discovered: {subdomain}", None, "", "",
         "Low", 2, f"IP: {ip_address}; Status: {status}",
         "Review the subdomain and restrict exposure if it is not required."))
    conn.commit()
    conn.close()


def save_technology_finding(scan_id, target, category, technology, version, risk, evidence, recommendation):
    score = {"Critical": 10, "High": 8, "Medium": 5, "Low": 2}.get(risk, 0)
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""INSERT INTO findings
        (scan_id, source, target, finding, port, service, version, severity, risk_score, evidence, recommendation)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (scan_id, "Technology Finder", target, f"{category}: {technology}", None, "", version,
         risk, score, evidence, recommendation))
    conn.commit()
    conn.close()


def save_technology(user_id, target, category, technology, version, risk, evidence, recommendation, confidence=70):
    confidence = max(0, min(100, int(confidence)))
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""INSERT INTO technologies
        (user_id, target, category, technology, version, risk, evidence, confidence, recommendation)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (user_id, target, category, technology, version, risk, evidence, confidence, recommendation))
    conn.commit()
    conn.close()


def get_scan_history(user_id):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""SELECT id, target, scan_type,
        datetime(created_at, 'localtime') AS created_at
        FROM scans WHERE user_id=? ORDER BY id DESC""", (user_id,))
    rows = cursor.fetchall()
    conn.close()
    return rows


def get_all_findings(user_id):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""SELECT
        findings.id, findings.source, findings.target, findings.finding,
        findings.port, findings.service, findings.version, findings.severity,
        findings.risk_score, findings.evidence, findings.recommendation,
        datetime(scans.created_at, 'localtime') AS created_at
        FROM findings LEFT JOIN scans ON findings.scan_id=scans.id
        WHERE scans.user_id=? ORDER BY findings.id DESC""", (user_id,))
    rows = cursor.fetchall()
    conn.close()
    return rows


def get_dashboard_stats(user_id):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM scans WHERE user_id=?", (user_id,))
    total_scans = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM findings f JOIN scans s ON f.scan_id=s.id WHERE s.user_id=?", (user_id,))
    total_findings = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM findings f JOIN scans s ON f.scan_id=s.id WHERE s.user_id=? AND f.source='Nmap'", (user_id,))
    total_open_ports = cursor.fetchone()[0]
    cursor.execute("SELECT f.severity, COUNT(*) FROM findings f JOIN scans s ON f.scan_id=s.id WHERE s.user_id=? GROUP BY f.severity", (user_id,))
    risk_distribution = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for severity, count in cursor.fetchall():
        if severity in risk_distribution:
            risk_distribution[severity] = count
    cursor.execute("SELECT MAX(f.risk_score) FROM findings f JOIN scans s ON f.scan_id=s.id WHERE s.user_id=?", (user_id,))
    max_risk = cursor.fetchone()[0]
    if max_risk is None:
        risk_level = "No Data"
    elif max_risk >= 9:
        risk_level = "Critical"
    elif max_risk >= 7:
        risk_level = "High"
    elif max_risk >= 4:
        risk_level = "Medium"
    else:
        risk_level = "Low"
    conn.close()
    return {"total_scans": total_scans, "total_open_ports": total_open_ports, "total_findings": total_findings,
            "risk_level": risk_level, "risk_distribution": risk_distribution}


def get_technology_history(user_id):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""SELECT id, target, category, technology, version, risk, evidence,
        confidence, recommendation, datetime(created_at, 'localtime') AS created_at
        FROM technologies WHERE user_id=? ORDER BY id DESC""", (user_id,))
    rows = cursor.fetchall()
    conn.close()
    return rows


def get_findings_by_scan(scan_id, user_id):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""SELECT f.id, f.source, f.target, f.finding, f.port, f.service,
        f.version, f.severity, f.risk_score, f.evidence, f.recommendation
        FROM findings f JOIN scans s ON f.scan_id=s.id
        WHERE f.scan_id=? AND s.user_id=? ORDER BY f.id DESC""", (scan_id, user_id))
    rows = cursor.fetchall()
    conn.close()
    return rows


def delete_scan(scan_id, user_id):
    conn = get_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT id FROM scans WHERE id=? AND user_id=?", (scan_id, user_id))
        if not cursor.fetchone():
            return False
        cursor.execute("DELETE FROM findings WHERE scan_id=?", (scan_id,))
        cursor.execute("DELETE FROM scans WHERE id=? AND user_id=?", (scan_id, user_id))
        deleted = cursor.rowcount
        conn.commit()
        return deleted > 0
    except Exception:
        conn.rollback()
        return False
    finally:
        conn.close()
