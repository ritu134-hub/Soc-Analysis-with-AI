import sqlite3
import os
import json
from datetime import datetime

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "soc_database.db")

def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()

    # Raw logs table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS raw_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            source TEXT NOT NULL,
            level TEXT NOT NULL,
            message TEXT NOT NULL,
            raw_data TEXT
        )
    ''')

    # Security events table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS security_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_id TEXT UNIQUE NOT NULL,
            timestamp TEXT NOT NULL,
            severity TEXT NOT NULL,
            category TEXT NOT NULL,
            title TEXT NOT NULL,
            description TEXT NOT NULL,
            source_ip TEXT,
            target_user TEXT,
            details_json TEXT
        )
    ''')

    # AI Reports table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS ai_reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            report_id TEXT UNIQUE NOT NULL,
            event_id TEXT NOT NULL,
            created_at TEXT NOT NULL,
            model_used TEXT NOT NULL,
            summary TEXT NOT NULL,
            mitre_attack TEXT,
            content_markdown TEXT NOT NULL,
            FOREIGN KEY(event_id) REFERENCES security_events(event_id)
        )
    ''')

    # System settings table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS system_settings (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        )
    ''')

    conn.commit()
    conn.close()

def insert_raw_log(source, level, message, raw_data=None):
    conn = get_db_connection()
    cursor = conn.cursor()
    timestamp = datetime.now().isoformat()
    cursor.execute(
        "INSERT INTO raw_logs (timestamp, source, level, message, raw_data) VALUES (?, ?, ?, ?, ?)",
        (timestamp, source, level, message, json.dumps(raw_data) if isinstance(raw_data, (dict, list)) else raw_data)
    )
    log_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return log_id

def insert_security_event(event_id, severity, category, title, description, source_ip=None, target_user=None, details=None):
    conn = get_db_connection()
    cursor = conn.cursor()
    timestamp = datetime.now().isoformat()
    cursor.execute(
        """INSERT OR IGNORE INTO security_events 
           (event_id, timestamp, severity, category, title, description, source_ip, target_user, details_json) 
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (event_id, timestamp, severity, category, title, description, source_ip, target_user, json.dumps(details) if details else None)
    )
    conn.commit()
    conn.close()

def get_recent_events(limit=50, severity=None):
    conn = get_db_connection()
    cursor = conn.cursor()
    if severity and severity.upper() != 'ALL':
        cursor.execute("SELECT * FROM security_events WHERE severity = ? ORDER BY id DESC LIMIT ?", (severity.upper(), limit))
    else:
        cursor.execute("SELECT * FROM security_events ORDER BY id DESC LIMIT ?", (limit,))
    rows = cursor.fetchall()
    conn.close()
    
    events = []
    for row in rows:
        event = dict(row)
        if event.get('details_json'):
            try:
                event['details'] = json.loads(event['details_json'])
            except Exception:
                event['details'] = event['details_json']
        events.append(event)
    return events

def get_event_by_id(event_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM security_events WHERE event_id = ?", (event_id,))
    row = cursor.fetchone()
    conn.close()
    if row:
        event = dict(row)
        if event.get('details_json'):
            try:
                event['details'] = json.loads(event['details_json'])
            except Exception:
                event['details'] = event['details_json']
        return event
    return None

def insert_ai_report(report_id, event_id, model_used, summary, mitre_attack, content_markdown):
    conn = get_db_connection()
    cursor = conn.cursor()
    created_at = datetime.now().isoformat()
    cursor.execute(
        """INSERT OR REPLACE INTO ai_reports 
           (report_id, event_id, created_at, model_used, summary, mitre_attack, content_markdown)
           VALUES (?, ?, ?, ?, ?, ?, ?)""",
        (report_id, event_id, created_at, model_used, summary, mitre_attack, content_markdown)
    )
    conn.commit()
    conn.close()

def get_reports(limit=50):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT r.*, e.title as event_title, e.severity as event_severity, e.category as event_category, e.source_ip
        FROM ai_reports r
        LEFT JOIN security_events e ON r.event_id = e.event_id
        ORDER BY r.id DESC LIMIT ?
    """, (limit,))
    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]

def get_report_by_id(report_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT r.*, e.title as event_title, e.severity as event_severity, e.category as event_category, e.source_ip, e.description as event_description
        FROM ai_reports r
        LEFT JOIN security_events e ON r.event_id = e.event_id
        WHERE r.report_id = ?
    """, (report_id,))
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None

def get_report_by_event_id(event_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM ai_reports WHERE event_id = ?", (event_id,))
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None

def delete_report(report_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM ai_reports WHERE report_id = ?", (report_id,))
    conn.commit()
    conn.close()

def get_soc_metrics():
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute("SELECT COUNT(*) FROM raw_logs")
    total_logs = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(*) FROM security_events")
    total_events = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(*) FROM security_events WHERE severity = 'CRITICAL'")
    critical_events = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(*) FROM security_events WHERE severity = 'HIGH'")
    high_events = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(*) FROM ai_reports")
    total_reports = cursor.fetchone()[0]
    
    # Severity distribution
    cursor.execute("SELECT severity, COUNT(*) as count FROM security_events GROUP BY severity")
    severity_dist = {row['severity']: row['count'] for row in cursor.fetchall()}
    
    # Category distribution
    cursor.execute("SELECT category, COUNT(*) as count FROM security_events GROUP BY category ORDER BY count DESC LIMIT 5")
    category_dist = {row['category']: row['count'] for row in cursor.fetchall()}
    
    conn.close()
    return {
        "total_logs": total_logs,
        "total_events": total_events,
        "critical_events": critical_events,
        "high_events": high_events,
        "total_reports": total_reports,
        "severity_distribution": severity_dist,
        "category_distribution": category_dist
    }

def get_setting(key, default=None):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT value FROM system_settings WHERE key = ?", (key,))
    row = cursor.fetchone()
    conn.close()
    return row['value'] if row else default

def set_setting(key, value):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("INSERT OR REPLACE INTO system_settings (key, value) VALUES (?, ?)", (key, value))
    conn.commit()
    conn.close()

if __name__ == "__main__":
    init_db()
    print("Database initialized successfully.")
