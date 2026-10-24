import sqlite3
import json
from datetime import datetime, timedelta
from config import DB_PATH, THRESHOLD_HIGH, THRESHOLD_MEDIUM


def get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def initialize_db():
    with get_conn() as conn:
        conn.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            user_id   TEXT PRIMARY KEY,
            username  TEXT NOT NULL,
            department TEXT NOT NULL,
            role      TEXT NOT NULL,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS activity_logs (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id     TEXT NOT NULL,
            timestamp   TEXT NOT NULL,
            event_type  TEXT NOT NULL,
            resource    TEXT,
            ip_address  TEXT,
            status      TEXT,
            details     TEXT
        );

        CREATE TABLE IF NOT EXISTS anomaly_scores (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id       TEXT NOT NULL,
            window_start  TEXT NOT NULL,
            window_end    TEXT NOT NULL,
            anomaly_score REAL NOT NULL,
            is_anomaly    INTEGER NOT NULL DEFAULT 0,
            severity      TEXT NOT NULL DEFAULT 'normal',
            features_json TEXT,
            detected_at   TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS alerts (
            id               INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id          TEXT NOT NULL,
            alert_type       TEXT NOT NULL,
            severity         TEXT NOT NULL,
            description      TEXT NOT NULL,
            timestamp        TEXT NOT NULL,
            is_acknowledged  INTEGER NOT NULL DEFAULT 0,
            acknowledged_at  TEXT
        );
        """)


def insert_user(user_id, username, department, role):
    with get_conn() as conn:
        conn.execute(
            "INSERT OR IGNORE INTO users (user_id, username, department, role, created_at) VALUES (?,?,?,?,?)",
            (user_id, username, department, role, datetime.utcnow().isoformat()),
        )


def insert_activity_log(user_id, timestamp, event_type, resource, ip_address, status, details_dict=None):
    details_str = json.dumps(details_dict) if details_dict else "{}"
    if isinstance(timestamp, datetime):
        timestamp = timestamp.isoformat()
    with get_conn() as conn:
        conn.execute(
            """INSERT INTO activity_logs
               (user_id, timestamp, event_type, resource, ip_address, status, details)
               VALUES (?,?,?,?,?,?,?)""",
            (user_id, timestamp, event_type, resource, ip_address, status, details_str),
        )


def get_all_users():
    with get_conn() as conn:
        rows = conn.execute("SELECT * FROM users ORDER BY username").fetchall()
    return [dict(r) for r in rows]


def get_user_logs(user_id, limit=500):
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT * FROM activity_logs WHERE user_id=? ORDER BY timestamp DESC LIMIT ?",
            (user_id, limit),
        ).fetchall()
    return [dict(r) for r in rows]


def get_recent_logs(hours=24):
    cutoff = (datetime.utcnow() - timedelta(hours=hours)).isoformat()
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT * FROM activity_logs WHERE timestamp >= ? ORDER BY timestamp ASC",
            (cutoff,),
        ).fetchall()
    return [dict(r) for r in rows]


def get_all_logs():
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT * FROM activity_logs ORDER BY timestamp ASC"
        ).fetchall()
    return [dict(r) for r in rows]


def insert_anomaly_score(user_id, window_start, window_end, score, is_anomaly, severity, features_dict):
    if isinstance(window_start, datetime):
        window_start = window_start.isoformat()
    if isinstance(window_end, datetime):
        window_end = window_end.isoformat()
    with get_conn() as conn:
        conn.execute(
            """INSERT INTO anomaly_scores
               (user_id, window_start, window_end, anomaly_score, is_anomaly, severity, features_json, detected_at)
               VALUES (?,?,?,?,?,?,?,?)""",
            (
                user_id, window_start, window_end,
                float(score), int(is_anomaly), severity,
                json.dumps(features_dict),
                datetime.utcnow().isoformat(),
            ),
        )


def get_anomaly_scores(user_id=None, limit=200):
    with get_conn() as conn:
        if user_id:
            rows = conn.execute(
                "SELECT * FROM anomaly_scores WHERE user_id=? ORDER BY detected_at DESC LIMIT ?",
                (user_id, limit),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM anomaly_scores ORDER BY detected_at DESC LIMIT ?",
                (limit,),
            ).fetchall()
    return [dict(r) for r in rows]


def insert_alert(user_id, alert_type, severity, description, timestamp):
    if isinstance(timestamp, datetime):
        timestamp = timestamp.isoformat()
    with get_conn() as conn:
        conn.execute(
            """INSERT INTO alerts
               (user_id, alert_type, severity, description, timestamp, is_acknowledged)
               VALUES (?,?,?,?,?,0)""",
            (user_id, alert_type, severity, description, timestamp),
        )


def get_alerts(acknowledged=None, limit=200):
    with get_conn() as conn:
        if acknowledged is None:
            rows = conn.execute(
                "SELECT a.*, u.username FROM alerts a JOIN users u ON a.user_id=u.user_id ORDER BY a.timestamp DESC LIMIT ?",
                (limit,),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT a.*, u.username FROM alerts a JOIN users u ON a.user_id=u.user_id WHERE a.is_acknowledged=? ORDER BY a.timestamp DESC LIMIT ?",
                (int(acknowledged), limit),
            ).fetchall()
    return [dict(r) for r in rows]


def acknowledge_alert(alert_id):
    with get_conn() as conn:
        conn.execute(
            "UPDATE alerts SET is_acknowledged=1, acknowledged_at=? WHERE id=?",
            (datetime.utcnow().isoformat(), alert_id),
        )


def get_dashboard_stats():
    with get_conn() as conn:
        total_users = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        total_logs = conn.execute("SELECT COUNT(*) FROM activity_logs").fetchone()[0]
        total_alerts = conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
        open_alerts = conn.execute("SELECT COUNT(*) FROM alerts WHERE is_acknowledged=0").fetchone()[0]
        high_severity = conn.execute(
            "SELECT COUNT(*) FROM alerts WHERE severity='high' AND is_acknowledged=0"
        ).fetchone()[0]
        cutoff = (datetime.utcnow() - timedelta(hours=24)).isoformat()
        recent_anomalies = conn.execute(
            "SELECT COUNT(*) FROM anomaly_scores WHERE is_anomaly=1 AND detected_at >= ?",
            (cutoff,),
        ).fetchone()[0]
    return {
        "total_users": total_users,
        "total_logs": total_logs,
        "total_alerts": total_alerts,
        "open_alerts": open_alerts,
        "high_severity_alerts": high_severity,
        "recent_anomalies": recent_anomalies,
    }


def is_db_empty():
    with get_conn() as conn:
        count = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    return count == 0


def get_user_alert_count(user_id):
    with get_conn() as conn:
        row = conn.execute(
            "SELECT COUNT(*) FROM alerts WHERE user_id=? AND is_acknowledged=0",
            (user_id,),
        ).fetchone()
    return row[0] if row else 0


def get_user_latest_score(user_id):
    with get_conn() as conn:
        row = conn.execute(
            "SELECT * FROM anomaly_scores WHERE user_id=? ORDER BY detected_at DESC LIMIT 1",
            (user_id,),
        ).fetchone()
    return dict(row) if row else None
