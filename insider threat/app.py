import json
from datetime import datetime, timedelta
from flask import Flask, render_template, request, redirect, url_for, jsonify

from config import DB_PATH
from database.db_manager import (
    initialize_db, is_db_empty, get_all_users, get_user_logs,
    get_recent_logs, get_all_logs, get_anomaly_scores,
    get_alerts, acknowledge_alert, get_dashboard_stats,
    get_user_alert_count, get_user_latest_score, insert_activity_log,
)
from data.generator import seed_database
from analytics.detector import ThreatDetector

app = Flask(__name__)

# Global detector instance
detector = ThreatDetector()


def startup():
    initialize_db()
    if is_db_empty():
        print("[Startup] Seeding database with synthetic data...")
        seed_database()
        print("[Startup] Running initial anomaly detection...")
        detector.run_full_detection()
    else:
        # Re-train on existing data so detector is ready for /simulate
        logs = get_all_logs()
        if logs:
            import pandas as pd
            from analytics.feature_engineer import extract_features
            logs_df = pd.DataFrame(logs)
            features_df = extract_features(logs_df)
            if not features_df.empty:
                detector.train(features_df)


# ─── Routes ──────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return redirect(url_for("dashboard"))


@app.route("/dashboard")
def dashboard():
    stats = get_dashboard_stats()
    scores = get_anomaly_scores(limit=200)

    # Time-series data for Chart.js line chart
    # Group by date, compute average anomaly score
    from collections import defaultdict
    daily_scores = defaultdict(list)
    for s in scores:
        date_key = s["window_start"][:10] if s["window_start"] else "unknown"
        daily_scores[date_key].append(s["anomaly_score"])

    sorted_dates = sorted(daily_scores.keys())
    ts_labels = sorted_dates
    ts_data = [round(sum(daily_scores[d]) / len(daily_scores[d]), 4) for d in sorted_dates]

    # Severity distribution
    severity_counts = {"normal": 0, "medium": 0, "high": 0}
    for s in scores:
        sev = s.get("severity", "normal")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    recent_anomalies = [s for s in scores if s.get("is_anomaly") == 1][:20]

    # Attach username
    users_map = {u["user_id"]: u["username"] for u in get_all_users()}
    for a in recent_anomalies:
        a["username"] = users_map.get(a["user_id"], a["user_id"])
        a["features"] = json.loads(a.get("features_json") or "{}")

    return render_template(
        "dashboard.html",
        stats=stats,
        ts_labels=json.dumps(ts_labels),
        ts_data=json.dumps(ts_data),
        severity_counts=json.dumps(severity_counts),
        recent_anomalies=recent_anomalies,
    )


@app.route("/users")
def users_list():
    users = get_all_users()
    for u in users:
        u["alert_count"] = get_user_alert_count(u["user_id"])
        latest = get_user_latest_score(u["user_id"])
        u["latest_score"] = round(latest["anomaly_score"], 4) if latest else None
        u["severity"] = latest["severity"] if latest else "normal"
    return render_template("users.html", users=users, selected_user=None)


@app.route("/users/<user_id>")
def user_detail(user_id):
    all_users = get_all_users()
    user = next((u for u in all_users if u["user_id"] == user_id), None)
    if not user:
        return redirect(url_for("users_list"))

    logs = get_user_logs(user_id, limit=50)
    scores = get_anomaly_scores(user_id=user_id, limit=60)

    from analytics.feature_engineer import get_user_profile
    import pandas as pd
    all_logs_df = pd.DataFrame(get_all_logs())
    profile = get_user_profile(all_logs_df, user_id) if not all_logs_df.empty else {}

    # Chart data: score history
    score_dates = [s["window_start"][:10] for s in scores]
    score_vals = [round(s["anomaly_score"], 4) for s in scores]

    for u in all_users:
        u["alert_count"] = get_user_alert_count(u["user_id"])
        latest = get_user_latest_score(u["user_id"])
        u["latest_score"] = round(latest["anomaly_score"], 4) if latest else None
        u["severity"] = latest["severity"] if latest else "normal"

    return render_template(
        "users.html",
        users=all_users,
        selected_user=user,
        logs=logs,
        scores=scores,
        profile=profile,
        score_dates=json.dumps(score_dates),
        score_vals=json.dumps(score_vals),
    )


@app.route("/alerts")
def alerts():
    filter_sev = request.args.get("severity", "all")
    all_alerts = get_alerts(acknowledged=False)
    if filter_sev != "all":
        all_alerts = [a for a in all_alerts if a["severity"] == filter_sev]
    counts = {
        "all": len(get_alerts(acknowledged=False)),
        "high": len([a for a in get_alerts(acknowledged=False) if a["severity"] == "high"]),
        "medium": len([a for a in get_alerts(acknowledged=False) if a["severity"] == "medium"]),
    }
    return render_template("alerts.html", alerts=all_alerts, filter_sev=filter_sev, counts=counts)


@app.route("/alerts/<int:alert_id>/acknowledge", methods=["POST"])
def ack_alert(alert_id):
    acknowledge_alert(alert_id)
    return redirect(url_for("alerts"))


@app.route("/simulate")
def simulate():
    users = get_all_users()
    return render_template("simulate.html", users=users, now=datetime.utcnow().strftime("%Y-%m-%dT%H:%M"))


@app.route("/simulate", methods=["POST"])
def simulate_post():
    data = request.get_json() or request.form
    user_id = data.get("user_id")
    event_type = data.get("event_type", "login")
    timestamp_str = data.get("timestamp", datetime.utcnow().isoformat())
    resource = data.get("resource", "/shared/file")
    ip_address = data.get("ip_address", "192.168.1.100")
    status = data.get("status", "success")

    try:
        ts = datetime.fromisoformat(timestamp_str)
    except Exception:
        ts = datetime.utcnow()

    event = {
        "user_id": user_id,
        "timestamp": ts,
        "event_type": event_type,
        "resource": resource,
        "ip_address": ip_address,
        "status": status,
        "details": {},
    }

    insert_activity_log(
        user_id=user_id,
        timestamp=ts,
        event_type=event_type,
        resource=resource,
        ip_address=ip_address,
        status=status,
        details_dict={},
    )

    all_logs = get_all_logs()
    result = detector.score_single_event(event, all_logs)
    return jsonify(result)


@app.route("/api/run-detection", methods=["POST"])
def api_run_detection():
    alerts_generated = detector.run_full_detection()
    stats = get_dashboard_stats()
    return jsonify({
        "status": "ok",
        "alerts_generated": len(alerts_generated),
        "stats": stats,
    })


@app.route("/api/stats")
def api_stats():
    return jsonify(get_dashboard_stats())


@app.route("/api/anomalies")
def api_anomalies():
    scores = get_anomaly_scores(limit=100)
    return jsonify(scores)


# ─── Main ─────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    startup()
    app.run(debug=True, port=5000)
