from flask import Blueprint, render_template, jsonify
import json
import os

main = Blueprint("main", __name__)

LOG_FILE = "logs/security.log"


@main.route("/")
def home():
    return render_template("dashboard.html")


@main.route("/health")
def health():
    return {
        "status": "online",
        "service": "AI-Powered WAF",
        "message": "WAF security system is running"
    }


@main.route("/api/stats")
def stats():

    total_requests = 0
    blocked_requests = 0
    detected_attacks = 0
    ai_anomalies = 0

    threat_intelligence_events = 0
    blocked_ip_events = 0
    rate_limit_events = 0

    recent_events = []

    if os.path.exists(LOG_FILE):

        with open(LOG_FILE, "r", encoding="utf-8") as log_file:

            for line in log_file:

                line = line.strip()

                if not line:
                    continue

                try:

                    event = json.loads(line)

                    total_requests += 1

                    # -----------------------------
                    # Blocked Requests
                    # -----------------------------

                    if event.get("action") == "BLOCK":
                        blocked_requests += 1

                    # -----------------------------
                    # Detected Attacks
                    # -----------------------------

                    attack_type = event.get("attack_type")

                    if (
                        attack_type
                        and attack_type not in [
                            "AI_ANOMALY",
                            "THREAT_INTELLIGENCE",
                            "BLOCKED_IP",
                            "RATE_LIMIT_EXCEEDED"
                        ]
                    ):
                        detected_attacks += 1

                    # -----------------------------
                    # AI Anomalies
                    # -----------------------------

                    if attack_type == "AI_ANOMALY":
                        ai_anomalies += 1

                    # -----------------------------
                    # Threat Intelligence
                    # -----------------------------

                    if attack_type == "THREAT_INTELLIGENCE":
                        threat_intelligence_events += 1

                    # -----------------------------
                    # Blocked IP
                    # -----------------------------

                    if attack_type == "BLOCKED_IP":
                        blocked_ip_events += 1

                    # -----------------------------
                    # Rate Limit
                    # -----------------------------

                    if attack_type == "RATE_LIMIT_EXCEEDED":
                        rate_limit_events += 1

                    recent_events.append(event)

                except json.JSONDecodeError:
                    continue

    # Latest 10 events
    recent_events = recent_events[-10:]
    recent_events.reverse()

    return jsonify({

        "total_requests": total_requests,

        "blocked_requests": blocked_requests,

        "detected_attacks": detected_attacks,

        "ai_anomalies": ai_anomalies,

        "threat_intelligence_events":
            threat_intelligence_events,

        "blocked_ip_events":
            blocked_ip_events,

        "rate_limit_events":
            rate_limit_events,

        "recent_events":
            recent_events
    })