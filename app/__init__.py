
from flask import Flask, request, jsonify

from app.routes import main
from app.waf.engine import WAFEngine
from app.utils.rate_limiter import RateLimiter
from app.utils.logger import log_security_event
from app.ai.anomaly_detector import AnomalyDetector
from app.utils.ip_blocker import IPBlocker
from app.utils.threat_intelligence import ThreatIntelligence


def create_app():

    app = Flask(
        __name__,
        template_folder="../templates",
        static_folder="../static"
    )

    # -----------------------------------
    # Security Components
    # -----------------------------------

    waf_engine = WAFEngine()

    rate_limiter = RateLimiter(
        limit=100,
        window=60
    )

    anomaly_detector = AnomalyDetector()

    ip_blocker = IPBlocker(
        block_duration=300
    )

    threat_intelligence = ThreatIntelligence()

    # -----------------------------------
    # Train AI Model with Normal Requests
    # -----------------------------------

    normal_requests = [

        {"user": "alice"},
        {"user": "bob"},
        {"page": "home"},
        {"page": "about"},
        {"search": "python"},
        {"search": "security"},
        {"id": "10"},
        {"id": "25"},
        {"category": "books"},
        {"category": "technology"},
        {"name": "john"},
        {"name": "alex"},
        {"query": "flask"},
        {"query": "networking"},
        {"status": "active"},
        {"type": "user"},
        {"page": "contact"},
        {"lang": "en"},
        {"sort": "latest"},
        {"limit": "10"}

    ]

    anomaly_detector.train(normal_requests)

    # -----------------------------------
    # Register Routes
    # -----------------------------------

    app.register_blueprint(main)

    # -----------------------------------
    # Security Middleware
    # -----------------------------------

    @app.before_request
    def security_check():

        ip_address = request.remote_addr or "unknown"

        # =================================
        # 1. Threat Intelligence Check
        # =================================

        threat_result = threat_intelligence.check_ip(
            ip_address
        )

        if threat_result["is_threat"]:

            log_security_event(
                ip_address=ip_address,
                method=request.method,
                path=request.full_path,
                attack_type="THREAT_INTELLIGENCE",
                severity=threat_result["threat_level"],
                action="BLOCK",
                matched_rule=(
                    f"{threat_result['category']} | "
                    f"Source: {threat_result['source']}"
                ),
                user_agent=request.headers.get("User-Agent")
            )

            return jsonify({
                "action": "BLOCK",
                "status": "blocked",
                "attack_type": "THREAT_INTELLIGENCE",
                "severity": threat_result["threat_level"],
                "category": threat_result["category"],
                "message": "Threat intelligence detected a malicious IP",
                "source_ip": ip_address
            }), 403

        # =================================
        # 2. IP BLOCK CHECK
        # =================================

        if ip_blocker.is_blocked(ip_address):

            block_info = ip_blocker.get_block_info(
                ip_address
            )

            log_security_event(
                ip_address=ip_address,
                method=request.method,
                path=request.full_path,
                attack_type="BLOCKED_IP",
                severity="HIGH",
                action="BLOCK",
                matched_rule=(
                    block_info["reason"]
                    if block_info
                    else "IP address is blocked"
                ),
                user_agent=request.headers.get("User-Agent")
            )

            return jsonify({
                "action": "BLOCK",
                "status": "blocked",
                "attack_type": "BLOCKED_IP",
                "severity": "HIGH",
                "message": "Your IP address is temporarily blocked",
                "source_ip": ip_address
            }), 403

        # =================================
        # 3. Rate Limiting
        # =================================

        rate_result = rate_limiter.check(ip_address)

        if not rate_result["allowed"]:

            ip_blocker.block(
                ip_address,
                reason="Rate limit exceeded"
            )

            log_security_event(
                ip_address=ip_address,
                method=request.method,
                path=request.full_path,
                attack_type="RATE_LIMIT_EXCEEDED",
                severity="MEDIUM",
                action="BLOCK",
                matched_rule="IP rate limit exceeded",
                user_agent=request.headers.get("User-Agent")
            )

            return jsonify({
                "action": "BLOCK",
                "message": "Rate limit exceeded",
                "status": "blocked",
                "source_ip": ip_address
            }), 429

        # =================================
        # 4. Collect Request Data
        # =================================

        request_data = {}

        for key, value in request.args.items():
            request_data[key] = value

        for key, value in request.form.items():
            request_data[key] = value

        # =================================
        # 5. WAF Rule Detection
        # =================================

        waf_result = waf_engine.inspect(
            request_data
        )

        if not waf_result["allowed"]:

            ip_blocker.block(
                ip_address,
                reason=(
                    f"WAF detected "
                    f"{waf_result['attack_type']}"
                )
            )

            log_security_event(
                ip_address=ip_address,
                method=request.method,
                path=request.full_path,
                attack_type=waf_result["attack_type"],
                severity=waf_result["severity"],
                action="BLOCK",
                matched_rule=waf_result["matched_rule"],
                user_agent=request.headers.get("User-Agent")
            )

            return jsonify({
                "action": "BLOCK",
                "status": "blocked",
                "attack_type": waf_result["attack_type"],
                "severity": waf_result["severity"],
                "message": "Malicious request detected and blocked"
            }), 403

        # =================================
        # 6. AI Anomaly Detection
        # =================================

        if request_data:

            ai_result = anomaly_detector.detect(
                request_data
            )

            print(
                "AI RESULT:",
                ai_result
            )

            if ai_result["is_anomaly"]:

                log_security_event(
                    ip_address=ip_address,
                    method=request.method,
                    path=request.full_path,
                    attack_type="AI_ANOMALY",
                    severity="MEDIUM",
                    action="MONITOR",
                    matched_rule=(
                        f"Anomaly Score: "
                        f"{ai_result['anomaly_score']}"
                    ),
                    user_agent=request.headers.get("User-Agent")
                )

        # =================================
        # 7. Allow Request
        # =================================

        return None

    return app

