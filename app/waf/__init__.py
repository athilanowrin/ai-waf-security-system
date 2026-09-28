
from flask import Flask, request, jsonify
from config import Config
from app.waf.engine import WAFEngine


def create_app():
    app = Flask(__name__, template_folder="../templates")
    app.config.from_object(Config)

    # Initialize WAF Engine
    waf = WAFEngine()

    # Inspect every incoming HTTP request
    @app.before_request
    def waf_middleware():

        request_data = {
            "method": request.method,
            "path": request.path,
            "query": request.query_string.decode(
                "utf-8", errors="replace"
            ),
            "headers": dict(request.headers),
            "body": request.get_data(
                cache=True, as_text=True
            )
        }

        result = waf.inspect(request_data)

        if not result["allowed"]:
            return jsonify({
                "status": "blocked",
                "message": "Malicious request detected",
                "attack_type": result["attack_type"],
                "severity": result["severity"]
            }), 403

    # Register application routes
    from app.routes import main
    app.register_blueprint(main)

    return app