import json
import logging
import os
from datetime import datetime


LOG_FILE = "logs/security.log"


def setup_logger():
    """
    Create and configure the WAF security logger.
    """

    os.makedirs("logs", exist_ok=True)

    logger = logging.getLogger("WAF_SECURITY")

    if not logger.handlers:
        logger.setLevel(logging.INFO)

        file_handler = logging.FileHandler(
            LOG_FILE,
            encoding="utf-8"
        )

        file_handler.setLevel(logging.INFO)

        formatter = logging.Formatter(
            "%(message)s"
        )

        file_handler.setFormatter(formatter)

        logger.addHandler(file_handler)

    return logger


security_logger = setup_logger()


def log_security_event(
    ip_address,
    method,
    path,
    attack_type,
    severity,
    action,
    matched_rule=None,
    user_agent=None
):
    """
    Record a WAF security event as structured JSON.
    """

    event = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "source_ip": ip_address,
        "method": method,
        "path": path,
        "attack_type": attack_type,
        "severity": severity,
        "action": action,
        "matched_rule": matched_rule,
        "user_agent": user_agent
    }

    security_logger.info(
        json.dumps(event)
    )