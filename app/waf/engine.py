import re
from urllib.parse import unquote_plus

from app.detectors.xss import detect_xss


class WAFEngine:
    """
    Core Web Application Firewall engine.

    Inspects HTTP request data and identifies
    common web attack patterns.
    """

    def __init__(self):

        self.rules = {

            "SQL_INJECTION": [
                r"(?i)(\bor\b|\band\b)\s+\d+\s*=\s*\d+",
                r"(?i)(union\s+select)",
                r"(?i)(select\s+.+\s+from)",
                r"(?i)(insert\s+into)",
                r"(?i)(update\s+.+\s+set)",
                r"(?i)(delete\s+from)",
                r"(?i)(drop\s+table)",
                r"(?i)(--\s*$)",
            ],

            "PATH_TRAVERSAL": [
                r"\.\./",
                r"\.\.\\",
                r"(?i)%2e%2e%2f",
                r"(?i)%2e%2e/",
                r"(?i)%2e%2e%5c",
                r"(?i)/etc/passwd",
                r"(?i)windows[/\\]system32",
            ],

            "COMMAND_INJECTION": [
                r"(?i);\s*(whoami|id|uname|cat|ls|dir)",
                r"\|\s*(whoami|id|uname|cat|ls|dir)",
                r"(?i)&&\s*(whoami|id|uname|cat|ls|dir)",
                r"\$\([^)]*\)",
                r"`[^`]+`",
            ],
        }

        self.severity = {
            "SQL_INJECTION": "HIGH",
            "XSS": "HIGH",
            "PATH_TRAVERSAL": "HIGH",
            "COMMAND_INJECTION": "CRITICAL",
        }

    def inspect(self, request_data):
        """
        Inspect request data and return a security decision.
        """

        searchable_data = self._prepare_request_data(request_data)

        # -------------------------
        # XSS Detection
        # -------------------------
        xss_result = detect_xss(searchable_data)

        if xss_result:
            return {
                "allowed": False,
                "attack_detected": True,
                "attack_type": xss_result["attack_type"],
                "severity": xss_result["severity"],
                "matched_rule": xss_result["matched_rule"],
                "action": "BLOCK",
            }

        # -------------------------
        # Other Attack Detection
        # -------------------------
        for attack_type, patterns in self.rules.items():

            for pattern in patterns:

                if re.search(pattern, searchable_data):

                    return {
                        "allowed": False,
                        "attack_detected": True,
                        "attack_type": attack_type,
                        "severity": self.severity[attack_type],
                        "matched_rule": pattern,
                        "action": "BLOCK",
                    }

        # -------------------------
        # Safe Request
        # -------------------------
        return {
            "allowed": True,
            "attack_detected": False,
            "attack_type": None,
            "severity": "LOW",
            "matched_rule": None,
            "action": "ALLOW",
        }

    @staticmethod
    def _prepare_request_data(request_data):
        """
        Normalize and decode request data before inspection.
        """

        if not request_data:
            return ""

        values = []

        for key, value in request_data.items():

            value = str(value)

            # Decode URL-encoded characters
            decoded_value = unquote_plus(value)

            values.append(str(key))
            values.append(decoded_value)

        return " ".join(values)