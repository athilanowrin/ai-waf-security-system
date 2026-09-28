import re


XSS_PATTERNS = [
    r"<script\b[^>]*>",
    r"</script>",
    r"javascript\s*:",
    r"onerror\s*=",
    r"onload\s*=",
    r"onclick\s*=",
    r"<iframe\b",
]


def detect_xss(value):
    if not value:
        return None

    for pattern in XSS_PATTERNS:
        if re.search(pattern, value, re.IGNORECASE):
            return {
                "attack_type": "XSS",
                "severity": "HIGH",
                "matched_rule": pattern,
            }

    return None