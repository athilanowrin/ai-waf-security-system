class ThreatIntelligence:
    """
    Local IP reputation / threat intelligence system.

    Maintains a list of known suspicious IP addresses
    and provides reputation information.
    """

    def __init__(self):

        self.threat_ips = {
            "192.0.2.10": {
                "threat_level": "HIGH",
                "category": "Scanner",
                "source": "Local Threat Feed"
            },

            "198.51.100.20": {
                "threat_level": "CRITICAL",
                "category": "Brute Force",
                "source": "Local Threat Feed"
            },

            "203.0.113.50": {
                "threat_level": "HIGH",
                "category": "Malicious Bot",
                "source": "Local Threat Feed"
            }
        }

    def check_ip(self, ip_address):

        if ip_address in self.threat_ips:

            threat_info = self.threat_ips[ip_address]

            return {
                "is_threat": True,
                "ip_address": ip_address,
                "threat_level": threat_info["threat_level"],
                "category": threat_info["category"],
                "source": threat_info["source"]
            }

        return {
            "is_threat": False,
            "ip_address": ip_address,
            "threat_level": "LOW",
            "category": "Unknown",
            "source": "Local Threat Feed"
        }

    def add_threat_ip(
        self,
        ip_address,
        threat_level="HIGH",
        category="Suspicious Activity",
        source="Manual Entry"
    ):

        self.threat_ips[ip_address] = {
            "threat_level": threat_level,
            "category": category,
            "source": source
        }

    def remove_threat_ip(self, ip_address):

        self.threat_ips.pop(ip_address, None)

    def get_threat_ips(self):

        return self.threat_ips.copy()