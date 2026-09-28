from datetime import datetime, timedelta


class IPBlocker:
    """
    Simple in-memory IP blocking system.

    Blocks suspicious IP addresses for a configurable
    amount of time.
    """

    def __init__(self, block_duration=300):

        self.block_duration = block_duration

        self.blocked_ips = {}

    def block(self, ip_address, reason="Suspicious activity"):

        self.blocked_ips[ip_address] = {
            "blocked_at": datetime.utcnow(),
            "expires_at": datetime.utcnow()
            + timedelta(seconds=self.block_duration),
            "reason": reason
        }

    def is_blocked(self, ip_address):

        if ip_address not in self.blocked_ips:
            return False

        block_info = self.blocked_ips[ip_address]

        if datetime.utcnow() >= block_info["expires_at"]:

            del self.blocked_ips[ip_address]

            return False

        return True

    def get_block_info(self, ip_address):

        if not self.is_blocked(ip_address):
            return None

        return self.blocked_ips[ip_address]

    def unblock(self, ip_address):

        self.blocked_ips.pop(ip_address, None)

    def get_blocked_ips(self):

        self._cleanup_expired()

        return self.blocked_ips.copy()

    def _cleanup_expired(self):

        current_time = datetime.utcnow()

        expired_ips = [
            ip
            for ip, info in self.blocked_ips.items()
            if current_time >= info["expires_at"]
        ]

        for ip in expired_ips:
            del self.blocked_ips[ip]