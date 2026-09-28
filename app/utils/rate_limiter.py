import time
from collections import defaultdict


class RateLimiter:
    """
    Simple in-memory IP-based rate limiter.
    """

    def __init__(self, limit=100, window=60):
        self.limit = limit
        self.window = window
        self.requests = defaultdict(list)

    def check(self, ip_address):
        now = time.time()

        # Remove expired requests
        self.requests[ip_address] = [
            timestamp
            for timestamp in self.requests[ip_address]
            if now - timestamp < self.window
        ]

        # Check rate limit
        if len(self.requests[ip_address]) >= self.limit:
            return {
                "allowed": False,
                "limit_exceeded": True,
                "remaining": 0,
            }

        # Record current request
        self.requests[ip_address].append(now)

        return {
            "allowed": True,
            "limit_exceeded": False,
            "remaining": self.limit - len(self.requests[ip_address]),
        }

    def reset(self, ip_address):
        self.requests.pop(ip_address, None)