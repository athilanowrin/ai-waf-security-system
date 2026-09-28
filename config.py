class Config:
    SECRET_KEY = "waf-development-key"

    MAX_REQUEST_SIZE = 1024 * 1024

    RATE_LIMIT = 100

    BLOCK_DURATION = 300

    LOG_FILE = "logs/security.log"