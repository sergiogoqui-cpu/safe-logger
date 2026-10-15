"""See safe-logger in action:  python examples/demo.py"""

import logging

from safe_logger import setup_logging

setup_logging("DEBUG", secrets=["my-real-api-secret"])
log = logging.getLogger("demo")

log.info("calling https://user:hunter2@api.example.com/v1?api_key=abc123&limit=10")
log.info("using key my-real-api-secret")
log.info("headers: Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig12345678")
log.info("config: %s", {"user": "ana", "password": "p4ss"})
log.warning("user said: hello\n2026-01-01 00:00:00 CRITICAL forged line")
log.info("payload: %s", "x" * 5000)

try:
    raise RuntimeError("login failed for password=p4ss")
except RuntimeError:
    log.exception("request failed")
