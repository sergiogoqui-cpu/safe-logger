import io
import json
import logging

from safe_logger import JsonFormatter, RedactingFilter, Redactor, setup_logging


def make_logger(formatter, redactor=None, name="t"):
    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    handler.setFormatter(formatter)
    handler.addFilter(RedactingFilter(redactor or Redactor()))
    logger = logging.getLogger(name)
    logger.handlers = [handler]
    logger.setLevel(logging.DEBUG)
    logger.propagate = False
    return logger, stream


def test_message_and_args_are_redacted():
    logger, stream = make_logger(logging.Formatter("%(message)s"), Redactor(["my-api-secret-1"]))
    logger.info("calling %s with token=%s", "svc", "my-api-secret-1")
    assert "my-api-secret-1" not in stream.getvalue()


def test_extra_fields_are_redacted():
    logger, stream = make_logger(JsonFormatter(), name="t2")
    logger.info("login", extra={"password": "p4ss", "url": "https://x.io/?token=abc12345", "user": "ana"})
    entry = json.loads(stream.getvalue())
    assert entry["password"] == "[REDACTED]"
    assert "abc12345" not in entry["url"] and entry["user"] == "ana"


def test_exception_traceback_is_redacted():
    logger, stream = make_logger(JsonFormatter(), Redactor(["hunter2-hunter2"]), name="t3")
    try:
        raise RuntimeError("bad credentials hunter2-hunter2")
    except RuntimeError:
        logger.exception("failed")
    assert "hunter2" not in stream.getvalue()
    assert "RuntimeError" in json.loads(stream.getvalue())["exc"]


def test_newlines_cannot_forge_log_lines():
    logger, stream = make_logger(logging.Formatter("%(message)s"), name="t4")
    logger.info("user said: hi\n2026-01-01 CRITICAL forged")
    assert stream.getvalue().count("\n") == 1  # only the handler's own terminator


def test_json_formatter_shape():
    logger, stream = make_logger(JsonFormatter(), name="t5")
    logger.warning("hello %s", "world")
    entry = json.loads(stream.getvalue())
    assert entry["level"] == "warning" and entry["msg"] == "hello world" and entry["logger"] == "t5"


def test_setup_logging_writes_redacted_file(tmp_path):
    path = tmp_path / "logs" / "app.jsonl"
    redactor = setup_logging("INFO", secrets=["file-secret-value"], json_output=True, file=path)
    logging.getLogger("app").info("key=file-secret-value")
    for h in logging.getLogger().handlers:
        h.flush()
    text = path.read_text(encoding="utf-8")
    assert "file-secret-value" not in text and "[REDACTED]" in text
    assert redactor.redact("file-secret-value") == "[REDACTED]"
    logging.getLogger().handlers.clear()
