"""Synthetic canaries only: these values have never been real credentials."""
import ast
import io
import json
import logging
import pathlib
import sys
import os
import subprocess
import unittest
from unittest.mock import patch

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "rootfs/opt/hometunnel"))
import safe_logging as safe

CANARIES = (
    "synthetic-unlabelled-secret-9cd512", "Bearer synthetic-supervisor-token",
    "Cookie: session=synthetic-cookie", "setup-key-synthetic", "signed-binding-synthetic",
    "192.0.2.47", "198.51.100.0/24", "2001:db8::47", "2001:db8:abcd::/48",
    "https://user:synthetic-password@example.invalid/private/route?code=synthetic-code#secret",
    "synthetic-device-id", "synthetic-peer-key", "\nforged log event",
)


class SafeLoggingTests(unittest.TestCase):
    def render(self, msg, args=(), **extra):
        record = logging.LogRecord("third-party", logging.ERROR, CANARIES[0], 1, msg, args, None)
        record.__dict__.update(extra)
        result = safe.EventFormatter().format(record)
        for value in CANARIES:
            self.assertNotIn(value, result)
        return json.loads(result)

    def test_arbitrary_messages_exceptions_stack_and_extras_are_dropped(self):
        for value in CANARIES:
            with self.subTest(value=value):
                error = RuntimeError(value)
                self.assertEqual(self.render(value, exc_info=(RuntimeError, error, None),
                    exc_text=value, stack_info=value, secret=value)["event"], "unstructured_log_suppressed")
                self.render("request failed %s", (value,))

    def test_every_event_rejects_unknown_fields_and_nested_values(self):
        for event in safe.EVENTS:
            for value in CANARIES:
                self.render(event, ({value: value, "body": {"password": value}, "status": value, "received": value},))

    def test_only_exact_types_and_bounds_are_accepted(self):
        self.assertEqual(self.render("upstream_request", ({"status": 401},))["status"], 401)
        for value in (True, 99, 600, 401.0, "401", {"status": 401}):
            self.assertNotIn("status", self.render("upstream_request", ({"status": value},)))
        self.assertIs(safe.event_payload("supervisor_api_capability", {"received": False})["received"], False)
        self.assertNotIn("received", safe.event_payload("supervisor_api_capability", {"received": 1}))

    def test_never_stringifies_hostile_objects(self):
        class Hostile:
            def __str__(self):
                raise AssertionError("secret object must not be formatted")
        self.render(Hostile(), (Hostile(),))
        self.assertEqual(safe.event_payload(Hostile())["event"], "unstructured_log_suppressed")

    def test_real_handlers_drop_third_party_tracebacks_and_access_arguments(self):
        stream = io.StringIO()
        handler = logging.StreamHandler(stream)
        handler.setFormatter(safe.EventFormatter())
        logger = logging.getLogger("hometunnel.synthetic-test")
        with patch.object(logger, "handlers", [handler]), patch.object(logger, "propagate", False):
            for name in ("uvicorn.error", "httpx", "websockets", "asyncio"):
                record = logging.LogRecord(name, logging.ERROR, "secret", 1, "%s", (CANARIES,),
                    (RuntimeError, RuntimeError(" ".join(CANARIES)), None))
                logger.handle(record)
            logger.handle(logging.LogRecord("uvicorn.access", 20, "", 1, '%s - "%s %s HTTP/%s" %d',
                (CANARIES[5], "GET", CANARIES[9], "1.1", 200), None))
        for line in stream.getvalue().splitlines():
            self.assertEqual(json.loads(line)["event"], "unstructured_log_suppressed")
        for value in CANARIES:
            self.assertNotIn(value, stream.getvalue())

    def test_configured_root_handlers_and_interpreter_hooks(self):
        source = """
import logging, sys, threading, warnings
from safe_logging import configure_logging, install_event_filter
configure_logging("debug")
log = logging.getLogger("hometunnel")
install_event_filter(log)
secret = "synthetic-process-secret-192.0.2.47/32"
log.warning("upstream_request", {"status": 403, "secret": secret})
logging.getLogger("httpx").error(secret, exc_info=(ValueError, ValueError(secret), None))
warnings.warn(secret)
sys.excepthook(ValueError, ValueError(secret), None)
threading.excepthook(None)
sys.unraisablehook(None)
"""
        root = pathlib.Path(__file__).resolve().parents[1] / "rootfs/opt/hometunnel"
        result = subprocess.run([sys.executable, "-c", source], capture_output=True, text=True,
                                env={**os.environ, "PYTHONPATH": str(root)}, check=True)
        self.assertNotIn("synthetic-process-secret", result.stderr + result.stdout)
        self.assertNotIn("192.0.2.47", result.stderr + result.stdout)
        rows = [json.loads(line) for line in result.stderr.splitlines()]
        self.assertEqual(rows[0], {"event": "upstream_request", "status": 403, "level": "warning"})
        self.assertEqual({row["event"] for row in rows}, {"upstream_request", "unstructured_log_suppressed",
                         "uncaught_exception", "thread_exception", "unraisable_exception"})

    def test_application_log_calls_use_literal_registered_events(self):
        root = pathlib.Path(__file__).resolve().parents[1]
        tree = ast.parse((root / "rootfs/opt/hometunnel/app.py").read_text())
        for call in ast.walk(tree):
            if not isinstance(call, ast.Call):
                continue
            if isinstance(call.func, ast.Attribute) and isinstance(call.func.value, ast.Name) and call.func.value.id == "LOG":
                index = 1 if call.func.attr == "log" else 0
            elif isinstance(call.func, ast.Name) and call.func.id in {"log_method", "log_fn"}:
                index = 0
            else:
                continue
            self.assertIsInstance(call.args[index], ast.Constant)
            self.assertIn(call.args[index].value, safe.EVENTS)
            self.assertLessEqual(len(call.args), index + 2)
        self.assertNotIn("console.error(\"[HomeTunnel", (root / "rootfs/opt/hometunnel/app.py").read_text())


if __name__ == "__main__":
    unittest.main()
