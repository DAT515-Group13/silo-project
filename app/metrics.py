"""Prometheus metrics, all defined in one place.

The metrics are served by ``start_metrics_server`` on an internal port (``METRICS_PORT``), never
on the app port. Label values must come from small fixed sets: route templates, status codes and
fixed words. Never put a username, IP, file ID, file name or token into a label.
"""

from http.server import HTTPServer

from prometheus_client import Counter, Gauge, Histogram, start_http_server

# Uploads stream the whole file inside one request, so the buckets reach one minute.
_DURATION_BUCKETS = (0.01, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30, 60)

HTTP_REQUESTS = Counter("silo_http_requests_total", "HTTP requests.", ["method", "route", "status"])
HTTP_DURATION = Histogram(
    "silo_http_request_duration_seconds",
    "HTTP request duration.",
    ["method", "route"],
    buckets=_DURATION_BUCKETS,
)
DEPENDENCY_UP = Gauge(
    "silo_dependency_up", "1 if the last readiness check passed, else 0.", ["dependency"]
)
STORAGE_ERRORS = Counter("silo_storage_errors_total", "Failed blob storage calls.", ["operation"])
LOGIN_ATTEMPTS = Counter("silo_login_attempts_total", "Login attempts by result.", ["result"])
UPLOADS = Counter("silo_uploads_total", "Uploads by result.", ["result"])
UPLOAD_BYTES = Counter("silo_upload_bytes_total", "Bytes of successful uploads.")
DOWNLOADS = Counter("silo_downloads_total", "Download links issued.", ["kind"])


def start_metrics_server(port: int) -> HTTPServer:
    """Serve ``/metrics`` on ``port`` in a background thread; stop it with ``shutdown()``."""
    server, _thread = start_http_server(port)
    return server
