"""Prometheus metrics: request labels, the internal server and its lifespan.

The counters of other modules are checked where their behaviour is tested: storage errors in
``test_storage.py``, the dependency gauge in ``test_health.py``, logins, uploads and downloads
in the ``db`` tests of ``test_auth.py``, ``test_files_quota.py``, ``test_files.py`` and
``test_links.py``. Metrics are global, so every check compares before and after.
"""

import urllib.request

import httpx
import pytest
from fastapi import FastAPI
from prometheus_client import generate_latest

from app import main
from app.metrics import start_metrics_server
from app.middleware import KNOWN_METHODS
from tests.conftest import make_settings, sample
from tests.fakes import InMemoryBlobStore

SECRET_TOKEN = "SECRETTOKENVALUE0123456789"  # noqa: S105 - malformed on purpose, 404 without DB
OVERSIZED_BODY = b"x" * (64 * 1024 + 1)


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("method", "path", "body", "route", "status"),
    [
        ("GET", "/healthz", None, "/healthz", "200"),
        ("GET", "/no/such/page", None, "unmatched", "404"),
        # /metrics is not on the app port: it is an unknown path there.
        ("GET", "/metrics", None, "unmatched", "404"),
        # A public link path is a secret: only the template is recorded.
        ("GET", f"/s/{SECRET_TOKEN}", None, "/s/{token}", "404"),
        # An invented method must not create a new label value.
        ("FOO1", "/healthz", None, "/healthz", "405"),
        # The body limit answers before routing.
        ("POST", "/login", OVERSIZED_BODY, "unmatched", "413"),
    ],
    ids=["route", "unmatched", "no-metrics-on-app-port", "link-token", "unknown-method", "413"],
)
async def test_requests_are_counted_by_route_template(
    client: httpx.AsyncClient,
    method: str,
    path: str,
    body: bytes | None,
    route: str,
    status: str,
) -> None:
    """Each request adds one to the counter and the histogram, labelled with the template."""
    label_method = method if method in KNOWN_METHODS else "OTHER"
    labels = {"method": label_method, "route": route}
    count_before = sample("silo_http_requests_total", **labels, status=status)
    duration_before = sample("silo_http_request_duration_seconds_count", **labels)

    response = await client.request(method, path, content=body)

    assert response.status_code == int(status)
    assert sample("silo_http_requests_total", **labels, status=status) == count_before + 1
    assert sample("silo_http_request_duration_seconds_count", **labels) == duration_before + 1


@pytest.mark.anyio
async def test_client_values_never_reach_the_output(client: httpx.AsyncClient) -> None:
    """Neither a link token nor an invented method appears anywhere in /metrics."""
    await client.get(f"/s/{SECRET_TOKEN}")
    await client.request("FOO1", "/healthz")

    output = generate_latest().decode()
    assert SECRET_TOKEN not in output
    assert "FOO1" not in output


@pytest.mark.anyio
async def test_unhandled_error_is_counted_as_500(app: FastAPI, client: httpx.AsyncClient) -> None:
    """An exception that escapes the app still counts, with the status the client got."""

    async def boom() -> None:
        raise RuntimeError("boom")

    app.add_api_route("/test-boom", boom)
    labels = {"method": "GET", "route": "/test-boom", "status": "500"}
    before = sample("silo_http_requests_total", **labels)

    response = await client.get("/test-boom")

    assert response.status_code == 500
    assert sample("silo_http_requests_total", **labels) == before + 1


def test_metrics_server_serves_the_metrics() -> None:
    """Port 0 picks a free port; the endpoint answers and can be shut down."""
    server = start_metrics_server(0)
    try:
        url = f"http://127.0.0.1:{server.server_port}/metrics"
        body = urllib.request.urlopen(url, timeout=5).read().decode()  # noqa: S310
        assert "process_resident_memory_bytes" in body
    finally:
        server.shutdown()
        server.server_close()


class FakeMetricsServer:
    """Records that the lifespan shuts the metrics server down and closes its socket."""

    def __init__(self) -> None:
        self.calls: list[str] = []

    def shutdown(self) -> None:
        self.calls.append("shutdown")

    def server_close(self) -> None:
        self.calls.append("server_close")


@pytest.mark.anyio
async def test_lifespan_starts_and_stops_the_metrics_server(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """METRICS_PORT > 0 starts the server on that port; shutdown stops it. Port 0 starts none."""
    started: list[int] = []
    fake = FakeMetricsServer()

    def fake_start(port: int) -> FakeMetricsServer:
        started.append(port)
        return fake

    monkeypatch.setattr(main, "start_metrics_server", fake_start)

    for port in (0, 9000):
        app = main.create_app(
            settings=make_settings(metrics_port=port),
            blob_store=InMemoryBlobStore(),
            initial_admin=False,
        )
        async with app.router.lifespan_context(app):
            assert fake.calls == []
    assert started == [9000]
    assert fake.calls == ["shutdown", "server_close"]
