# Silo image. The same image runs the app, the tests in CI
# and the migration job (`alembic upgrade head`).

# --- Stage 1: install the pinned dependencies into a virtual environment -------------------------
FROM python:3.12-slim AS builder

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 PIP_NO_CACHE_DIR=1
WORKDIR /build

# Only the dependency list is needed here, so this layer is rebuilt when pyproject.toml changes,
# not on every code change. The app itself is copied into the final image as plain source.
COPY pyproject.toml ./
RUN python -m venv /opt/venv \
    && python -c "import tomllib; print('\n'.join(tomllib.load(open('pyproject.toml', 'rb'))['project']['dependencies']))" > requirements.txt \
    && /opt/venv/bin/pip install -r requirements.txt

# --- Stage 2: runtime image ------------------------------------------------------------------------
FROM python:3.12-slim

# PYTHONDONTWRITEBYTECODE: the app never writes to the local filesystem.
ENV PATH="/opt/venv/bin:$PATH" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# Non-root user with a fixed UID, so Kubernetes can enforce runAsNonRoot / runAsUser.
RUN groupadd --gid 10001 silo \
    && useradd --uid 10001 --gid silo --no-create-home --shell /usr/sbin/nologin silo

COPY --from=builder /opt/venv /opt/venv

WORKDIR /app
COPY app ./app
COPY migrations ./migrations
COPY alembic.ini ./

USER 10001:10001
EXPOSE 8000
# Internal metrics port (METRICS_PORT); not part of the public Service.
EXPOSE 9000

# Liveness only; it does not check any dependency (same as /healthz).
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/healthz', timeout=2)"]

# --proxy-headers: the client IP and scheme come from Traefik. Which proxies are trusted is set
# with FORWARDED_ALLOW_IPS (deployment configuration).
CMD ["uvicorn", "app.main:create_app", "--factory", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers"]
