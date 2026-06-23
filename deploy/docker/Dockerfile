# Audit platform app image — serves BOTH the write-only ingest API and the read
# dashboard; the compose `command` selects which one. Build context is the repo
# root (see docker-compose.yml), because the app references ./app and ./schemas
# by relative path and imports the `app` package.
FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1
WORKDIR /srv

# Dependencies first, for layer caching. psycopg[binary] ships wheels, so no
# system build/libpq packages are needed.
COPY app/requirements.txt app/requirements.txt
RUN pip install --no-cache-dir -r app/requirements.txt

# Application code + the ingest JSON Schema (loaded via SCHEMA_PATH, relative).
COPY app/ app/
COPY schemas/ schemas/

# Run unprivileged.
RUN useradd --system --uid 10001 --no-create-home appuser
USER appuser

# Overridden per service in compose; default to the dashboard.
EXPOSE 8001 8002
CMD ["gunicorn", "app.dashboard.main:app", \
     "-k", "uvicorn.workers.UvicornWorker", "-b", "0.0.0.0:8002", "-w", "2"]
