# RedPrompt application image (CLI + REST API/dashboard).
FROM python:3.11-slim AS base

ENV PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
WORKDIR /app

COPY pyproject.toml README.md ./
COPY src ./src
COPY migrations ./migrations
COPY alembic.ini ./

RUN pip install ".[api]"

# Run as non-root.
RUN useradd --create-home app && chown -R app:app /app
USER app

EXPOSE 8080
# Default: show help. Override CMD to run e.g. `serve --host 0.0.0.0`.
ENTRYPOINT ["redprompt"]
CMD ["--help"]
