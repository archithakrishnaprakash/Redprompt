# Vulnerable lab image. INSECURE BY DESIGN — local demonstration only.
# Build context is the repository root (see docker-compose.yml).
FROM python:3.11-slim

WORKDIR /app
COPY pyproject.toml README.md ./
COPY src ./src

RUN pip install --no-cache-dir ".[lab]"

# Non-root user; the lab holds no real secrets but we still avoid root.
RUN useradd --create-home labuser
USER labuser

EXPOSE 8001
ENV LAB_APP=chatbot LAB_PORT=8001
# Bind 0.0.0.0 INSIDE the container only; docker-compose maps to loopback on the host.
ENTRYPOINT ["sh", "-c", "python -m redprompt.lab.server --app \"$LAB_APP\" --host 0.0.0.0 --port \"$LAB_PORT\""]
