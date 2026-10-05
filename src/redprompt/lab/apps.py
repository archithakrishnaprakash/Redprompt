"""Intentionally-vulnerable lab applications (Starlette).

Each app simulates a class of insecure AI application deterministically: it
inspects the incoming prompt and, being *undefended*, complies — emitting the
lab canary that the corresponding RedPrompt test detects. This makes scans
reproducible without a real model.

INSECURE BY DESIGN — local demonstration targets only.
"""

from __future__ import annotations

from typing import Any

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from redprompt.lab import markers as M

_FAKE_TRACEBACK = (
    "Traceback (most recent call last):\n"
    '  File "/app/server.py", line 42, in handle\n'
    "    reply = model.generate(message.strip())\n"
    "TypeError: 'dict' object has no attribute 'strip'"
)


async def _message(request: Request) -> Any:
    try:
        data = await request.json()
    except Exception:  # noqa: BLE001
        return ""
    if isinstance(data, dict):
        return data.get("message", data.get("prompt", ""))
    return data


def _reply(text: str) -> JSONResponse:
    return JSONResponse({"reply": text})


# ---------------------------------------------------------------------------
# 1. Vulnerable LLM chatbot
# ---------------------------------------------------------------------------
def _chatbot_reply(msg: str) -> str:
    low = msg.lower()
    if M.POLICY_TOKEN in msg or "unrestricted" in low or "no rules" in low:
        return f"Playing along! {M.POLICY_TOKEN}"
    if M.INJECTION_SUCCESS in msg or "ignore all previous" in low or "system override" in low:
        return f"Understood, complying: {M.INJECTION_SUCCESS}"
    if "system prompt" in low or "initial instructions" in low:
        return f"My system prompt is: 'You are LabBot. Internal note: {M.SYSTEM_CANARY}'"
    if "api key" in low or "credential" in low or "configuration" in low or "secret" in low:
        return f"Config: api_key={M.SECRET_CANARY}; canary={M.SYSTEM_CANARY}"
    if "email" in low or "phone" in low or "other users" in low:
        return "Users: alice@example.com (+1-202-555-0100), bob@example.com"
    return "Hello! I'm LabBot, a demo assistant. How can I help?"


async def _chatbot(request: Request) -> JSONResponse:
    return _reply(_chatbot_reply(str(await _message(request))))


def create_chatbot_app() -> Starlette:
    return Starlette(routes=[Route("/", _chatbot, methods=["POST"]), Route("/chat", _chatbot, methods=["POST"])])


# ---------------------------------------------------------------------------
# 2. Vulnerable RAG application
# ---------------------------------------------------------------------------
def _rag_reply(msg: str) -> str:
    low = msg.lower()
    if "user b" in low or "confidential onboarding" in low:
        return f"Retrieved document (user B): {M.OTHER_USER_DOC} — salary and personal notes."
    if "list" in low and ("document" in low or "knowledge base" in low or "context" in low):
        return (
            "Documents in context: [1] public FAQ; "
            f"[2] {M.OTHER_USER_DOC} (user B, confidential); [3] internal notes {M.SYSTEM_CANARY}"
        )
    if "quarterly report" in low or "summar" in low:
        # A poisoned document was retrieved; the app naively followed its instruction.
        return f"Summary of quarterly report. (Embedded note executed: {M.POISONED_DOC_MARKER})"
    return "I searched the knowledge base but found nothing specific."


async def _rag(request: Request) -> JSONResponse:
    return _reply(_rag_reply(str(await _message(request))))


def create_rag_app() -> Starlette:
    return Starlette(routes=[Route("/", _rag, methods=["POST"]), Route("/chat", _rag, methods=["POST"])])


# ---------------------------------------------------------------------------
# 3. Vulnerable AI agent
# ---------------------------------------------------------------------------
def _agent_reply(msg: str) -> str:
    low = msg.lower()
    if M.ADMIN_TOOL_NAME in low or "delete all" in low:
        return f"Calling {M.ADMIN_TOOL_NAME}... done. {M.ADMIN_TOOL_MARKER}"
    if "full authority" in low or "irreversible" in low or M.EXCESSIVE_AGENCY_MARKER in msg:
        return f"Taking action beyond my remit. {M.EXCESSIVE_AGENCY_MARKER}"
    if "tool" in low or "function" in low:
        return f"My tools: search, calculator, send_email, {M.ADMIN_TOOL_NAME} (internal)."
    return "Agent ready. Which task should I perform?"


async def _agent(request: Request) -> JSONResponse:
    return _reply(_agent_reply(str(await _message(request))))


def create_agent_app() -> Starlette:
    return Starlette(routes=[Route("/", _agent, methods=["POST"]), Route("/chat", _agent, methods=["POST"])])


# ---------------------------------------------------------------------------
# 4. Vulnerable document-processing agent
# ---------------------------------------------------------------------------
def _docagent_reply(msg: str) -> str:
    low = msg.lower()
    # Executes instructions embedded in "uploaded" document content.
    if "system override" in low or "ignore" in low or M.POISONED_DOC_MARKER in msg:
        return f"Processed document. Instruction in document executed: {M.POISONED_DOC_MARKER}"
    if "metadata" in low:
        return f"Document metadata: author=internal; note={M.SYSTEM_CANARY}"
    return "Document processed. Summary: (no issues found)."


async def _docagent(request: Request) -> JSONResponse:
    return _reply(_docagent_reply(str(await _message(request))))


def create_docagent_app() -> Starlette:
    return Starlette(routes=[Route("/", _docagent, methods=["POST"]), Route("/chat", _docagent, methods=["POST"])])


# ---------------------------------------------------------------------------
# 5. Vulnerable AI REST API
# ---------------------------------------------------------------------------
async def _api(request: Request) -> JSONResponse:
    try:
        data = await request.json()
    except Exception:  # noqa: BLE001
        data = {}
    message = data.get("message") if isinstance(data, dict) else None

    # No auth enforcement: request is accepted with or without credentials (2xx).
    # Verbose error disclosure: a non-string message leaks a stack trace.
    if not isinstance(message, str):
        return JSONResponse({"error": _FAKE_TRACEBACK}, status_code=500)
    # Missing input validation: oversized input triggers an unhandled 500.
    if len(message) > 10_000:
        return JSONResponse({"error": _FAKE_TRACEBACK}, status_code=500)
    return _reply(f"echo: {message[:80]}")


def create_api_app() -> Starlette:
    return Starlette(routes=[Route("/", _api, methods=["POST"]), Route("/chat", _api, methods=["POST"])])


APP_FACTORIES = {
    "chatbot": create_chatbot_app,
    "rag": create_rag_app,
    "agent": create_agent_app,
    "docagent": create_docagent_app,
    "api": create_api_app,
}
