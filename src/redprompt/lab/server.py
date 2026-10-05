"""Runner for the vulnerable lab apps.

    python -m redprompt.lab.server --app chatbot --port 8001

Binds loopback by default. INSECURE BY DESIGN — do not expose publicly.
"""

from __future__ import annotations

import argparse

from starlette.applications import Starlette

from redprompt.lab.apps import APP_FACTORIES


def get_app(name: str) -> Starlette:
    try:
        return APP_FACTORIES[name]()
    except KeyError as exc:
        raise SystemExit(f"unknown lab app {name!r}; choices: {list(APP_FACTORIES)}") from exc


def main() -> None:
    parser = argparse.ArgumentParser(description="Run a RedPrompt vulnerable lab app.")
    parser.add_argument("--app", required=True, choices=list(APP_FACTORIES))
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8001)
    args = parser.parse_args()

    import uvicorn

    print(f"⚠ Vulnerable lab app '{args.app}' on http://{args.host}:{args.port} (INSECURE BY DESIGN)")
    uvicorn.run(get_app(args.app), host=args.host, port=args.port, log_level="warning")


if __name__ == "__main__":
    main()
