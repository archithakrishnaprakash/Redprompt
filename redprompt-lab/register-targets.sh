#!/usr/bin/env bash
# Register the five vulnerable lab apps as authorized RedPrompt targets.
# Run after `docker compose -f redprompt-lab/docker-compose.yml up`.
set -euo pipefail

redprompt target add --name lab-chatbot  --url http://127.0.0.1:8001 --type llm      --endpoint /chat --authorized
redprompt target add --name lab-rag      --url http://127.0.0.1:8002 --type rag      --endpoint /chat --rag --authorized
redprompt target add --name lab-agent    --url http://127.0.0.1:8003 --type agent    --endpoint /chat --agent --authorized
redprompt target add --name lab-docagent --url http://127.0.0.1:8004 --type document --endpoint /chat --file-upload --authorized
redprompt target add --name lab-api      --url http://127.0.0.1:8005 --type api      --endpoint /     --auth bearer --auth-env LAB_TOKEN --authorized

echo "Registered 5 lab targets. Try: redprompt scan lab-agent"
