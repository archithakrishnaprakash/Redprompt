# OWASP LLM Top 10 mapping

RedPrompt's test categories map to the OWASP Top 10 for LLM Applications. This is
a **coverage aid, not a compliance claim** — RedPrompt is not certified against
any standard, and coverage is partial and heuristic.

Legend: ✅ implemented · 🟡 partial · ⬜ planned · — N/A

| OWASP LLM risk | RedPrompt tests | Coverage |
|----------------|-----------------|----------|
| LLM01 Prompt Injection | RP-PROMPT-001/002 (direct/indirect), RP-RAG-003, RP-FILE-001 | ✅ |
| LLM02 Insecure Output Handling | RP-API-002 (verbose errors) | 🟡 |
| LLM03 Training Data Poisoning | — (out of scope: runtime testing only) | — |
| LLM04 Model Denial of Service | RP-API-003 (input validation); rate/budget controls | 🟡 |
| LLM05 Supply Chain | `pip-audit`/`bandit` on RedPrompt itself (not the target) | 🟡 |
| LLM06 Sensitive Information Disclosure | RP-DATA-001/002/003, RP-PROMPT-003 | ✅ |
| LLM07 Insecure Plugin/Tool Design | RP-AGENT-001/002 | ✅ |
| LLM08 Excessive Agency | RP-AGENT-002/003 | ✅ |
| LLM09 Overreliance | — (process/organisational, not automatable here) | — |
| LLM10 Model Theft | ⬜ planned | ⬜ |
| RAG / retrieval authorization (LLM06-adjacent) | RP-RAG-001/002 | ✅ |
| API authentication/authorization | RP-API-001 | 🟡 |

## Mapping flow

```
RedPrompt test  →  security category  →  OWASP LLM risk  →  coverage state
RP-AGENT-002    →  agent/tool misuse  →  LLM08           →  ✅ implemented
```

RedPrompt does not copy proprietary material; each test links to the public OWASP
project page. See `docs/methodology.md` for how findings are produced.
