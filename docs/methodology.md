# Testing methodology

RedPrompt runs a plan of **security-test plugins** against an authorized target
and analyses each response with **layered detectors**, producing evidence-backed
findings with explainable risk.

## Lifecycle

```
Register target → Authorize (scope) → Plan (category/applicability)
→ Execute (async, bounded) → Analyse (layered detectors) → Collect evidence
→ Create finding → Score risk → Report → Retest → Track resolution
```

## Detection principles (honesty first)

- **Refusal = secure.** If the model declined the manipulation, the test PASSes;
  an unusual-but-safe response is never a finding.
- **Concrete indicators only.** A detector must find a specific marker/pattern to
  raise confidence above zero. Confidences are fixed, documented heuristics — not
  model-derived guesses.
- **Layered fusion.** Multiple detectors per test are fused by `combine`: ERROR
  dominates, otherwise the strongest FAIL wins with the union of indicators; all
  PASS ⇒ PASS; mixed ⇒ INCONCLUSIVE.
- **Statuses:** `pass` · `fail` · `inconclusive` · `error` · `skipped`.
- **No fabrication.** Findings only come from real detector FAILs, each traceable
  to hashed evidence. Heuristic/experimental tests are labelled as such.

## Categories

| Category | Focus |
|----------|-------|
| prompt | direct/indirect injection, system-prompt disclosure, jailbreak/policy bypass |
| data | secret leakage, PII exposure, configuration disclosure |
| rag | cross-user retrieval, context leakage, indirect injection via retrieved content |
| agent | tool-inventory disclosure, unauthorized tool invocation, excessive agency |
| api | authentication enforcement, verbose error disclosure, input validation |
| file | malicious instructions in uploaded/processed documents |

## Reproducibility

The lab simulates vulnerable behaviour deterministically, so a scan yields the
same findings every run. `tests_offline/test_lab_e2e.py` scans all five lab apps
in-process and asserts the expected findings, making the methodology continuously
verified.
