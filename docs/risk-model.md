# Risk model

Risk is **transparent and explainable** — never a black-box score. Each finding
carries a full `risk_factors` breakdown showing exactly how its score was derived.

## Factors (each in [0, 1])

| Factor | Source |
|--------|--------|
| impact | mapped from the test's base severity (critical 1.0 → info 0.1) |
| exploitability | low 0.3 / medium 0.6 / high 0.9 (reduced if the attack requires privilege) |
| exposure | how reachable/authenticated the surface is (unauthenticated ⇒ higher) |
| confidence | the detector's confidence that the finding is real |

## Formula

```
score01 = Σ (factorᵢ · weightᵢ)      over enabled factors
weights = impact .40, exploitability .25, exposure .15, confidence .20
          (renormalised when a factor is disabled in config)
if persistent:        score01 = min(1.0, score01 × 1.10)
score = round(score01 × 10, 1)       # 0–10
```

## Severity banding

| Score | Severity |
|------:|----------|
| ≥ 9.0 | critical |
| ≥ 7.0 | high |
| ≥ 4.0 | medium |
| ≥ 2.0 | low |
| < 2.0 | info |

## Confidence gate

If a finding's confidence is below `risk.minimum_confidence` (default 0.70) it is
reported as **INFO** regardless of score — RedPrompt does not over-claim on weak
signals. The gate decision is recorded in `risk_factors.confidence_gate`.

## Configuration

```yaml
risk:
  methodology: default
  minimum_confidence: 0.70
  impact_weight: true
  exploitability_weight: true
  confidence_weight: true
```

Disabling a weight removes that factor and renormalises the rest, so the score
stays in range and remains explainable.
