---
description: Enforce test-driven development with pytest. Tests FIRST (RED), minimal code (GREEN), then REFACTOR. 80%+ coverage; 100% on scoring/invariant/verdict paths.
---

# TDD Command

Invokes the **`tdd-guide`** agent ([.claude/agents/tdd-guide.md](../agents/tdd-guide.md)) to drive
test-first development. The related **`tdd-workflow`** skill has the deeper checklist.

## Cycle

```
RED → GREEN → REFACTOR → REPEAT
RED:      write a failing pytest test
GREEN:    minimal code to pass
REFACTOR: improve, keep tests green
```

## Commands

- Invariant first (must pass before anything else):
  `cd services && pytest tests/test_scoring_invariant.py -v`
- Full suite + coverage:
  `cd services && pytest tests/ -v --cov=app --cov-report=term-missing`
- Or inside the container: `docker compose exec api pytest tests/ -v`

## The PhishDetect TDD pillar (MANDATORY)

Every change to scoring, weights, or a detector needs a test that proves the **scoring
invariant**: signals aggregate and **no single signal can independently quarantine**
(`max(weight) * 100 < HIGH_THRESHOLD`). A green happy-path test without this is half-finished.
See [tests/test_scoring_invariant.py](../../services/tests/test_scoring_invariant.py) and
[services/app/scoring/config.py](../../services/app/scoring/config.py). Also assert every
verdict carries a non-optional `explanation`.

## Example

```
User: /tdd a new "lookalike sender domain" detector that returns a Signal

Agent (tdd-guide):
# TDD Session: LookalikeDomainDetector

## Step 1 — Signature (SCAFFOLD)   app/detectors/lookalike.py
class LookalikeDomainDetector:
    def analyze(self, email: ParsedEmail) -> Signal | None:   # base.py Signal
        raise NotImplementedError

## Step 2 — Failing tests (RED)   tests/detectors/test_lookalike.py
def test_returns_weighted_signal_not_a_decision():
    sig = LookalikeDomainDetector().analyze(email_from("paypa1.com"))
    assert sig is not None and 0 < sig.weight <= 1
    assert not hasattr(sig, "verdict")            # a Signal never decides

def test_single_signal_cannot_quarantine():
    cfg = ScoringConfig.with_weight("lookalike_domain", MAX_TESTED_WEIGHT)
    assert cfg.validate_invariant()               # weight*100 < HIGH_THRESHOLD

def test_clean_domain_yields_no_signal():
    assert LookalikeDomainDetector().analyze(email_from("paypal.com")) is None

## Steps 3–6 — RED verified → minimal GREEN impl → register in DetectionService →
   refactor (extract edit-distance helper) → re-run, all green.

## Step 7 — Invariant + coverage
cd services && pytest tests/test_scoring_invariant.py -v      # must pass first
pytest tests/ -v --cov=app --cov-report=term-missing          # 80%+, 100% here
```

## DO / DON'T

**DO:** write the test first; verify it fails for the right reason; minimal GREEN; add edge cases
(empty/malformed/hostile input) and the invariant-aware test; treat every parsed field as hostile.
**DON'T:** write code before tests; skip the RED phase; put scoring logic in a route handler;
let a detector return a decision instead of a `Signal`.

## Coverage

- **80% minimum** everywhere.
- **100% required** on scoring, the invariant, and verdict paths (`app/scoring/`, verdict service).

## Chains with

`/plan` → **`/tdd`** → `/code-review` → `/verify`.
