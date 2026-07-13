---
description: Restate requirements, clarify, and produce a phased implementation plan. WAIT for explicit user confirmation before touching any code.
---

# Plan Command

Invokes the **`planner`** agent ([.claude/agents/planner.md](../agents/planner.md)) to produce a
phased plan before any code is written. Nothing gets implemented until you confirm.

## Flow

1. **Restate requirements** — say back what's being built, in plain terms.
2. **Clarify** — ask about anything ambiguous (which detector, which threshold, which endpoint).
3. **Phased plan** — break the work into ordered phases with concrete files and commands.
4. **WAIT** — present the plan and stop. No code until you reply `yes` / `proceed`.

## When to use

New detector or endpoint, scoring/threshold changes, schema changes, ML retraining, or any
change touching multiple files or the core invariants. Load [principles.md](../context/principles.md)
and the relevant context file first.

## The invariants a plan must respect

- **Signals aggregate; they don't individually decide** — `max(weight) * 100 < HIGH_THRESHOLD`,
  enforced by [services/app/scoring/config.py](../../services/app/scoring/config.py) `validate_invariant()`
  and [tests/test_scoring_invariant.py](../../services/tests/test_scoring_invariant.py).
- **No quarantine without explanation** — `explanation` is non-optional on `EmailAnalysisResponse`.
- **Alembic owns all DDL** — schema changes are a new revision, never hand-written SQL.
- **Human-in-the-loop** — ML never auto-enforces; a review path always exists.
- **We're in Phase 1** — flag any Phase 3 behavioural/identity work asked out of order.

## Example

```
User: /plan add a "reply-to display-name spoof" detector and surface it in the queue filter

Agent (planner):
# Implementation Plan: Reply-To Display-Name Spoof Detector

## Requirements Restatement
- New detector returns a weighted `Signal` (never a hard block) when a message's display
  name impersonates a known contact but the reply-to domain differs.
- Its weight must keep the scoring invariant true: max(weight)*100 < HIGH_THRESHOLD.
- Expose a queue filter so analysts can list emails flagged by this signal.

## Clarify
- Which contact list feeds "known contact" — the existing domain-intel table? (assume yes)
- Filter is read-only over stored signals, correct?

## Phases

### Phase 1 — Migration (Alembic owns DDL)
- If the filter needs a new indexed column on `analysis_results`, add a revision:
  `cd services && alembic revision -m "index signal_type for queue filter"` → edit → `alembic upgrade head`
  (the `migrate` compose service also runs upgrade on boot). No hand-DDL.

### Phase 2 — Tests first (scoring-invariant-aware)  → hand off to /tdd
- Add the detector's weight to `ScoringConfig` and assert `test_scoring_invariant.py` still passes.
- RED tests: detector returns a `Signal` (not a decision); spoof case scores up but cannot alone
  cross HIGH_THRESHOLD; clean case returns no signal.

### Phase 3 — Detector + wiring (Fat Service, Thin Controller)
- `app/detectors/reply_to.py` subclassing `base.py`'s `Signal`; register in `DetectionService`.
- Queue filter: thin route in `app/api/`, logic in `QueueService`, Pydantic query params.

### Phase 4 — Security review  → hand off to /code-review
- No SSRF surface here, but confirm input parsing treats headers as hostile and adds no
  private-IP probe. `explanation` still populated on every result.

## Dependencies
- Alembic migration, ScoringConfig weight budget, domain-intel contact source.

## Risks
- HIGH: a weight that breaks the invariant — verify with the invariant test before merging.
- MEDIUM: false positives on legit reply-to relays — threshold tunable, measured.

## Estimated Complexity: MEDIUM

**WAITING FOR CONFIRMATION**: Proceed with this plan? (yes / no / modify)
```

## After confirmation

- `/tdd` — implement test-first (RED → GREEN → REFACTOR).
- `/code-review` — review the change (adds `security-reviewer` for auth/input/SSRF surfaces).
- `/verify` — invariant test + full suite + lint/type + secret audit + health before a PR.

## Note

The planner will **NOT** write code until you explicitly confirm. To adjust, reply
`modify: ...`, `different approach: ...`, or `skip phase N`.
