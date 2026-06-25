# Engineering Principles & Working Agreement

> Load this for any non-trivial change — these are the non-negotiables that follow from the
> problem and the production-MVP target. Hold the line on them.

## Principles

1. **Signals aggregate; they don't individually decide.** Every detector contributes a weighted
   signal to a risk score. Avoid hard-coded single-signal blocks. Keep weights configurable and
   auditable.
2. **Human-in-the-loop by default.** No fully automated enforcement on ML decisions. Always
   provide a review path and an explanation.
3. **Explainability is a feature, not a nice-to-have.** Every score should be traceable to the
   signals that produced it. Phase 2 formalises this; design for it from Phase 1.
4. **Preserve the feedback loop.** Layer 2 → Layer 1 (scoring/blocklists) and Layer 1 → Layer 2
   (context). Don't build components that break this flow. See [architecture.md](architecture.md).
5. **Capture data early for later phases.** Phase 3 baselines depend on history that only exists
   if Phase 1 stored it. Log email metadata, verdicts, and analyst decisions from the start
   (within governance constraints).
6. **Calibrate for false positives.** Layered detection raises coverage *and* false-positive
   risk. Thresholds must be tunable and measured. Usability erosion kills analyst trust.
7. **Security & privacy first.** Handles email content and account metadata — treat all of it as
   sensitive: least-privilege, encryption, audit trails, retention controls. Use the
   `security-review` skill when touching auth, input handling, secrets, or new endpoints.
8. **Measurable at each stage.** Every phase delivers value standalone and exposes metrics
   (detection rate, false-positive rate, analyst load). "Better, measurably" over "perfect".
9. **Models drift — plan for retraining.** Treat every ML model as a maintained asset with a
   retraining path, not a one-time artifact.

## Working agreement for AI assistants

- **Read [original plan.md](../../original%20plan.md) for the "why"; read the slim
  [CLAUDE.md](../../CLAUDE.md) for the "how" and which context file to load.** If the two ever
  conflict, the plan wins on product intent — update the docs to match.
- **Respect the phase order.** Don't build Phase 3 behavioural analytics before Phase 1's data
  pipeline exists — call it out if asked to skip ahead. See [roadmap.md](roadmap.md).
- **Keep the docs current.** When you add a dependency, service, directory, or make an
  architectural decision, update the relevant `.claude/context/` file (and the slim CLAUDE.md
  index if the map changed) so the next assistant inherits it.
- **Prefer rules before ML.** Only introduce a model where [ml.md](ml.md) justifies it.
- **When scope vs. cost is in tension** (sandboxing, infra), favour the scoped, cost-aware
  option and flag the trade-off — a recurring theme across all phases.
