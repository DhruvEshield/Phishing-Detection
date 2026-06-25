# Frontend — Analyst Dashboard (`frontend/`)

> Load this when working in `frontend/` — the analyst-facing dashboard for review and triage.
>
> **Skills:** `frontend-patterns` (React/Next.js, state, performance), `tdd-workflow`,
> `api-design` (when shaping the contract with the backend).

## Responsibility

The human-in-the-loop surface. Surfaces flagged emails, risk scores, the **signal breakdown
that explains each score**, and Layer 2 alerts — so an analyst can review, triage, and record
a verdict. The analyst's decision feeds back into the corpus and scoring
(see the feedback loop in [architecture.md](architecture.md)).

This is where [principles.md](principles.md) #2 (human-in-the-loop) and #3 (explainability is a
feature) become concrete UI: no decision should be a black box to the analyst.

## Stack (intended direction — pin versions in `package.json` as code lands)

- **React + Next.js + TypeScript.** Consumes the backend API ([backend.md](backend.md)).

## Conventions

- **Explanation-first UI.** Every flagged email shows *why* — the weighted signals that
  produced its score — not just a number. Analysts must trust a decision before acting on it.
- **Review queue is the core loop.** Medium-risk emails land here; the verdict an analyst
  records is training data and a feedback signal, so capture it cleanly and completely.
- **Surface Layer 2 alerts** (behavioural / identity / relationship) alongside email triage —
  retroactive-review results need an analyst destination.
- Follow `frontend-patterns` for component structure, state management, and performance.
