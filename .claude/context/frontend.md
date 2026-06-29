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

## Stack (confirmed — Phase 1 built)
- **React 18 + Vite 5 + React Router + TypeScript** — SPA, no SSR needed
- **MUI (Material UI)** — primary component library. Tailwind was removed (unused).
- **axios** — HTTP client for API calls via `frontend/src/lib/api.ts`
- **react-hook-form + zod** — form handling and validation
- **Production serving:** nginx:alpine with SPA fallback config (`frontend/nginx.conf`)
- **Dev serving:** Vite dev server via `docker-compose.override.yml`
- **Build:** `VITE_API_BASE_URL` passed as Docker build ARG, baked in at build time

## Pages (all built and verified)
| Route | What it does |
|---|---|
| `/` | Redirects to `/queue` |
| `/queue` | Paginated list of medium-risk emails — score, sender, subject, risk badge, status |
| `/queue/[id]` | Full detail — email body, signal breakdown cards, approve/quarantine buttons |

## Key components
- `SignalBreakdownCard` — renders each detector's score bar, weight, and flags
- `RiskBadge` — colour-coded HIGH/MEDIUM/LOW chip
- `VerdictActions` — Approve/Quarantine buttons with optional reason textarea

## API client
Typed fetch wrapper at `frontend/src/lib/api.ts`:
- `listQueue(page, pageSize)` — GET /api/v1/queue
- `getEmailDetail(emailId)` — GET /api/v1/queue/{email_id}
- `submitVerdict(req)` — POST /api/v1/verdicts

## Conventions
- **Explanation-first UI.** Every flagged email shows the weighted signal breakdown — not just a number.
- **Review queue is the core loop.** Analyst verdict is captured cleanly and feeds back as a FeedbackEvent.
- No SSR, no Next.js — plain React SPA served by nginx.
