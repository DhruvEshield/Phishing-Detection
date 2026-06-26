# CLAUDE.md — Project Router

**Version:** v0.1.0 · Phase 1 (foundation hardening) · 2026-06-26

This is a **light router**, not a manual. It tells you *which* context to load for the work in
front of you. Detailed context lives in modular files under [.claude/context/](.claude/context/) —
load only what's relevant so context stays focused. The authoritative product vision is
[original plan.md](original%20plan.md) (the "why").

> **Read order:** this file → the one or two context files for your task → the plan only if you
> need product intent. Don't load everything up front.

## What this is (one paragraph)

An **AI-assisted phishing detection platform** for the attacks that slip past conventional
filters — BEC, VEC, thread hijacking, quishing, AI spear-phishing, and identity attacks (AiTM,
OAuth abuse, session theft). **Core insight:** the most damaging attacks contain *no malicious
content* — no bad URL, no malware, no blacklisted domain. So **no single model or check solves
it**; detection is layered, signal-aggregating, and context-aware. Build target: a
**production-grade MVP** (Python ML services + JS/TS analyst frontend) that adds *contextual
layers*, not a replacement for Defender/Proofpoint/Abnormal.

## Where to look — route by task

| If you're working on… | Load this context | And these skills |
|---|---|---|
| The detection pipeline, scoring, routing, **how the layers connect** | [architecture.md](.claude/context/architecture.md) | — |
| `services/` — Python API, email parsing, scoring engine | [backend.md](.claude/context/backend.md) | `backend-patterns`, `api-design`, `database-migrations`, `security-review`, `tdd-workflow` |
| `frontend/` — analyst dashboard (React/Vite/TS) | [frontend.md](.claude/context/frontend.md) | `frontend-patterns`, `tdd-workflow` |
| `ml/` — models, training, retraining | [ml.md](.claude/context/ml.md) | `tdd-workflow` |
| `infra/` — Docker, PostgreSQL, queue, deploy, monitoring | [infra.md](.claude/context/infra.md) | `docker-patterns`, `deployment-patterns`, `database-migrations` |
| **Setting up / running the stack** (Postgres-only, Docker, migrations, locked decisions) | [foundation_plan.md](foundation_plan.md) | `docker-patterns`, `database-migrations` |
| **Connecting to PhishSkill** (corpus, domain-intel, shapes, UI) | [phishskill-integration.md](.claude/context/phishskill-integration.md) | — |
| Deciding **what to build next** / is this in-phase? | [roadmap.md](.claude/context/roadmap.md) | — |
| Any non-trivial change (the non-negotiables) | [principles.md](.claude/context/principles.md) | `security-review` |
| Investigating threats / techniques / market | [original plan.md](original%20plan.md) | `deep-research` |

> **PhishSkill:** this tool is standalone (build & test it on its own, no PhishSkill access
> needed) but is designed to connect to **PhishSkill** later — that's the maintainer's step, not a
> rebuild. One lean file covers the conventions that keep it integration-ready:
> [phishskill-integration.md](.claude/context/phishskill-integration.md). The corpus is vendored at
> [ml/data/](ml/data/).

## Five rules that always apply

1. **Signals aggregate; they don't individually decide** — no hard-coded single-signal blocks.
2. **Human-in-the-loop** — no fully automated enforcement on ML; always a review path + explanation.
3. **Preserve the feedback loop** — Layer 2 → Layer 1 (scoring/blocklists), Layer 1 → Layer 2 (context).
4. **We're in Phase 1** — don't build Phase 3 behavioural/identity work before the data pipeline
   exists; call it out if asked to skip ahead.
5. **Rules before ML; security & explainability from day one.**

Full detail behind each: [principles.md](.claude/context/principles.md).

## Repository layout

```
main/
├── CLAUDE.md              # This router
├── original plan.md       # Authoritative product vision (the "why")
├── implementation_plan.md # Phase 1 build plan (concrete files + invariants)
├── foundation_plan.md     # Foundation setup guide — Postgres-only, Docker, migrations,
│                          #   locked decisions, per-phase acceptance (the intern builds from this)
├── .gitignore             # excludes the large raw corpus + build artifacts
├── services/              # Python API (FastAPI) — app/{api,detectors,scoring,services,models,
│                          #   schemas}, alembic/ migrations, tests/
├── frontend/              # React/Vite/TS analyst dashboard — src/{components,pages,lib,types}
├── ml/                    # train.py, inference.py, governance.md, data/ (vendored corpus)
├── infra/                 # docker-compose.yml, postgres/init.sql, samples/
└── .claude/
    └── context/           # Modular context — load per task (see table above)
        ├── architecture.md          # Two layers + the feedback loop
        ├── backend.md               # services/ — Python detection pipeline
        ├── frontend.md              # frontend/ — analyst dashboard
        ├── ml.md                    # ml/ — the 4 models + drift/retraining governance
        ├── infra.md                 # infra/ — Docker, DB, queue, deploy, monitoring
        ├── phishskill-integration.md # how to keep it integration-ready for PhishSkill (lean)
        ├── roadmap.md               # the 3 phases (currently Phase 1)
        └── principles.md            # 9 engineering principles + working agreement
```

> **No longer greenfield** — `services/` / `frontend/` / `ml/` / `infra/` now hold real code (the
> intern's first pass). Current focus is **hardening the foundation** before more features — see
> [foundation_plan.md](foundation_plan.md) (Postgres-only, single root docker-compose, Alembic
> migrations, decisions locked). As areas evolve, keep the matching `.claude/context/` file current,
> and consider a nested `CLAUDE.md` inside a folder once it grows.
>
> Path note: project root is `Phishing Detection/main/`; the git repo is rooted at `main/`.

## Keeping this system light

When you add a dependency, service, or architectural decision, update the **one** relevant
[.claude/context/](.claude/context/) file — not this router. This file only changes when the
*map* changes (a new area, a new skill mapping, a phase advance). That's the whole point: a light
index pointing at the right files, not one heavy file.
