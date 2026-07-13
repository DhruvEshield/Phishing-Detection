# `.claude/` — PhishDetect agents, commands & context

This folder is the working layer for Claude Code on PhishDetect. It has three parts:

## `context/` — modular project knowledge (load per task)
The [CLAUDE.md](../CLAUDE.md) router points here. Load only what the task needs:
`architecture.md`, `backend.md`, `frontend.md`, `ml.md`, `infra.md`, `principles.md`,
`roadmap.md`, `phishskill-integration.md`.

## `agents/` — specialist sub-agents (invoke by name via the Agent tool)
Each is re-targeted to PhishDetect's stack (FastAPI · SQLAlchemy · Alembic · Pydantic ·
pytest · Vite/React/MUI · the ML pipeline) and the [5 rules](../CLAUDE.md).

| Agent | Use it for |
|---|---|
| `planner` | Turn a request into a phased, clarify-first implementation plan. Waits for your confirmation before code. |
| `architect` | System/pipeline design — signal aggregation, scoring engine, feedback loop, Phase-1 scope. |
| `code-reviewer` | Review uncommitted changes for correctness + the project invariants. |
| `security-reviewer` | SSRF (URL probing), untrusted email/attachment/QR parsing, secrets, explainability. |
| `tdd-guide` | RED→GREEN→REFACTOR with pytest; the scoring-invariant test is the mandatory pillar. |
| `brainstormer` | No-code divergent ideation grounded in the hard constraints. |
| `doc-updater` | Keep `context/*.md` and the `CLAUDE.md` router in sync with the code. |

## `commands/` — slash commands (type `/name`)
| Command | Does |
|---|---|
| `/plan` | Invoke `planner` → restate, clarify, phase, **wait for confirmation**. |
| `/tdd` | Invoke `tdd-guide` → tests first, minimal impl, refactor, coverage. |
| `/code-review` | Invoke `code-reviewer` (+ `security-reviewer` for auth/input/SSRF) on the diff. |
| `/verify` | Ordered gate: invariant test → pytest+cov → ruff+mypy → secret audit → app health → git status. |
| `/learn` | Extract a reusable procedure into a `SKILL.md` (facts go to memory instead). |
| `/log` | Append a session summary to `.claude/session-logs/<date>.md`. |

**Typical loop:** `/plan` → `/tdd` → `/code-review` → `/verify`.

## The doctrine every agent/command enforces
1. Signals aggregate; no single signal independently decides — enforced by
   `ScoringConfig.validate_invariant()` + [tests/test_scoring_invariant.py](../services/tests/test_scoring_invariant.py).
2. Human-in-the-loop — ML never auto-quarantines; a review path + explanation always exist.
3. Preserve the feedback loop (Layer 2 ⇄ Layer 1).
4. We're in Phase 1 — don't build Phase 3 work early.
5. Rules before ML; security & explainability from day one.

## Notes
- **Portable by design.** Every path in these files is project-relative (`services/...`,
  `.claude/context/...`) — nothing is tied to one person's machine, so this folder works
  as-is for anyone who checks out the repo.
- Facts/preferences/project state live in Claude Code's per-user **auto-memory**
  (`~/.claude/projects/<this-project>/memory/`, loaded via its `MEMORY.md` index). That
  memory is personal and per-machine — it is NOT committed with the repo, so each person
  builds their own over time.
- `settings.json` (permission allowlist for this stack) reduces permission prompts. It is
  committed so the whole team shares it — see [SETUP.md](./SETUP.md) for the exact contents
  to drop in (Claude won't self-grant permissions, so a human adds this file once).
