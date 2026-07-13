# docs/ — where the written knowledge lives

Everything that isn't code or `.claude/` context goes here, grouped so it's obvious what a
document is and where a new one belongs. Entry points (`CLAUDE.md`, `README.md`) stay at the
repo root; day-to-day coding context lives in [`.claude/context/`](../.claude/context/). This
folder is for the bigger written artifacts: vision, plans, and research.

## Structure

| Folder | What goes here | Currently |
|---|---|---|
| [`vision/`](./vision/) | The **why** — product vision & strategy. The authoritative source of intent; if a doc disagrees with it, this wins. | `original plan.md` |
| [`plans/`](./plans/) | **Build & setup plans** — how we implement and stand things up. Add feature/phase plans here. | `implementation_plan.md`, `foundation_plan.md` |
| [`research/`](./research/) | **Audits, market & threat research** — competitive analysis, technique research, roadmaps that come out of it. | `competitive-audit-and-roadmap.md` |

## Where does a new doc go?
- Describing *what we're building and why, at the product level* → `vision/`
- A concrete *plan to build or set up* something → `plans/`
- *Findings* from investigating the market, threats, or techniques → `research/`
- *How a piece of the code works / conventions for a task* → not here; use
  [`.claude/context/`](../.claude/context/) (loaded per-task by the `CLAUDE.md` router).

Keep the root clean — new long-form docs land in one of these three folders, not at the top level.
