---
description: Append a concise, human-readable session summary to today's project session log — what was done, agents/commands used, files changed, key decisions.
---

# /log — Session Log

Summarize the current session and **append** a dated entry to
`.claude/session-logs/<YYYY-MM-DD>.md` under the project root. This project has **no Obsidian
vault** — it's a plain markdown file per day.

- Create `.claude/session-logs/` if it doesn't exist.
- **Append** to today's file; never overwrite an existing day's entries.
- **Source = this session's conversation, NOT git.** Recount what was actually done from the
  session. Use `git log` / `git diff --stat` only to confirm real committed `services/`,
  `frontend/`, or `ml/` changes.

## Capture, in plain language

- **What was done** — the work, in a sentence or two.
- **Agents / commands / skills used** — e.g. `/plan`, `planner`, `/tdd`, `security-review`.
- **Files changed** — created/edited paths.
- **Key decisions** — trade-offs, threshold/weight choices, invariant or migration notes.

## Format (append this block)

```markdown
## <HH:MM> — <short title>

- **Done:** <what happened>
- **Used:** <agents / commands / skills>
- **Files:** <paths created/edited>
- **Decisions:** <key choices, invariant/migration notes>
```

Keep it human and concise — a few lines, not a transcript.
