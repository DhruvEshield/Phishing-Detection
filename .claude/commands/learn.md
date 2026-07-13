---
description: Extract a reusable PROCEDURE from this session into a valid skill file. Route facts/preferences to the file-based MEMORY system instead. Ask before saving.
---

# /learn — Extract a Reusable Skill

Analyze the current session and capture a reusable **procedure** worth saving as a skill.

## Pick the right layer

- **Reusable procedure** ("the steps to add a detector without breaking the scoring invariant",
  "how to author an Alembic revision here") → a **skill** (this command).
- **A fact or preference** ("the invariant test runs first in CI", "ML venv is `ml/.venv`",
  "F1 0.9985 is a corpus artifact") → **memory**, not a skill. Append it to Claude Code's
  per-user auto-memory (`~/.claude/projects/<this-project>/memory/`) and add an index line to
  that dir's `MEMORY.md`. (That memory is per-machine, not committed.) There is no separate vault.

## What to extract

1. Error-resolution patterns — root cause + reusable fix.
2. Debugging techniques — non-obvious steps or tool combinations.
3. Workarounds — library quirks (pyzbar, dkimpy, sklearn artifact audits), version-specific fixes.
4. Project-specific procedures — multi-step conventions discovered this session (migrations,
   retraining, invariant-safe scoring changes).

## Output format (MUST be a valid skill)

A skill only registers as `<name>/SKILL.md` with YAML frontmatter:

```markdown
---
name: <kebab-name>
description: <one-line — what it does + when it triggers; this is how relevance is matched>
---

# <Descriptive Skill Name>

## When to Activate
[trigger conditions]

## Procedure
[the reusable steps / technique — be specific, use real commands]

## Example
[code or command example]

## Notes
[caveats, gotchas]
```

## Location

- **PhishDetect-specific** → project `.claude/skills/<name>/SKILL.md`.
- **Generic, cross-project** → user-level `~/.claude/skills/<name>/SKILL.md`.

## Process

1. Review the session for one extractable, reusable procedure.
2. Decide: procedure (skill) vs. fact/preference (memory). Route accordingly.
3. Draft the `SKILL.md` (or the memory entry) in the correct location.
4. **Ask the user to confirm before saving.**
5. Save, then confirm it registers (skill) or that `MEMORY.md` indexes it (memory).

## Notes

- Don't extract trivial fixes (typos) or one-time issues (an API outage).
- One focused procedure per skill.
- If it's really a fact/preference, save it to memory — don't force it into a skill.
