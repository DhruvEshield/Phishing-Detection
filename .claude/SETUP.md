# `.claude/` setup — read this on a fresh machine

This folder gives Claude Code a planner, specialist agents, and slash commands tuned to
PhishDetect. It is **portable**: every path inside is project-relative, so it works for
anyone who checks out the repo — no per-machine editing needed.

## What's here
- `agents/` — specialist sub-agents (invoke by name, or via the commands below).
- `commands/` — slash commands: `/plan`, `/tdd`, `/code-review`, `/verify`, `/learn`, `/log`.
- `context/` — modular project knowledge the `../CLAUDE.md` router points at.
- `README.md` — the index / cheat-sheet.
- `settings.json` — permission allowlist (see below). **You add this file by hand.**

## One manual step: create `settings.json`

Claude Code will not write its own permission allowlist (that would let the agent widen
its own powers). So a human creates this file once. Create
`.claude/settings.json` with exactly this content:

```json
{
  "permissions": {
    "allow": [
      "Bash(sed -n *)",
      "Bash(awk *)",
      "Bash(grep *)",
      "Bash(rg *)",
      "Bash(ls *)",
      "Bash(wc *)",
      "Bash(find *)",
      "Bash(command -v *)",
      "Bash(docker compose *)",
      "Bash(docker exec *)",
      "Bash(docker inspect *)",
      "Bash(docker ps *)",
      "Bash(curl -s *)",
      "Bash(curl -sI *)",
      "Bash(curl -i *)",
      "Bash(git log *)",
      "Bash(git diff *)",
      "Bash(git --no-pager diff *)",
      "Bash(git status *)",
      "Bash(git show *)",
      "Bash(git ls-files *)",
      "Bash(git add *)",
      "Bash(git commit *)",
      "Bash(git push *)",
      "Bash(git checkout *)",
      "Bash(git stash *)",
      "Bash(pytest *)",
      "Bash(services/.venv/bin/pytest *)",
      "Bash(services/.venv/bin/python *)",
      "Bash(ruff check *)",
      "Bash(ruff format *)",
      "Bash(mypy *)",
      "Bash(alembic *)",
      "Bash(ml/.venv/bin/python *)",
      "Bash(mkdir -p *)",
      "Bash(chmod +x *)",
      "WebSearch"
    ],
    "additionalDirectories": [
      "/tmp"
    ]
  }
}
```

It only removes prompts for common, read-mostly dev commands (git, docker compose, pytest,
ruff/mypy, alembic). It grants nothing destructive. Tune it to taste — anything not listed
still works, it just asks first. Personal overrides go in `.claude/settings.local.json`
(gitignored).

## First-run checklist (new machine)
1. `cp .env.example .env` (or use the committed `.env`), then `docker compose up --build -d`.
2. Create `.claude/settings.json` from the block above.
3. Python envs for local ML/tests: the API/tests run in Docker, but for host-side ML work
   create `ml/.venv` and install `scikit-learn==1.6.1 joblib==1.4.2` (matches the API).
4. Open Claude Code in the repo root and try `/plan a small change` to confirm the agents load.

## Notes on portability
- **Committed** (shared with everyone): `agents/`, `commands/`, `context/`, `README.md`,
  `SETUP.md`, and `settings.json` once you add it.
- **NOT committed / per-person:** Claude Code's auto-memory
  (`~/.claude/projects/<this-project>/memory/`) is personal and machine-local — each person
  builds their own. `.claude/session-logs/` (written by `/log`) and
  `.claude/settings.local.json` are local too; add them to `.gitignore` if you don't want
  them shared.
