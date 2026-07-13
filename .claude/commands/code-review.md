---
description: Security + quality review of uncommitted changes. Reports CRITICAL / HIGH / MEDIUM / LOW with file:line and a one-line fix. Blocks on CRITICAL or HIGH.
argument-hint: "[optional: scope to a specific path]"
---

# Code Review

Review of uncommitted changes. Defer the deep pass to the **`code-reviewer`** agent
([.claude/agents/code-reviewer.md](../agents/code-reviewer.md)). For anything touching
**auth / input parsing / SSRF (URL or QR probing) / secrets**, also run the
**`security-reviewer`** agent ([.claude/agents/security-reviewer.md](../agents/security-reviewer.md))
and the **`security-review`** skill.

1. Get changed files: `git diff --name-only HEAD` (and `git diff --staged`).

2. Check each changed file against this checklist:

**CRITICAL — block:**
- **Scoring invariant broken** — a single signal can independently push to quarantine
  (a hard-coded single-signal block, or a weight where `weight * 100 >= HIGH_THRESHOLD`).
  Verify against [services/app/scoring/config.py](../../services/app/scoring/config.py) `validate_invariant()`.
- **Explanation missing/optional** on a verdict or `EmailAnalysisResponse` — every result must
  carry a non-optional `explanation`.
- **Hand-written DDL** (raw `CREATE`/`ALTER`, or a model change with no matching revision in
  [services/alembic/versions/](../../services/alembic/versions/)) instead of an Alembic revision.
- **Secret hardcoded or logged** — `google_safe_browsing_key`, `phishtank_api_key`, `secret_key`
  must come from env, never appear in source or log lines.
- **SSRF** — a URL/redirect/RDAP probe with no timeout (`RDAP_TIMEOUT`, `HTTP_PROBE_TIMEOUT`),
  no `MAX_REDIRECT_HOPS`, or no private/internal-IP block.

**HIGH — block:**
- No **Pydantic** validation at the API boundary (raw dict / unvalidated request body).
- ML result used to **auto-enforce** without a review path (breaks human-in-the-loop).
- Functions > 50 lines; missing tests for new code (incl. an invariant-aware test); missing
  error handling (real failures must log at `error`, never a silent `except`).

**MEDIUM:**
- Detection/scoring logic in a route handler (violates Fat Service, Thin Controller).
- Raw SQL string interpolation instead of SQLAlchemy parameterization.
- Missing structured log / audit record on a verdict or analyst decision.

**LOW:**
- Mutation where an immutable pattern fits; minor a11y issues on the frontend.

3. Report — **SHORT (BINDING)**. One line per finding:
   `SEVERITY · file:line · issue · one-line fix`. Then a one-line verdict. No prose, no per-file
   walkthrough, no restating clean code beyond a single "rest clean" line. When relaying a
   sub-agent's review, extract only actionable findings — never paste its full output.

4. **Block commit if any CRITICAL or HIGH remains.**

Never approve code that breaks the scoring invariant, ships a verdict without an explanation, or
opens an SSRF hole.

## Chains with

`/plan` → `/tdd` → **`/code-review`** → `/verify`.
