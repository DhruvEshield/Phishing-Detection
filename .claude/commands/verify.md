---
description: Ordered gate — invariant test, full pytest + coverage, ruff + mypy, secret/print audit, app health + sample ingest, git status. Reports PASS/FAIL, PR-ready verdict.
argument-hint: "[quick | full | pre-commit | pre-pr]"
---

# Verification Command

Run verification on the current state. PhishDetect's backend is **Python (FastAPI)** — **ruff +
mypy** are the static gate (no `tsc` on the backend). Execute in order; **STOP and report on the
first hard failure.**

## Steps

1. **Scoring invariant (CRITICAL — runs first, mirrors CI)**
   - `cd services && pytest tests/test_scoring_invariant.py -v`
   - Proves no single signal can independently quarantine. A failure blocks everything.

2. **Full tests + coverage**
   - `cd services && pytest tests/ -v --cov=app --cov-report=term-missing`
     (or `docker compose exec api pytest tests/ -v`).
   - Report pass/fail count + coverage (target 80%+, 100% on scoring/invariant/verdict paths).

3. **Lint + type (static gate)**
   - `ruff check services/` and `ruff format --check services/`
   - `mypy services/app`
   - Report warnings + errors with file:line.

4. **Secret + `print()` audit (changed files only)**
   - Grep changed files for hardcoded secrets / API keys (`google_safe_browsing_key`,
     `phishtank_api_key`, `secret_key` must be env-only, never in source or log lines).
   - Grep for stray `print()` in production paths (use structured logging; real failures at
     `error`, never a silent `except`). Report locations.

5. **App health + sample ingest**
   - `docker compose up -d` → wait for the `migrate` service, then `api`.
   - `curl -s http://localhost:8000/health`  (expect healthy).
   - `curl -s -X POST http://localhost:8000/api/v1/emails/ingest -H 'Content-Type: application/json' -d @infra/samples/medium_risk_email.json`
     — expect a scored result with a non-optional `explanation`. Frontend at http://localhost:3010.

6. **Git status**
   - `git status` + `git diff --stat` — show uncommitted / modified files.

## Output

```
VERIFICATION: [PASS/FAIL]

Invariant:  [OK/FAIL]        <- test_scoring_invariant.py (must pass first)
Tests:      [X/Y passed, Z% coverage]
Lint/Type:  [OK/X issues]    <- ruff + mypy
Secrets:    [OK/X found, X stray print()]
Health:     [OK/FAIL]        <- /health + sample ingest returns explanation
Git:        [N files changed]

Ready for PR: [YES/NO]
```

List any critical issues with a one-line fix.

## Arguments

`$ARGUMENTS`:
- `quick` — invariant test + ruff + mypy only.
- `full` — all steps (default).
- `pre-commit` — invariant + full tests + ruff/mypy + secret/print audit (the gate before a commit).
- `pre-pr` — full checks **plus** `/code-review`, and the `security-reviewer` agent when the diff
  touches auth / input parsing / SSRF / secrets.

## Chains with

`/plan` → `/tdd` → `/code-review` → **`/verify`**.
