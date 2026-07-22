# PhishDetect — Phase 1 Build Guide & Complete Findings

**Date:** 2026-07-22 · **Companion to:** [phase1-completion-roadmap.md](phase1-completion-roadmap.md)
(strategic summary). This document is the *implementation handbook*: the complete research findings,
then a milestone-by-milestone build guide with the exact files to touch, what to implement, and how
to verify each step.

**Goal (owner's words):** a genuinely good detector that **sits in a mailbox**, lets an admin
configure it once, and then shows the admin a good/bad verdict on **every arriving mail**. Admin side
is required; the employee extension is optional/nice-to-have.

---

# PART I — COMPLETE FINDINGS

Five parallel research tracks: (1) internal detector audit, (2) weak→strong signal taxonomy,
(3) impersonation APIs, (4) deployment, (5) mailbox architecture.

## 1. Detector audit — what we have, rated

Each detector returns `raw_score` 0–100, multiplied by a fixed weight. "Points" are raw contributions
*before* weighting.

**Weights** (`services/app/config.py` → `ScoringConfig.from_settings`): header 0.20 · content 0.30 ·
url 0.25 · attachment 0.10 · qrcode 0.08 · threat_intel 0.07 (sum 1.00).
**Thresholds:** high 70 · medium 35 · internal LOW floor 15.
**Tiers → verdict → routing** (`scoring/engine.py`): ≥90 CRITICAL/PHISHING/quarantine · ≥70
HIGH/PHISHING/quarantine · ≥35 MEDIUM/SUSPICIOUS/review · <35 LOW/**LEGITIMATE/deliver**.

### Signal inventory (condensed)

| Detector (weight, max weighted) | Strong | Partial | Weak / Missing |
|---|---|---|---|
| **header** (0.20, max 20) | auth-alignment (`auth_pass_but_unaligned` +30, just built), Reply-To≠From (+20), homoglyph sender domain (+25), brand-impersonation mismatch (+35) | SPF/DKIM/DMARC graduated penalties, lookalike display/sender (11-brand list) | brand lists hardcoded (11–15); no cross-header (Return-Path/DKIM-d=/IP) consistency |
| **content** (0.30, max 30) | header-brand + ML=phishing boost (+20) | urgency/credential/authority regex (English only), body-brand-mention (+15), single sklearn model | monolithic ML as decider; no multilingual; no BEC/tone modeling |
| **url** (0.25, max 25) | newly-registered (RDAP, +20), homoglyph link (+25), raw-IP host (+15), `@`-trick (+15) | lookalike (15-vendor, Levenshtein≤3), excessive subdomains, redirect chain, form-action (gated) | **anchor-text≠href MISSING**; shortener flagged-not-expanded; credential heuristic exempts HTTPS |
| **qrcode** (0.08, max 8) | decoded QR URL re-run through URLAnalyzer | QR presence (+10) | weight 0.08 neuters even a malicious QR |
| **threat_intel** (0.07, max 7) | — | local blocklist + Google Safe Browsing (`40+10×hits`) | **weight 0.07 = a confirmed-malicious URL contributes ≤7 points** |
| **attachment** (0.10, max 10) | dangerous ext (+40), double ext (+35) | macro Office (+25), content-type mismatch (+20) | metadata-only; no hashing/VT, no archive recursion, no HTML-smuggling/ISO/LNK/OneNote |

### Scoring analysis — the critical finding

The invariant `weight×100 < high_threshold` (`ScoringConfig.validate_invariant`) means **no single
detector can reach even MEDIUM (35) alone** — header maxes at 20, threat_intel at 7. Two consequences:

- **A textbook brand spoof is delivered as LEGITIMATE.** `From: "Amazon"
  <no-reply@amaz0n-security.com>`: header raw = missing-auth (12) + exact brand display (30) +
  lookalike root (25) + brand mismatch (35) = **capped 100** → `100 × 0.20 = 20` → **<35 → LEGITIMATE
  → delivered.**
- **A confirmed known-malicious URL cannot reach "suspicious."** threat_intel raw 50 → **3.5
  weighted**; even raw 100 → **7**.

The philosophy ("signals aggregate") is right; the **calibration is wrong** — strong,
high-confidence signals are weighted like weak heuristics. This is the single highest-leverage fix and
is independent of all mailbox work.

### Brand + link-destination mismatch — does it work today?

Code path exists: `header.py` sets `meta["brand_impersonation"]` (+35 raw) → `detection_service.py`
correlates and adds `brand_url_mismatch` (+25 raw to URL) if links don't go to the real brand domain.
**But:**
- **In theory (full MIME):** contributes ~18 weighted — still usually needs the content ML to also
  fire to cross 35.
- **End-to-end via the current extension: NO.** `extension/content.js` sends `body_html:''` and only
  `{From, Subject}`, so (a) no hrefs → `brand_url_mismatch` never fires, (b) no auth headers → the
  alignment engine is dead, (c) anchor-text vs href is never compared anywhere.

## 2. Signal taxonomy — weak → strong (build checklist)

**Design principle:** cheap deterministic signals carry the verdict; ML/NLP is a *supporting*
feature, never the decider (brittle against AI-written mail).

- **WEAK (noisy alone):** urgency/keyword regex; monolithic ML classifier; grammar/greeting; **raw
  SPF/DKIM "pass" without alignment** (dangerously misleading); shortener-present / low-trust-TLD.
- **MEDIUM (need corroboration):** display-name≠from-domain; Reply-To/Return-Path mismatch;
  anchor-text≠href / brand-in-text≠destination; redirect chains / IP-literal / `@`-userinfo;
  newly-registered domain; credential-harvest page heuristics; attachment tricks (macro/HTML-smuggling
  /ISO/double-ext/encrypted archive); **QR codes (quishing — ~12% of phishing in 2025)**.
- **STRONG (high-confidence, hard to spoof):** **DMARC with alignment** (keystone); lookalike/
  homoglyph/punycode/combosquat vs a trusted set; **communication-history baseline / first-time-sender**
  (decisive for BEC); thread-hijack detection; sender-reputation + cross-header consistency.

**Build-first order (power per effort):** 1) DMARC+alignment (done) · 2) cross-header consistency ·
3) lookalike/homoglyph/combosquat vs trusted list · 4) URL anchor≠href + decode/follow shorteners ·
5) **QR-decode → reuse URL pipeline** · 6) newly-registered-domain lookup · 7) **first-time-sender /
comm-history baseline** (start collecting history *now*).

**Commonly-missed strong signals:** alignment (not just "pass"); QR-decode-then-URL-pipeline; HTML
attachment smuggling parsing; cross-header consistency graph; relationship/first-contact baseline;
follow redirect chains + cloaking detection; extract URLs/QRs from *inside* attachments.

## 3. Impersonation APIs — don't build the brand DB

**Recommendation (≈$0 until you outgrow free tiers):**
1. **dnstwist** (self-hosted, MIT, no key) — the brand-lookalike *engine*. Feed a small
   brand→canonical-domain seed list; it generates + live-checks typosquat/homoglyph/combosquat
   permutations. This *replaces* hand-building a brand database.
2. **Google Web Risk API** (free Lookup ≤100k/mo, **commercially licensed**) — known-malicious
   URL/domain oracle. Use Web Risk, **not** Safe Browsing (Safe Browsing is non-commercial-only).
3. **urlscan.io** (free: 5k scans/day, 1k searches/day) — enrichment + brand/CT discovery.
- **Free no-key add-ons:** newly-registered-domain feed (WhoisDS); **CertStream / crt.sh** for
  brand-lookalike certs at issuance. Keep the existing **RDAP** age check.

Others considered: VirusTotal (4/min free — batch only), PhishTank (signups closed), OpenPhish
(free feed), Cloudflare URL Scanner, Spamhaus DBL, IPQS/APIVoid (cheap paid). Commercial brand
protection (PhishLabs/Bolster/DomainTools) is out of MVP budget.

Sources: Web Risk https://cloud.google.com/security/products/web-risk · urlscan
https://urlscan.io/docs/api/ · dnstwist https://github.com/elceef/dnstwist · WhoisDS
https://www.whoisds.com/newly-registered-domains · CertStream wss://certstream.calidog.io

## 4. Deployment — Cloudflare no, cheap VPS yes

- **Cloudflare Workers/Pages CANNOT host this backend:** request-scoped (no always-on mailbox
  watcher), 128 MB memory cap (can't hold opencv+sklearn), no pyzbar (libzbar) / psycopg2 in Pyodide.
- **"Burden Google" is a misconception:** where the backend *runs* is independent of calling
  Gmail/Graph — those are lightweight outbound API calls; ML runs on your host regardless. You owe
  only rate-limit politeness (prefer push over polling).
- **Recommendation:** one always-on **Hetzner CX33 (4 vCPU / 8 GB, ~€6.5/mo)** running the existing
  `docker compose`, fronted by **Cloudflare free** (DNS/WAF/DDoS, optional Tunnel = no public IP).
  R2 for artifacts if needed. Split to managed Postgres/Redis only when you outgrow one box.

## 5. Mailbox architecture — how it sits in a mailbox

The connector's only job is **provider payload → `EmailIngestRequest`** (which already accepts
`raw_mime`, `headers`, `attachments`, `tenant_id`). Both API connectors are two-step: push says "mail
arrived" → you fetch full MIME.

| | MS Graph (webhooks) | Gmail API (watch+Pub/Sub) | Journaling / SMTP relay | IMAP IDLE |
|---|---|---|---|---|
| Provider | M365 | Google Workspace | Any | Any (universal) |
| Full MIME | 2nd call `…/$value` | 2nd call `messages.get?format=RAW` | **Native** (`.eml`) | **Native** (`FETCH BODY[]`) |
| Push/poll | Push | Push→pull | Push (SMTP) | IDLE long-poll |
| Scope | **Org-wide, 1 admin consent** | Org-wide (domain-wide delegation) | **Org-wide, 1 rule** | Per-mailbox |
| Auth | Entra app + admin consent (`Mail.Read`, RBAC-scoped) | OAuth + super-admin delegation | No OAuth (admin rule) | Per-mailbox app password |
| Effort | Medium | Medium | **Low** | Low (1) / high (org) |
| Remediation | Yes (`move`, `Mail.ReadWrite`) | Yes (`messages.modify`) | No (copy) | Limited |

**Admin "sees all mail classified" surface:** the React analyst queue mostly exists (`frontend/`, fed
by `EmailSummary`). Add: (1) every arriving message → a row (connector ingests *all* mail),
(2) `tenant_id` filter, (3) verdict-band filter + counts, (4) later, human-in-the-loop
quarantine/release.

**Employee extension:** once the server sees full MIME, demote it from *detector* to **thin
verdict-viewer + "report suspicious" button** (the browser can't see raw headers/hrefs).

Sources: Graph change notifications https://learn.microsoft.com/en-us/graph/outlook-change-notifications-overview
· Get MIME https://learn.microsoft.com/en-us/graph/outlook-get-mime-message · Gmail push
https://developers.google.com/workspace/gmail/api/guides/push · Exchange journaling
https://learn.microsoft.com/en-us/exchange/security-and-compliance/journaling/journaling

---

# PART II — STEP-BY-STEP BUILD GUIDE

Sequenced so each milestone unblocks the next. Each has: **objective · files · steps · verify ·
done-when.** Recommended order is by leverage-per-effort. Everything uses the existing local venv
(`services/.venv`) for tests and `docker compose` for the running stack.

## Milestone 0 — Prerequisites & baseline

**Objective:** clean baseline before changes.
**Steps:**
1. `cd services && ./.venv/bin/python -m pytest -q` → confirm the current suite is green (baseline 63).
2. `docker compose ps` → confirm api/postgres/redis/frontend up.
3. Skim `services/app/scoring/engine.py`, `scoring/config.py`, `config.py` (weights/thresholds),
   `services/app/services/detection_service.py`.
**Done when:** tests green, stack up, you can trace one email through ingest→detectors→scoring.

## Milestone 1 — Scoring recalibration (DO FIRST; cheapest, highest impact)

**Objective:** let high-confidence "smoking-gun" signals independently reach at least SUSPICIOUS,
without abandoning "weak signals aggregate."
**Files:** `services/app/scoring/engine.py`, `scoring/config.py`, `services/app/config.py`,
`services/tests/test_scoring_engine.py` (+ conftest fixtures).
**Approach — a "critical-signal floor" (preferred over just raising weights, keeps the invariant):**
1. Define a set of **critical flags** that represent high-confidence evidence, e.g.
   `auth_pass_but_unaligned`, `brand_impersonation`, `brand_url_mismatch`, a known-malicious IOC hit
   from threat_intel, and DMARC-fail on a `p=reject/quarantine` domain.
2. In `ScoringEngine.compute`, after the weighted sum, scan all signals' `flags`. If any critical flag
   is present, **floor the tier at MEDIUM/SUSPICIOUS/review** (and if two+ critical flags, floor at
   HIGH). Record *why* in the explanation (e.g. `floor_applied: brand_url_mismatch`).
3. Separately, fix the most conspicuous weight miscalibration: raise `weight_threat_intel` (0.07 is
   too low for a *confirmed* IOC) — but keep `validate_invariant` passing (`weight×100 <
   high_threshold`), so cap around 0.30–0.34 if high_threshold=70. Re-run the invariant test.
4. Change the `<35` mapping label from **LEGITIMATE** to **UNKNOWN/undetermined** for the low-mid
   band, reserving "LEGITIMATE" for genuinely clean+authenticated mail (e.g. `fully_authenticated`
   and no critical flags). This stops the system from *affirmatively* clearing spoofs.
**Verify:**
- Add tests: the `"Amazon" <no-reply@amaz0n-security.com>` spoof now yields ≥ SUSPICIOUS; a
  threat_intel-only known-malicious hit yields ≥ SUSPICIOUS; a clean DMARC-aligned email stays
  LEGITIMATE/deliver; confirm `validate_invariant` still passes.
- `./.venv/bin/python -m pytest -q` green; e2e POST the spoof to `/api/v1/emails/ingest` and confirm
  tier ≥ MEDIUM.
**Done when:** a lone strong signal can no longer be labeled LEGITIMATE, and clean mail is unaffected.

## Milestone 2 — External impersonation & URL intel

**Objective:** brand-impersonation + known-malicious coverage without a hand-built DB.
**Files (new):** `services/app/detectors/brand_intel.py` (dnstwist wrapper),
`services/app/integrations/web_risk.py`, extend `services/app/detectors/threat_intel.py`; config keys
in `services/app/config.py`; `services/requirements.txt` (+`dnstwist`).
**Steps:**
1. **Seed list:** a small `brand → [canonical domains]` YAML/JSON (e.g. `services/app/data/brands.yml`)
   — replaces the 11-entry hardcoded lists in `header.py`/`url.py`. Include international domains
   (amazon.co.uk/.in) to kill false positives.
2. **dnstwist integration:** given a suspicious domain, check whether it is a lookalike of any seed
   brand (dnstwist as a library / subprocess). Cache results in Redis (like RDAP). Emit
   `combosquat`/`lookalike_brand` flags with the matched brand. Run this in `url.py` and reuse for the
   sender domain in `header.py`.
3. **Google Web Risk:** `web_risk.py` — Lookup API client (API key in env/compose, **not** committed),
   Redis-cached, safe-fail on error/timeout. Wire into `threat_intel.py` as an additional provider
   (chain with the existing local blocklist + Safe Browsing → migrate to Web Risk for commercial use).
4. **NRD feed (optional, free):** a daily job pulls WhoisDS NRD list into a Redis set; flag any
   sender/link domain that is both a lookalike **and** newly-registered (high-confidence combo).
**Verify:** unit tests with a mocked dnstwist/Web Risk; a `paypal-secure-verify.xyz` link flags
combosquat; a known-bad test URL flags via Web Risk; caches hit on repeat. Ensure safe-fail (no
network in CI).
**Done when:** brand-impersonation no longer depends on the hardcoded lists, and a known-malicious URL
is caught via an external oracle — both feeding the recalibrated scorer (M1).

## Milestone 3 — Close detector gaps (weak→strong)

**Objective:** the highest-value missing/weak signals from the taxonomy.
**Files:** `services/app/detectors/url.py`, `header.py`, `qrcode_detector.py`, tests.
**Steps:**
1. **Anchor-text vs href (missing):** requires structured links. Parse `<a>` tags from `body_html`
   into `{text, href}` pairs (in the URL detector or a small helper). Flag when the visible text names
   a domain/brand that differs from the href's registrable domain (`registered_domain` in
   `domain_intel.py`). *(Depends on the payload carrying HTML — fully lit by M4.)*
2. **Combosquat in URL detector:** brand-as-label detection (`amazon-security.com`,
   `login.amazon.evil.com`) using the M2 seed list + `registered_domain`, beyond Levenshtein.
3. **Expand URL shorteners:** for known shortener hosts, resolve the final destination (already have
   SSRF-guarded redirect following) and analyze *that*, instead of only flagging.
4. **QR → URL pipeline:** confirm decoded QR URLs run through the full URL detector (they do by
   design) — the real fix is the qrcode **weight** (M1) so a malicious QR isn't neutered at 0.08.
5. **Cross-header consistency:** in `header.py`, compare From-domain vs Return-Path vs DKIM `d=` vs
   Reply-To; emit a `header_inconsistency` flag when they disagree (composite spoof signal).
**Verify:** targeted unit tests per signal; full suite green; ruff clean.
**Done when:** anchor≠href, combosquat, shortener-expansion, and cross-header consistency all fire in
tests and feed the scorer.

## Milestone 4 — Connector Phase 0 (real mail, full MIME, no OAuth)

**Objective:** prove "sits in a mailbox, auto-verdicts every arriving mail" with the least code, and
**light up the alignment engine + hrefs end-to-end.**
**Files (new):** `services/app/connectors/` — `imap_poller.py` (universal, quickest to demo) and/or
`smtp_sink.py` (journaling target); a `normalize_mime(raw_bytes) -> EmailIngestRequest` helper (reuse
`_parse_eml` in `services/app/api/ingest.py`); a small always-on worker entry (compose service).
**Steps:**
1. **Normalizer:** `raw .eml → EmailIngestRequest` — populate `raw_mime`, full `headers` (incl.
   `Authentication-Results`, `Return-Path`, `DKIM-Signature`), `body_text`, **`body_html`**, and
   attachment metadata. Stamp `tenant_id`.
2. **IMAP poller (fastest demo):** connect (app password / XOAUTH2) to a real test inbox, IDLE or poll
   for unseen mail, fetch `BODY[]`, normalize, `POST /api/v1/emails/ingest`, mark processed. Run as a
   background compose service.
3. *(Provider-agnostic alt.)* **SMTP sink:** tiny receiver that accepts journaled/relayed mail and
   feeds the same normalizer. Point an Exchange/Workspace journal rule at it. Watch for duplication;
   secure egress.
4. Dedup is already handled by ingest (`dedup_hash`).
**Verify:** send test emails (a clean DMARC-aligned one; the Amazon-spoof; one with a hidden
`href`) to the connected inbox; confirm rows appear via the API/DB with `auth_pass_but_unaligned` /
`brand_url_mismatch` / anchor≠href firing — the exact cases that were inert via the extension.
**Done when:** every mail arriving in the test inbox is auto-scored with full-fidelity signals, no
manual open.

## Milestone 5 — Admin dashboard: sees all mail, sorted

**Objective:** the required admin surface.
**Files:** `frontend/` (existing React/Vite/MUI analyst queue), `services/app/api/queue.py`,
`schemas` (`EmailSummary`).
**Steps:**
1. **All mail as rows:** the queue currently shows the review band; add a view/filter that lists
   *every* ingested message (not just medium-risk), since M4 ingests all mail.
2. **Tenant scoping:** filter by `tenant_id` (already on schema) so one customer = one view.
3. **Verdict bands + counts:** header tiles "Critical / High / Suspicious / Clean" with counts; click
   to filter. Map from existing `risk_tier`.
4. **Explanation panel:** ensure the per-signal explanation (already produced) renders so the admin
   sees *why*.
**Verify:** with M4 feeding a real inbox, the admin view shows arriving mail sorted into bands with
reasons; tenant filter works.
**Done when:** an admin can watch mail arrive and be sorted good/bad with explanations — Phase-1's
headline capability.

## Milestone 6 — Connector Phase 1 (Microsoft Graph, production)

**Objective:** org-wide, push-based, one-admin-consent connector for the dominant M365 market.
**Files (new):** `services/app/connectors/graph/` — webhook receiver, subscription manager, MIME
fetcher; config/secrets via env.
**Steps:**
1. Entra app registration; **admin-consent** `Mail.Read` (application permission), scoped with **RBAC
   for Applications** to chosen mailboxes.
2. Create subscription on `messages`, `changeType=created`, with a public HTTPS webhook +
   validation-token handshake.
3. On notification → `GET /users/{id}/messages/{id}/$value` (raw MIME) → normalizer → `/ingest`.
4. **Subscription renewal** (≤4230 min) + lifecycle-notification recovery (re-subscribe / backfill via
   delta).
5. *(Later)* remediation: Graph `move`/`delete` behind human-in-the-loop admin actions
   (`Mail.ReadWrite`).
**Verify:** a message sent to a tenant mailbox appears scored in the admin dashboard within seconds,
no user action.
**Done when:** one admin consent wires a whole tenant; arriving mail is auto-captured with full MIME.
**Then Phase 1b:** Gmail API (`users.watch`+Pub/Sub→`format=RAW`, domain-wide delegation, weekly
`watch` renewal) reusing the same normalizer.

## Milestone 7 — Deployment (Hetzner + Cloudflare)

**Objective:** live, always-on, cheap.
**Steps:**
1. Provision **Hetzner CX33** (Ubuntu, Docker). Harden (SSH keys, firewall, unattended-upgrades).
2. `git clone` + `.env` (secrets: DB, Web Risk key, OAuth creds) + `docker compose up -d`.
3. Point **Cloudflare** DNS at the box; enable proxy (WAF/DDoS), free TLS. Optionally run
   `cloudflared` **Tunnel** (no public inbound IP / open ports).
4. Postgres backups (cron `pg_dump` → R2/off-box). Basic uptime monitoring.
**Verify:** ingest + dashboard reachable via the Cloudflare hostname; a test mail flows end-to-end on
the server; reboot survives (compose `restart: unless-stopped`).
**Done when:** the stack runs 24/7 behind Cloudflare, watching mailboxes.

## Milestone 8 — Optional: employee extension + BEC groundwork

**Objective:** nice-to-have client + seed the Phase-3 behavioral signal.
**Steps:**
1. **Thin extension:** rewrite `extension/` to read the server verdict for the open message (by
   message-id) and render an inline badge; add a **"report suspicious"** button that POSTs to
   `/ingest` as an inbound report. Detection stays server-side.
2. **BEC history capture (start now):** persist per-tenant sender/communication metadata (who emails
   whom, first-seen, domains) on every ingest — *collect it before scoring on it* so a
   first-time-sender / relationship baseline exists when Phase 3 begins.
**Done when:** employees can see a mail's score inline and report; the system is accumulating the
history that makes BEC detection possible later.

---

## Quick reference — build order & why

1. **Scoring recalibration** — cheap, no infra, makes the detector act on evidence it already has.
2. **Impersonation/URL intel** — big coverage jump, mostly free/self-hosted.
3. **Detector gaps** — anchor≠href, combosquat, shortener expansion, cross-header consistency.
4. **Connector Phase 0** — real mail + full MIME; lights up alignment/hrefs end-to-end; proves "in a
   mailbox."
5. **Admin dashboard** — all-mail rows + tenant + bands (the required admin surface).
6. **Graph connector** — org-wide production capture (then Gmail).
7. **Deploy** — Hetzner + Cloudflare.
8. *(optional)* employee extension → thin viewer; begin BEC history capture.

**Guardrails to keep (repo principles):** rules before ML; human-in-the-loop (no fully automated ML
enforcement); explanation on every verdict; don't build Phase-3 behavioral scoring before the data
exists — but *do* start capturing the history now.
