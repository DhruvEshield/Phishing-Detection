# Phase 1 Completion Roadmap — a good detector that sits in a mailbox

**Date:** 2026-07-22 · Synthesis of a 5-track research pass (detector audit, impersonation
APIs, signal taxonomy, deployment, mailbox architecture).

## The goal (restated by the owner)

1. **Be a genuinely good detector first** — catch signals from very weak to very strong, close the
   gaps, and reliably separate genuine mail from fraudulent. Includes the brand case: *if a mail
   claims to be from Amazon but the sending domain and the links both resolve to some other domain,
   that's wrong — flag it.*
2. **Domain/brand impersonation via an external API/feed** — don't hand-build a brand database.
3. **Sit in a mailbox** — admin configures once, then sees **every arriving mail sorted good/bad**.
   *(Admin side = required. Employee extension = optional, nice-to-have.)*
4. **Deploy it somewhere sane** — Cloudflare? where does the backend run?

---

## Honest gap assessment — what's built vs. the goal

**The brain is real; it's mis-calibrated and half-fed.** The 6-detector pipeline, scoring engine,
analyst queue, and feedback loop exist and work. But two problems sit between it and the goal:

### Problem 1 — scoring dilutes the strongest signals (calibration bug, highest leverage)

The scoring invariant ("no single signal decides") was over-tuned into "no *strong* signal can move
the verdict at all." Weighted ceilings: content 30, url 25, header **20**, attachment 10, qrcode 8,
threat_intel **7**. Thresholds: high 70, medium 35, and anything **<35 is affirmatively labeled
LEGITIMATE**.

Worked example — a textbook brand spoof `From: "Amazon" <no-reply@amaz0n-security.com>`:
- Header detector maxes out (raw 100: missing-auth + exact brand display + lookalike root + brand
  mismatch) → `100 × 0.20 = 20` → below 35 → **verdict: LEGITIMATE, delivered.**
- A **confirmed known-malicious URL** (threat_intel raw 50→100) contributes **3.5–7 points** — it
  *cannot* reach even "suspicious" on its own.

So the two signals most associated with real, damaging phishing — sender/brand spoofing and known-bad
IOCs — are individually incapable of moving the verdict off "legitimate." **This is the single
highest-leverage fix in the system and is independent of all the mailbox work.**

### Problem 2 — the capture layer starves the detectors (the real missing half)

The only mailbox surface is the **Gmail-only, open-to-scan, DOM-scraping** extension. It sends
`body_html:''` and only `{From, Subject}`. Consequences, traced in the audit:
- **No hrefs reach the backend** → the brand↔link-mismatch logic (`detection_service.py`) never
  fires; the URL detector has nothing to analyze. The exact Amazon→other-domain case is **inert
  end-to-end** even though the code for it exists.
- **No auth headers** → the SPF/DKIM/DMARC + alignment engine (just built) scores only the small
  "missing" penalties. The strongest single idea in the codebase is **dead in this deployment.**
- **Anchor-text vs href** is never compared anywhere.

**Verdict on "how far are we":** the *detection engine* is ~70% of a good Phase-1 brain (needs
recalibration + a few high-value signals). The *capability the owner is describing* — sits in any
mailbox, auto-verdicts every arriving mail with full fidelity — is **not built**; the extension is a
demo, not that product. The ingest contract (`EmailIngestRequest` already accepts `raw_mime`,
`headers`, `attachments`, `tenant_id`) is ready for it — the missing piece is a **connector layer**,
not a backend redesign.

---

## Workstream A — make it a genuinely good detector

### A1. Recalibrate scoring so strong signals count (do first — cheap, highest impact)

Keep "weak signals only earn confidence in combination," but let **high-confidence "smoking gun"
signals** independently reach at least SUSPICIOUS. Options (pick one, plan separately):
- Raise weights for header + threat_intel, **or**
- Add a **signal floor / override tier**: if any of {auth-pass-but-unaligned, brand-impersonation
  mismatch, known-malicious IOC, DMARC-fail on a `p=reject` domain} fires, the email cannot be
  labeled LEGITIMATE — it floors at SUSPICIOUS/review.
- Fix the most conspicuous miscalibration: **threat_intel 0.07** (a confirmed-malicious URL scoring
  3.5/100).
- Stop labeling `<35` as affirmatively "LEGITIMATE" — use "UNKNOWN/undetermined" for the low-mid band.

### A2. Close detection gaps — weak→strong build order (power per effort)

From the signal-taxonomy research. Design principle: **cheap deterministic signals carry the verdict;
ML/NLP is a supporting feature, never the decider** (it's brittle against AI-written mail).

1. **DMARC with alignment** — done (this session). Ensure it's fed real headers (needs Workstream B).
2. **Cross-header consistency** — From vs Reply-To vs Return-Path vs DKIM `d=` vs origin IP/geo. Pure
   header parsing. Partly present; extend.
3. **Lookalike / homoglyph / combosquat** vs a trusted-domain list — have Levenshtein + confusables +
   punycode; **add combosquatting** (`amazon-security.com` — brand as a label) and move off the
   11–15 hardcoded brands (see A3).
4. **URL: anchor-text ≠ href** (missing), IP-literal/`@`-userinfo (have), **expand shorteners**
   (currently only flagged), follow redirects (have), brand↔destination mismatch (have but inert).
5. **QR-decode → run decoded URL through the URL pipeline** — cheap, high-value; most gateways skip it.
6. **Newly-registered-domain** on sender + linked domains (RDAP; have age check — wire an NRD feed).
7. **First-time-sender / communication-history baseline** — the decisive BEC signal. *Start
   collecting history now* even before scoring on it. (This is the Phase-3 behavioral seed — begin
   the data capture early.)

Deprioritize: grammar/urgency regex alone, and the monolithic ML classifier as the *decision-maker*.

### A3. Brand/domain impersonation via external services (don't build the DB)

Recommended stack, ~$0 until you outgrow free tiers:
- **dnstwist (self-hosted, MIT, no key)** — the brand-lookalike *engine*. Feed it a small
  brand→canonical-domain seed list; it generates + live-checks the typosquat/homoglyph/combosquat
  space. This replaces "hand-building a brand database."
- **Google Web Risk API (free Lookup ≤100k/mo, commercially licensed)** — the known-malicious
  URL/domain oracle. Use Web Risk **not** Safe Browsing (Safe Browsing is non-commercial-only).
- **urlscan.io (free tier: 5k scans/day, 1k searches/day)** — enrichment + brand/CT discovery.
- **Free add-ons, no key:** a newly-registered-domain feed (WhoisDS) so "lookalike + NRD" becomes
  high-confidence; **CertStream/crt.sh** to catch brand-lookalike certs at issuance.

---

## Workstream B — make it sit in a mailbox (admin side = the required deliverable)

The connector's only job is **provider payload → `EmailIngestRequest`**; the backend is unchanged.
Both API options are two-step (push says "mail arrived" → you fetch full MIME). Full raw MIME is what
makes the whole detector actually work (real auth headers, real hrefs, attachments).

**Connector path (phased):**
- **Phase 0 — journaling / SMTP relay (days, no OAuth).** An Exchange/Workspace journal or routing
  rule copies every inbound mail as full `.eml` to a small SMTP-ingest service → `/ingest`. Cheapest
  way to *prove* "sits in a mailbox, admin configures once, every mail auto-sorted," provider-agnostic.
  Caveats: it's a copy (no clawback), can duplicate mail, and moves mail off the provider (secure the
  egress).
- **Phase 1 — Microsoft Graph (the MVP product connector).** One Entra app + a single admin consent
  (`Mail.Read` application permission, scoped via RBAC for Applications) covers the **whole tenant**
  with push (`changeType=created`) → `GET …/$value` for MIME → normalizer → `/ingest`. M365 dominates
  enterprise mail and Graph has an official remediation API for later.
- **Phase 1b — Gmail API.** `users.watch` + Pub/Sub → `messages.get?format=RAW`; org-wide via
  domain-wide delegation. Same normalizer, same `/ingest`.
- **IMAP IDLE** — universal fallback for any mailbox; fine to prototype against one real inbox, not an
  org-wide production answer.

**Admin "sees all mail classified" surface** — the React analyst queue mostly exists. Add: (1) every
arriving message becomes a row (because the connector ingests *all* inbound mail), (2) `tenant_id`
filtering (already on the schema), (3) verdict-band filter + counts (Critical/High/Suspicious/Clean),
(4) later, human-in-the-loop quarantine/release wired to the connector's provider action.

**Employee extension (optional).** Once the server ingests full MIME, demote the extension from
*detector* to **thin verdict-viewer + "report suspicious" button**. The browser can't see raw
headers/hrefs, so client-side detection permanently caps accuracy. Its durable value is surfacing the
server verdict where the employee reads mail, and covering not-yet-connected mailboxes via report-to-server.

---

## Workstream C — deployment

- **Cloudflare cannot host this backend.** Workers are request-scoped (no always-on mailbox
  watcher), capped at 128 MB (can't hold the opencv+sklearn stack), and can't run pyzbar/psycopg2 in
  Pyodide. Pages doesn't change that.
- **"Burden Google" is a misconception.** Where the backend *runs* is independent of calling
  Gmail/Graph — those are lightweight outbound API calls; your ML work runs on your host regardless.
  You owe Google/Microsoft only *rate-limit* politeness (prefer push over aggressive polling), not
  compute. Pick the host on cost/ops grounds alone.
- **Recommendation:** one always-on VPS — **Hetzner CX33 (4 vCPU / 8 GB, ~€6.5/mo)** — running the
  existing `docker-compose` stack (FastAPI + connector/poller + Postgres + Redis), fronted by
  **Cloudflare free** (DNS/WAF/DDoS, optional Tunnel so there's no public IP). The compose file is
  already the deploy artifact. R2 for model artifacts/screenshots if needed. Split to managed
  Postgres/Redis only when you outgrow one box — a scaling decision, not an MVP one.

---

## Sequenced build plan

| # | Slice | Why here |
|---|---|---|
| 1 | **Scoring recalibration** (A1) | Cheap, no new infra, makes the detector actually *act* on what it already sees. Highest leverage. |
| 2 | **Impersonation APIs** (A3): dnstwist + Web Risk + NRD feed | Big brand-coverage jump, mostly self-hosted/free; feeds the recalibrated scorer. |
| 3 | **Detector gaps** (A2): anchor≠href, combosquat, QR→URL reuse, shortener expansion, cross-header consistency | Close the weak→strong checklist. |
| 4 | **Connector Phase 0** (journaling/IMAP) → real mail with full MIME | Unblocks the alignment engine + hrefs end-to-end; proves "sits in a mailbox." |
| 5 | **Admin dashboard**: all-mail rows + tenant filter + bands | The required "admin sees good/bad" surface. |
| 6 | **Connector Phase 1** (Microsoft Graph) | The production-grade org-wide connector. |
| 7 | **Deploy** to Hetzner + Cloudflare | Make it live and always-on. |
| 8 | *(optional)* Employee extension → thin viewer; **start BEC history capture** | Nice-to-have + seeds Phase 3. |

**One-line strategy:** *recalibrate the brain → give it external brand/URL intel → feed it full MIME
via a connector (journaling → Graph) → surface it to the admin → deploy on a cheap VPS behind
Cloudflare.* The employee extension is the last, optional mile.
