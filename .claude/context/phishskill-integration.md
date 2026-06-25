# PhishSkill Integration (keep it simple)

> This is a small, **standalone** Python tool. Build and run it **on its own** — you do **not**
> need access to PhishSkill (or its code, database, or credentials) to develop or test it. It will
> later be connected to **PhishSkill** (a phishing training/simulation platform) by the maintainer.
> "Integration-ready" just means: follow a few conventions now so connecting later is config + one
> API call, not a rewrite. **Don't over-build.**

## How it connects later (so you know the target)

You build the detector as a self-contained service that exposes an HTTP API. Later the maintainer
runs it alongside PhishSkill and points PhishSkill at its `POST /detect` endpoint. Your job is the
standalone tool; the connection is the maintainer's job.

## 1. Reuse, don't rebuild

- **Corpus** — already vendored at [ml/data/phishing_pot/](../../ml/data/) (8,614 real phishing
  `.eml`). Still need a legitimate (ham) set for the classifier. See [ml.md](ml.md).
- **Domain intel** — build it in Python with a proven approach: **RDAP** for domain age (not
  `python-whois`), one self-protecting parser per signal (SPF/DKIM/DMARC/MX/age), and an **SSRF
  guard** before any probe. Emit one structured DNS-analysis object per domain.

## 2. Conventions that make the later connection easy

- **Config from env vars** — read `DATABASE_URL` (and any other infra setting) from the
  environment; never hardcode. The maintainer repoints the DB without touching code.
- **API:** `{ success, data, meta? }`; errors `{ success: false, message, code }`. ISO-8601 timestamps.
- **Verdict enum:** `PHISHING | SUSPICIOUS | LEGITIMATE | UNKNOWN`. Risk levels `LOW → CRITICAL`.
- **Multi-tenant ready:** put a nullable `tenantId` on any record that may later sync outward.
- **Inbound reports:** accept a reported-email shape `{ sender, senderIp, subject, headers, rawEml }`
  and **dedup by an MD5 of the payload**. (Reported emails can also grow the corpus.)
- **Threat intel:** cluster reported phish by sender domain → an internal blocklist that feeds
  Layer 1 scoring (the [architecture.md](architecture.md) feedback loop).
- **Own database namespace** — keep the tool's tables under their own schema so they never collide.

## 3. Frontend

- **Vite + React + React Router + Tailwind + MUI** (not Next.js) — an auth-gated SPA.
- UI conventions, to stay visually consistent with PhishSkill: layout order **PageHeader →
  filters → stats → table**; reuse components, don't invent new visual treatments; palette
  blue/emerald/rose/slate (no indigo, no gradients on data); **no emojis** on user-facing surfaces.

---
Don't expand this into a framework. Build the tool standalone; the maintainer handles the connection.
