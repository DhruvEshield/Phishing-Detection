# PhishDetect — Competitive Audit & Roadmap (2026-07)

Based on research across the modern email-security market (Abnormal, Microsoft Defender for
O365, Proofpoint/Tessian, Mimecast, Sublime, Material, Cofense, IRONSCALES, Darktrace),
open-source tooling, ML literature (2023–2026), and SOC operational practice — then audited
against what PhishDetect actually does today.

---

## 1. Verdict: are we going the right direction?

**Yes — the core thesis is exactly what the market leaders do.** Every serious modern tool
converged on the same design we chose:

| Our design choice | Market validation |
|---|---|
| Many weak signals aggregated into one risk score; no single signal decides | Table-stakes #1 across Abnormal, Darktrace, Proofpoint, Mimecast, Rspamd (additive symbol scoring) |
| Human-in-the-loop + per-signal **explanation** shown to the analyst | This is Sublime's entire market position (transparent MQL verdicts vs black-box ML). A genuine differentiator we already have. |
| Two layers (pre-delivery email → post-delivery behaviour) + a feedback loop | Mirrors Abnormal/Material "herd immunity" and the industry's pre/post-delivery split |
| Phased: no behavioural baselines until history exists | Correct — vendors build 14-day+ baselines; premature behavioural models produce FP floods |
| The corpus-artifact bug we fixed (old ham vs modern phish) | The **canonical, documented trap** in the literature (concept drift; Enron-vs-Nazario). Fixing it was real, not busywork. |

So: **direction is right, phasing is right, and the explainability bet is a real edge.** The
gaps below are about *depth, scope, and reach* — not a wrong turn.

---

## 2. What we already match (credit where due)

Multi-signal scoring · explainable per-signal breakdown (differentiator) · SPF/DKIM/DMARC ·
lookalike + homoglyph domain detection · URL analysis (RDAP newly-registered, redirect
chains, raw-IP, `@`-trick, shorteners, suspicious TLD, credential-harvest page) · QR→URL
pipeline · **real threat-intel feeds (OpenPhish / URLhaus / PhishTank) + Google Safe
Browsing** (many MVPs never get here) · SSRF guard · analyst queue + verdict flow ·
partial feedback loop (quarantine verdict → sender domain to blocklist).

**One-line framing (from the SOC research):** we are strong on **decision** (classify +
explain + act on *one* message) but have no **scope** (campaign view) or **reach** (touch the
mailbox). That's the map of what's next.

---

## 3. Prioritized improvements

### Tier A — cheap, high-ROI, doable NOW in Phase 1 (email-alone, no integration)

1. **Attachment *content* analysis with `oletools`** (BSD, pure-Python). We only check file
   extensions today; `olevba`/`oleid` detect auto-exec macros, suspicious VBA, embedded IOCs.
   Direct coverage gap, drop-in.
2. **Certificate Transparency monitoring** (`crt.sh` / certstream) — flagged as the *biggest
   missing signal*. Catches lookalike/brand-keyword domains (`login-…`, `…-secure`) at cert
   issuance, often before the campaign lands. Pairs with our existing lookalike logic.
3. **Port Sublime's open detection rules** (`sublime-rules`, MIT) into our content-rule engine.
   Hundreds of hand-crafted BEC / exec-&-vendor-impersonation / gift-card / sextortion /
   free-hosting-abuse heuristics. Highest signal-per-effort single source.
4. **BEC intent / request-type classifier** (payment-change, wire, gift-card, payroll
   diversion) — orthogonal to the content classifier; catches the *no-URL* BEC that content+URL
   filters miss. Start as rules, grow into a small model.
5. **Similar-message clustering / campaign grouping** — the #1 SOC force-multiplier. Fuzzy-hash
   on fields we already parse so an analyst adjudicates a *campaign* once, not N duplicates.
   Makes the queue, metrics, and feedback loop all more useful. (Rspamd's fuzzy/perceptual
   HTML hash is the same idea for template reuse.)
6. **Finish the feedback loop.** Today: verdict → sender-domain blocklist. Extend to URL/hash
   IOCs, accumulate labelled training data, and **track FP *and* FN rates** (FN tracking is what
   reveals attacker tactic shifts).
7. **Metrics dashboard** — FP rate (>30% burns analysts out), time-to-triage, queue backlog,
   coverage. Cheap to compute from existing verdict/queue tables.
8. **Classifier upgrade path: SBERT/MiniLM embeddings + the same LogReg head.** CPU-friendly
   (seconds, not hours), closes most of the gap to fine-tuned transformers, stays linear and
   inspectable, and handles paraphrased / AI-generated phishing far better than TF-IDF. Keep
   TF-IDF+LR as the calibrated explainable baseline.
9. **Calibration + temporal/source-split validation baked into training** (Platt/isotonic;
   never random-split same-era corpora). Directly hardens against the artifact class of bug we
   already hit once.
10. **Header module depth: `checkdmarc`** (BIMI/VMC, MTA-STS, DMARC alignment) **+ ARC
    validation** (known gap; forwarded/thread mail leans on ARC).
11. **Harden the QR pipeline** — add OpenCV/`zxing-cpp` fallback (pyzbar misses rotated/low-
    contrast), rasterize PDF pages + image attachments before decode, handle nested/split QR.
12. **Threat-intel maintenance + expansion** — add abuse.ch **ThreatFox**; note abuse.ch now
    requires a free **Auth-Key** and **Google Safe Browsing v4 is deprecated** (migrate to
    **Web Risk**). ⚠️ Verify our current OpenPhish/GSB integrations still work under these changes.

### Tier B — Phase 2 (heavier, still the email domain)

- **URL enrichment via `urlscan.io`** (screenshot + resolved DOM + resource graph) on suspicious
  URLs — beyond our redirect-follower.
- **Attachment sandbox detonation** (CAPE / Hatching Triage) — the plan's own Phase 2 item.
- **Detection-as-code**: let analysts add/tune rules and **test them against historical messages
  without a redeploy** (Sublime's model) — big FP-reduction lever, gives detection engineers
  ownership.
- **Formalize the explainability layer + append-only audit trail** (plan's Phase 2) — near-free
  from evidence we already surface; unlocks the auditability/regulatory story.
- **MITRE ATT&CK T1566 tagging on verdicts + STIX/TAXII IOC export** — cheap tagging, boosts
  analyst trust and interop.
- **AiTM / EvilProxy / callback-phishing (TOAD) lure heuristics** (linkless + phone-number,
  reverse-proxy lure patterns).

### Tier C — Phase 3 / strategic (needs mailbox / identity API)

> **The one architectural decision to make early:** the **mail-integration surface**
> (Microsoft **Graph** / Gmail API, API-based post-delivery is the pragmatic path). It gates
> *half the roadmap* — make the call now because it constrains everything below.

Unlocked only by that integration:
- **Blast-radius search — "who else got this"** (prerequisite for any remediation).
- **Retroactive remediation / clawback** (ZAP-style purge, PhishRIP-style search-and-remove).
- **Abuse-mailbox / report-button intake** — the dominant real-world input source.
- **Behavioural baselines + relationship/vendor graph** (per-user/vendor history) — Phase 3.
- **Identity/ATO detection** (Entra/Graph sign-in logs): AiTM token replay, impossible travel,
  OAuth illicit-consent grants, malicious inbox rules, MFA-fatigue. **All Layer 2 — invisible in
  any single email.**
- **VEC from a *genuinely compromised* vendor** (passes SPF/DKIM/DMARC) — needs vendor-
  relationship baselining, ideally ERP/payment correlation.

---

## 4. The single highest-value increment

**cluster → blast-radius → remediate.** It converts single-message verdicts into incident
response and is what separates a classifier from a security tool. Clustering (A5) is cheap and
should be next; blast-radius + remediate are gated on the mail-integration decision (C). So:

- **Now (no integration):** deepen detection (A1–A4, A8–A11) + clustering (A5) + finish the
  feedback loop (A6) + metrics (A7).
- **Decide early:** the Graph/Gmail integration path — it unlocks Phase 2/3.

---

## 5. Honest cautions

- **Don't** chase fully fine-tuned transformers or "AI-written text" detectors — accuracy
  numbers are corpus-artifact-inflated and text-authorship detection is unreliable and worsening.
- Our headline ML metric is still corpus-bound; a trustworthy number needs temporal/source-split
  validation on a modern labelled set.
- **Licensing gotchas if this ever goes commercial:** GSB & VirusTotal free tiers are
  non-commercial; Spamhaus free needs your own resolver + non-commercial; abuse.ch needs an
  Auth-Key; OpenPhish/PhishTank real-time is paid. Rspamd is GPL (borrow *ideas*, not code);
  Sublime rules / oletools / checkdmarc are permissive and safe to vendor.

---

*Sources: vendor docs & threat reports (Abnormal, Microsoft Learn, Proofpoint, Mimecast,
Sublime, Material, Cofense, IRONSCALES, Darktrace); arXiv/MDPI/ScienceDirect phishing-ML
literature 2023–2026; abuse.ch / urlscan.io / crt.sh / VirusTotal / Spamhaus docs; MITRE
ATT&CK T1566. Full source URLs captured in the research session.*
