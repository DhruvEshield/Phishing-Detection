# Architecture — Two Layers + A Feedback Loop

> Load this when touching the detection pipeline, scoring, routing, or anything that
> crosses Layer 1 ↔ Layer 2. This is the "shape of the system."

Detection is organised into two layers targeting different points in the attack chain.
**What Layer 1 cannot catch, Layer 2 is positioned to detect.** Neither makes a binary
decision from a single check — they aggregate weighted signals into a **risk score**.

## Layer 1 — Email Analysis (Pre-Delivery)

Analyses every email *before* it reaches the user. Collects signals from multiple sources
and aggregates them into a risk score. No single signal blocks; the weight of combined
evidence does.

| Signal | Looks for | Technique |
|---|---|---|
| **Header analysis** | Auth failures, reply-to mismatches, routing anomalies, lookalike display names | SPF / DKIM / DMARC validation + heuristic header rules |
| **Content analysis** | Urgency, payment/credential requests, authority impersonation, tone inconsistency | NLP classification on a phishing corpus + high-risk pattern matching |
| **URL analysis** | Newly registered domains, redirect chains, lookalike URLs, credential-harvest pages | Domain age / WHOIS, threat-intel feeds, link following + page inspection |
| **Attachment analysis** | Malicious macros, embedded executables, disguised file types | File-type validation, static analysis, sandbox detonation (Phase 2) |
| **QR-code detection** | Malicious URLs hidden in QR images in emails/PDFs | CV extraction + decode → decoded URL handed to the URL pipeline |
| **Threat intelligence** | Known phishing infra, IOCs, reported campaigns | Cross-reference external feeds + internal blocklists |

**Risk-score routing (tiered — balances security vs. usability, limits analyst load):**
- **High risk** → quarantined automatically.
- **Medium risk** → flagged for analyst review.
- **Below threshold** → delivered.

## Layer 2 — Behavioural & Identity Monitoring (Post-Delivery)

Exists because some attacks cannot be stopped at the email level — a VEC attack uses a
*legitimate* account, a thread-hijack lives inside a *real* conversation, an AiTM attack
succeeds *after* a clean-looking click. These only become visible through behaviour.

1. **Behavioural baselines (per-user/account):** unusual send volume/timing vs. the user's
   established pattern, new external recipients, newly created auto-forward/inbox rules,
   mass BCC, sudden frequency changes.
2. **Relationship-graph analysis:** "known contact" emails from an address with no prior
   history, first-contact from lookalike vendor domains, sudden shifts in established vendor
   patterns.
3. **Account-health / identity signals:** logins from new geographies or impossible travel,
   OAuth consent to unfamiliar apps, anomalous token/session usage, privilege escalation.

When Layer 2 flags a compromise it triggers a **retroactive review**: similar already-delivered
emails are pulled and re-evaluated. One detection protects the whole organisation.

## The feedback loop (critical — do not break this)

The two layers are **not** independent. This is the project's main differentiator:

- Indicators confirmed by **Layer 2 feed back into Layer 1's scoring and blocklists.**
- Layer 1's **flagged-but-undelivered emails provide context for Layer 2's behavioural analysis.**

Any change to scoring, storage, or the detection pipeline must preserve this bidirectional flow.

See also: [ml.md](ml.md) (where models fit), [principles.md](principles.md) (signals aggregate;
human-in-the-loop), [backend.md](backend.md) (where the pipeline lives in code).
