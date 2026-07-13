# High-Level Plan For Identifying Phishing Emails Using AI

## Summary

Modern phishing attacks have outpaced traditional email filtering. The most damaging campaigns today are Business Email Compromise, vendor fraud, thread hijacking, and identity-based attacks. These attacks succeed not because filters miss malicious content, but because there is often no malicious content to find. They exploit trust, relationships, and legitimate infrastructure.

This plan proposes a structured, phased detection capability that addresses both traditional threats and modern attack patterns. It is designed to be realistic to implement, measurable at each stage, and extensible as attacker techniques continue to evolve.

## The Problem with Current Defences

Most email security tools in use today were built around the core assumption that phishing emails contain something detectable, a known bad URL, a suspicious attachment, or a blacklisted sender domain. That assumption held for a long time. It holds less and less now.

The attack categories causing the most damage have shifted. The ones that now slip through most consistently are not the ones with malicious payloads; they are the ones that look completely legit:

1. **Attacks with no malicious content:**
   - Business Email Compromise (BEC)
   - Vendor Email Compromise (VEC)
   - Thread Hijacking

2. **Attacks that hide from scanners:**
   - QR Code phishing (Quishing)
   - Delayed payload attacks

3. **Attacks that bypass content analysis entirely:**
   - AI-generated spear phishing
   - Identity-based attacks (AiTM, OAuth abuse, session theft)

**The core gap:** These attacks do not share a common indicator. Credential phishing needs URL analysis. BEC needs behavioural content. Quishing needs image processing. Identity attacks need post-delivery monitoring. This is the reason a single detection model or a single tool cannot solve the problem, which is why a layered approach is the right direction.

## Proposed Detection Approach

The proposed approach organises detection into two layers. Each layer targets a different point in the attack chain and a different set of indicators. They are designed to complement each other: what Layer 1 cannot catch, Layer 2 is positioned to detect.

### Layer 1: Email Analysis (Pre-Delivery)

The first layer analyses emails before they reach the user. The goal is to intercept as much as possible at this stage. Every threat caught here removes the need for post-delivery handling.

Rather than making a binary decision from a single check, this layer collects signals from multiple sources and aggregates them into a risk score. No signal triggers a block; the weight of combined evidence does. This reduces false positives while maintaining coverage.

| Signal Type | What It Looks For | Detection Technique |
|---|---|---|
| **Header Analysis** | Authentication failures, reply-to mismatches, sender routing anomalies, lookalike display names | SPF, DKIM, DMARC Validation, heuristic rules on header fields |
| **Content Analysis** | Urgency language, payment or credential requests, authority impersonation, tone inconsistencies | NLP Classification trained on phishing corpora, pattern matching for high-risk language |
| **URL Analysis** | Newly registered domains, redirect chains, lookalike URLs, and credential harvest page structure | Domain age and WHOIS checks, threat intel feeds, link following and page content inspection |
| **Attachment Analysis** | Malicious macros, embedded executables, and disguised file types | File type validation, static analysis, sandbox detonation for high-risk attachments (Phase 2) |
| **QR Code Detection** | Malicious URLs hidden inside QR code images embedded in emails or PDFs | Image processing to extract and decode QR codes, and decoded URLs submitted to the standard URL analysis pipeline |
| **Threat Intelligence** | Known phishing infrastructure, IOCs, and recently reported campaigns | Cross-reference against external threat intel feeds and internal blocklists |

The output of Layer 1 is a risk score assigned to each email. Emails that exceed a high-risk threshold are quarantined automatically, while emails that fall within a medium-risk range are flagged for analyst review. Emails below the threshold are delivered to the user. This tiered approach helps balance security and usability by reducing analyst workload while avoiding excessive reliance on automated decisions.

### Layer 2: Behavioural & Identity Monitoring (Post-Delivery)

The second layer exists because some attacks cannot be stopped at the email level. A VEC attack uses a legitimate account. A thread hijacking attack lives inside a real conversation. An AiTM attack succeeds after a user clicks on the link that appeared clean. These only become visible through behaviour.

This layer monitors three things:

1. **Behavioural Baselines: User and account behaviour**
   - Unusual email send volume or timing relative to the user's established pattern.
   - Emails sent to new external recipients not previously contacted.
   - Auto-forward rules or inbox rules created that were not previously present.
   - Mass BCC or sudden changes in communication frequency.

2. **Relationship graph analysis: Communication relationships**
   - Emails purporting to be from a known contact, sent from an address with no prior communication history.
   - First-contact emails from domains that closely resemble known vendor domains.
   - Sudden changes in established vendor communication patterns.

3. **Account health monitoring: Identity signals**
   - Logins from new geographies or impossible travel scenarios.
   - OAuth application consent granted to unfamiliar third-party apps.
   - Unusual token usage, session anomalies, or privilege escalation attempts.

When Layer 2 flags a compromise, it triggers a retroactive review: similar emails already delivered to other inboxes are pulled and re-evaluated against the new information. One detection ends up protecting the whole organisation.

**How the layers connect:** Layer 2 is not independent of Layer 1. This feedback operates as a continuous loop: indicators confirmed by Layer 2 are fed back into Layer 1's scoring and blocklists, while Layer 1's flagged-but-undelivered emails provide additional context for Layer 2's behavioural analysis.

## Where AI/ML Learning Fits In

This is one tool within this approach, not the approach itself. It earns its place in specific situations where the volume of data, the need for contextual pattern recognition, or the rate of attacker evolution makes rule-based methods insufficient. Below is where it is used and why.

1. **Content Analysis (NLP Classification):** Rules can catch known phishing language. They cannot adapt to new phrasing, different languages, or AI-generated content that deliberately avoids known patterns. A classification model trained on a broad phishing corpus can generalise to new variants in a way that static rules cannot. It also scales — running inference across thousands of emails per minute is not feasible with manual rule review.

2. **Behavioural Analysis (Anomaly Detection):** Every user has a communication pattern — volume, timing, recipients, and response rates. Defining what is anomalous for one user is different from another. Anomaly detection models build per-user baselines automatically and flag meaningful deviations without requiring a handcrafted rule for every possible scenario.

3. **Relationship Analysis (Graph-Based Modelling):** The communication network of an organisation is a graph. Contacts, vendors, and internal teams form clusters of expected relationships. A vendor impersonation attack introduces a new node — a lookalike domain that tries to insert itself into an existing cluster. Graph-based analysis can detect structural anomalies like this that would be invisible to content-only scanning.

4. **QR Code Extraction (Computer Vision):** QR Codes embedded in images or PDFs cannot be read by standard text parsers. A computer vision model can identify, extract, and decode these images as part of an email processing pipeline, after which the decoded URL is handed to the standard link analysis workflow. This is a narrow, well-defined application of image processing.

Each of these models introduces its own risk: classification and anomaly detection models can drift as attacker behaviour and normal user behaviour evolve, so all AI-driven decisions remain subject to analyst review and periodic retraining rather than fully automated enforcement.

## Roadmap

The proposed approach can be introduced in phases, with each phase expanding detection coverage while building on capabilities established in earlier stages.

| Phase | Primary Focus | Why This Phase Comes Here | Key Risk |
|---|---|---|---|
| **Phase 1** | Header analysis, content NLP, URL Scanning, basic QR detection, threat intel | Fastest path to operational value. Establishes the data pipeline and analyst feedback loop needed for everything that follows. | Cold start, no historical baselines yet. |
| **Phase 2** | Sandbox detonation for attachments, enhanced QR analysis, explainability layer, analyst dashboard | Phase 1 data shows where sophisticated campaigns are slipping through. Phase 2 data closes those gaps. Explainability is added here because analysts need to trust decisions before the scope expands. | Sandbox infrastructure cost. Scoping carefully, not every attachment needs full detonation. |
| **Phase 3** | Behavioural analytics, relationship intelligence analysis, model retraining pipeline | Only viable once Phase 1 has been operating long enough to accumulate a meaningful communication history. Behavioural baselines built on insufficient data produce high false positive rates, which erode analyst trust before the capability has a chance to prove its value. | Data governance and behavioural monitoring require access to email metadata, which engages stakeholders early. |

Progression between phases is guided by the evidence each phase generates, rather than a fixed schedule. Moving from Phase 1 to Phase 2 should be informed by where sophisticated campaigns are slipping through detection. Moving to Phase 3 should be informed by having accumulated sufficient communication history to build reliable behavioural baselines, alongside engagement with stakeholders on data governance.

### Phase 1: Core Email Analysis

The first phase focuses on strengthening email-level detection before messages reach the user. The primary objective is to improve the detection of traditional phishing attempts and QR-based phishing before email delivery.

Key capabilities include:
- Header analysis using SPF, DKIM, and DMARC validation
- Content analysis using NLP-based classification
- Basic QR Code extraction and decoding
- Threat intelligence integration

### Phase 2: Advanced Threat Detection

The second phase focuses on improving visibility into more sophisticated phishing techniques that may bypass basic email analysis. The primary objective is to increase detection coverage for advanced phishing campaigns and provide analysts with greater visibility into why an email was flagged.

Key capabilities include:
- Sandbox validation for suspicious URLs and attachments
- Enhanced QR phishing analysis
- Explainability features for analyst investigations
- Expanded threat intelligence correlation

### Phase 3: Behavioural & Identity Intelligence

The final phase extends detection beyond email content and focuses on user behaviour, communication patterns, and identity-based indicators. The primary objective is to improve detection of BEC, VEC, thread hijacking, account compromise, OAuth abuse, and other identity-based attacks that may not be visible during initial email analysis.

## Current Market Solutions & Positioning

Today, most organizations rely on solutions such as Microsoft Defender for Office 365, Proofpoint, Mimecast, and Abnormal Security as their primary line of defence against phishing attacks. These platforms are highly effective at detecting many common threats through techniques such as URL analysis, attachment scanning, threat intelligence, reputation checks, and machine learning-based detection.

While researching the phishing landscape, one thing that stood out was that the challenge is no longer just detecting malicious emails. Many of the attacks causing the greatest impact today contain nothing identifiably malicious at all. The problem is less about identifying a malicious file or link and more about understanding the context surrounding the communication. Some of these platforms, particularly Abnormal Security, have begun incorporating behavioural and identity-based signals as well, reflecting a similar shift in the industry.

The goal of this proposal is not to compete directly with existing security platforms or suggest that current solutions are inadequate. Instead, the idea is to explore how additional layers of context can be incorporated into the detection process. The proposed approach combines email analysis with behavioural signals, communication relationships, and identity-based indicators within a single workflow. An important aspect of the design is the feedback loop between pre-delivery and post-delivery detection. If suspicious activity is identified after an email has been delivered, that information can be used to re-evaluate similar emails and strengthen future detections.

Rather than introducing a completely new detection technique, this proposal focuses on bringing together multiple perspectives of the same problem. The intention is to build a more complete view of phishing activity across the entire attack lifecycle, rather than relying solely on indicators present within the email itself.

## Risks & Challenges

While the proposed approach provides broader phishing detection coverage, several considerations should be taken into account during planning and implementation.

1. **Data availability:** Behavioural and relationship-based analysis depend on historical communication data to establish meaningful baselines. Limited historical data may reduce the effectiveness of these capabilities during initial deployment.

2. **False Positives:** Combining multiple detection layers improves coverage but can also increase false positives if detection thresholds are not carefully calibrated. Maintaining a balance between security and usability remains an important consideration.

3. **Infrastructure and Operational Cost:** Capabilities such as sandbox analysis, behavioural monitoring, threat intelligence integration, and machine learning inference require additional infrastructure and operational resources. The value provided by each capability should be considered alongside its operational cost.

4. **Data Governance:** Behavioural and identity monitoring require access to communication and account metadata, introducing privacy and governance considerations.

5. **Evolving Threats:** Attackers continuously adapt their techniques. Detection models and intelligence sources must be reviewed and updated regularly to remain effective.

## Conclusion

The phishing problem is not going to be solved by a better spam filter. The attacks that cause the most damage today do not look like spam. They look like legitimate emails from real people, real accounts, and real vendors. Detection has to evolve to match that.

The plan proposed here is not trying to build a perfect system. It is trying to build a significantly better one, in a way that is realistic to implement, measurable at each stage, and honest about its limitations. Each phase delivers value on its own and creates the conditions for the next one to work properly.
