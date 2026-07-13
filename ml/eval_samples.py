"""
Curated MODERN emails used ONLY as an out-of-distribution guard set — never for
training. They approximate contemporary mail (SaaS/notification/personal) that
neither training corpus (2001 Enron, 2002-03 SpamAssassin, 2022-24 phishing_pot)
represents well. The metric that matters: how many modern LEGIT emails get
misflagged as phishing (false-positive rate on realistic inbox mail).
"""
from __future__ import annotations

LEGIT_MODERN: list[tuple[str, str]] = [
    ("github-notif", "Subject: [org/repo] PR #482: Fix flaky auth test\n\n@alice requested your review on this pull request. 3 files changed. View it on GitHub or reply to this email to comment."),
    ("calendar", "Subject: Invitation: Sprint planning @ Mon Jul 14 10am\n\nYou have been invited to Sprint planning. When: Monday, 10:00-11:00. Where: Google Meet. Organizer: bob@company.com. RSVP: Yes / No / Maybe."),
    ("saas-receipt", "Subject: Your receipt from Figma\n\nThanks for your payment. Plan: Professional, Amount: $12.00, Billing period: Jul 12 - Aug 12. Download your invoice from the billing page in your account settings."),
    ("coworker", "Subject: notes from standup\n\nHey, quick recap: we're pushing the release to Thursday, Priya is picking up the migration ticket, and I'll circle back on the caching bug tomorrow. Thanks!"),
    ("newsletter", "Subject: This week in Python\n\nHighlights: PEP 750 template strings land, a deep dive on asyncio task groups, and three libraries worth a look. Read online. Unsubscribe anytime."),
    ("slack-digest", "Subject: You have 4 unread messages in #engineering\n\nWhile you were away there was activity in your workspace. Catch up on the conversation in Slack."),
    ("shipping", "Subject: Your order has shipped\n\nGood news! Your order #A1029 is on its way and should arrive Thursday. Track your package or view order details from your account."),
    ("password-legit", "Subject: Your verification code\n\nYour one-time code is 480913. It expires in 10 minutes. If you didn't request this, you can safely ignore this email."),
]

PHISH_MODERN: list[tuple[str, str]] = [
    ("mfa-reset", "Subject: Action required: verify your account\n\nWe detected an unusual sign-in. Your account will be locked in 24 hours. Confirm your identity now at http://secure-login-verify.com to avoid suspension."),
    ("gift-card", "Subject: quick favor\n\nAre you at your desk? I need you to purchase five $100 Apple gift cards for a client gift. Send me the codes as soon as you can, I'm in a meeting. - CEO, sent from my iPhone"),
    ("invoice-scam", "Subject: Overdue invoice #INV-2231\n\nYour payment is past due. To avoid a late fee, settle immediately by clicking the secure payment link below. Failure to pay will result in account termination."),
    ("docusign", "Subject: You have a document to sign\n\nA document has been shared with you and requires your signature. Review and sign at http://docu-sign-secure.info/document before it expires today."),
    ("crypto", "Subject: Your wallet has a pending deposit\n\nA transfer of 0.85 BTC is pending. Verify your wallet within 12 hours to claim your funds or they will be returned to sender."),
]
