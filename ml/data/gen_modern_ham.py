"""
Generate a synthetic MODERN legitimate-email corpus to fill a real gap: neither
Enron (2001) nor SpamAssassin (2002-03) contains contemporary transactional /
notification mail (receipts, OTP codes, shipping, SaaS/dev notifications). The
v0.2.0 model therefore over-flagged that style as phishing.

This is targeted data augmentation, NOT a substitute for a real modern corpus:
  - Heavily randomized slots (vendors, names, amounts, ids) so the model can't
    latch onto a fixed template signature and create a NEW artifact.
  - Deliberately shares vocabulary with phishing ("account", "verify", "code",
    "payment", "invoice", "sign in") so the model learns these words are NOT by
    themselves phishing — the malicious cues are the combination (urgency +
    threat + credential-harvest link), which phishing_pot still supplies.
  - Kept DISJOINT from ml/eval_samples.py (the held-out guard set).

Writes ml/data/modern_ham/*.txt.  Run: ml/.venv/bin/python ml/data/gen_modern_ham.py
"""
from __future__ import annotations

import random
from pathlib import Path

OUT = Path(__file__).parent / "modern_ham"
SEED = 7
N_PER_CATEGORY = 70

VENDORS = ["Figma", "Notion", "Linear", "Slack", "GitHub", "GitLab", "Stripe",
           "Vercel", "Netlify", "Datadog", "Atlassian", "Zoom", "Dropbox",
           "Shopify", "Amazon", "Uber", "DoorDash", "Airbnb", "Spotify",
           "Adobe", "Canva", "Miro", "Asana", "Trello", "1Password"]
NAMES = ["Alex", "Priya", "Sam", "Jordan", "Wei", "Maria", "Tom", "Nadia",
         "Chen", "Omar", "Grace", "Leo", "Sara", "Diego", "Yuki", "Hannah"]
PRODUCTS = ["Pro plan", "Team plan", "Business plan", "annual subscription",
            "monthly subscription", "Premium", "Standard tier"]
CARRIERS = ["UPS", "FedEx", "DHL", "USPS", "Royal Mail", "Australia Post"]
ITEMS = ["wireless headphones", "a mechanical keyboard", "running shoes",
         "a coffee grinder", "a desk lamp", "a phone case", "notebooks",
         "a water bottle", "a monitor stand", "a backpack"]


def r(rng, lo, hi):
    return rng.randint(lo, hi)


def gen_receipt(rng):
    v = rng.choice(VENDORS); amt = f"${r(rng,5,240)}.{r(rng,0,99):02d}"
    p = rng.choice(PRODUCTS)
    return (f"Your receipt from {v}",
            f"Thanks for your payment. We've charged {amt} for your {p}. "
            f"Invoice #{r(rng,10000,99999)} is available in your billing settings. "
            f"Your next billing date is next month. Questions about this charge? "
            f"Reply to this email and our team will help.")


def gen_shipping(rng):
    c = rng.choice(CARRIERS); it = rng.choice(ITEMS)
    return (f"Your order has shipped",
            f"Good news — your order of {it} is on its way with {c}. "
            f"Tracking number {r(rng,10**9,10**10)}. Estimated delivery in "
            f"{r(rng,2,6)} days. You can view order #{r(rng,100000,999999)} and "
            f"track the package from your account order history.")


def gen_otp(rng):
    v = rng.choice(VENDORS)
    return (f"Your {v} verification code",
            f"Your one-time verification code is {r(rng,100000,999999)}. "
            f"It expires in {r(rng,5,15)} minutes. Enter it to finish signing in. "
            f"If you didn't request this code, you can safely ignore this email — "
            f"your account is secure.")


def gen_pwreset(rng):
    v = rng.choice(VENDORS)
    return (f"Reset your {v} password",
            f"We received a request to reset the password for your {v} account. "
            f"Use the link in your account settings to choose a new password within "
            f"{r(rng,30,60)} minutes. If you didn't ask to reset it, no action is "
            f"needed and your current password still works.")


def gen_calendar(rng):
    n = rng.choice(NAMES)
    return (f"Invitation: {rng.choice(['Sprint planning','1:1','Design review','Retro','All-hands'])}",
            f"{n} has invited you to a meeting. When: next {rng.choice(['Monday','Tuesday','Wednesday'])} "
            f"at {r(rng,8,11)}:00. Where: video call. Agenda attached. "
            f"Please RSVP yes, no, or maybe from your calendar.")


def gen_github(rng):
    n = rng.choice(NAMES)
    return (f"[org/repo] PR #{r(rng,100,900)}: {rng.choice(['Fix flaky test','Add caching layer','Refactor auth','Bump deps'])}",
            f"{n} requested your review on this pull request. "
            f"{r(rng,1,9)} files changed, {r(rng,2,200)} additions. "
            f"Reply to this email to comment, or review the changes in the repository.")


def gen_ticket(rng):
    n = rng.choice(NAMES)
    return (f"[{rng.choice(['JIRA','Linear','Asana'])}] {rng.choice(['BUG','TASK','STORY'])}-{r(rng,100,999)} assigned to you",
            f"{n} assigned you a ticket. Status: In Progress. Priority: "
            f"{rng.choice(['Low','Medium','High'])}. Due next week. "
            f"View the ticket and add a comment from your project board.")


def gen_digest(rng):
    return (f"You have {r(rng,2,15)} unread messages",
            f"While you were away there was new activity in your workspace across "
            f"{r(rng,1,6)} channels. Catch up on the conversation when you have a "
            f"moment. You can adjust notification settings anytime.")


def gen_newsletter(rng):
    return (f"This week in {rng.choice(['Python','Frontend','DevOps','Design','Data'])}",
            f"Highlights this week: a deep dive on {rng.choice(['async patterns','type systems','caching','testing'])}, "
            f"{r(rng,2,5)} libraries worth a look, and community news. "
            f"Read the full issue online. You are receiving this because you subscribed; "
            f"unsubscribe anytime from the footer.")


def gen_renewal(rng):
    v = rng.choice(VENDORS); p = rng.choice(PRODUCTS)
    return (f"Your {v} subscription renews soon",
            f"Your {p} will automatically renew next week for "
            f"${r(rng,9,199)}.{r(rng,0,99):02d}. No action is needed to continue. "
            f"To review or change your plan, visit billing in your account settings.")


def gen_welcome(rng):
    v = rng.choice(VENDORS); n = rng.choice(NAMES)
    return (f"Welcome to {v}, {n}!",
            f"Thanks for signing up. Here are a few tips to get started with your "
            f"new account. Invite your team, set up your first project, and explore "
            f"the docs. We're glad you're here — reply if you need a hand.")


def gen_coworker(rng):
    n = rng.choice(NAMES)
    return (f"re: {rng.choice(['notes from standup','the migration','next release','budget'])}",
            f"Hey, quick follow-up: {n} is taking the migration ticket, we're moving "
            f"the release to {rng.choice(['Thursday','Friday','next week'])}, and I'll "
            f"circle back on the report tomorrow. Let me know if that works. Thanks!")


GENERATORS = [gen_receipt, gen_shipping, gen_otp, gen_pwreset, gen_calendar,
              gen_github, gen_ticket, gen_digest, gen_newsletter, gen_renewal,
              gen_welcome, gen_coworker]


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    for f in OUT.glob("*.txt"):
        f.unlink()
    rng = random.Random(SEED)
    i = 0
    for gen in GENERATORS:
        for _ in range(N_PER_CATEGORY):
            subject, body = gen(rng)
            (OUT / f"modern_{i:05d}.txt").write_text(f"Subject: {subject}\n\n{body}",
                                                     encoding="utf-8")
            i += 1
    print(f"[OK] wrote {i} modern-ham emails to {OUT}")


if __name__ == "__main__":
    main()
