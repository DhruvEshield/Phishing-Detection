"""Seed list of legitimate brand domains for lookalike-domain detection.

Maps a brand's short name to its real, canonical domain. Fed into the
brand_intel dnstwist wrapper to generate and check for typosquat/homoglyph/
combosquat lookalikes. Manually maintained — add a brand here when it's
observed being impersonated in real traffic.
"""
BRAND_SEEDS: dict[str, str] = {
    "microsoft": "microsoft.com",
    "google": "google.com",
    "apple": "apple.com",
    "amazon": "amazon.com",
    "paypal": "paypal.com",
    "netflix": "netflix.com",
    "facebook": "facebook.com",
    "linkedin": "linkedin.com",
    "instagram": "instagram.com",
    "twitter": "twitter.com",
    "dropbox": "dropbox.com",
    "docusign": "docusign.com",
    "zoom": "zoom.us",
    "slack": "slack.com",
    "github": "github.com",
    "salesforce": "salesforce.com",
    "chase": "chase.com",
    "bankofamerica": "bankofamerica.com",
    "wellsfargo": "wellsfargo.com",
    "americanexpress": "americanexpress.com",
    "fedex": "fedex.com",
    "ups": "ups.com",
    "dhl": "dhl.com",
    "adobe": "adobe.com",
    "coinbase": "coinbase.com",
}
