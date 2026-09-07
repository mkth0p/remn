"""
Domains that well-known brands actually own, and the closed brand TLDs they operate.

Used by the lookalike analyser: a sender under one of these *is* the brand, not a
lookalike of it. The first real Outlook export (2026-09-04) flagged teams.mail.microsoft
(as a "gmail" edit-distance lookalike: under the .microsoft TLD the second-level label is
"mail"), contoso.onmicrosoft.com ("microsoft", distance 2), service-now.com and
credit-agricole.fr (hyphen stripped == brand) - together 80 % of the lookalike findings.
"""

from __future__ import annotations

from services.reference.notification_senders import NOTIFICATION_SENDERS

# Closed brand gTLDs: delegated to the brand, not open for registration. Open TLDs that
# happen to be brand names too (.live, .ing, .free) are deliberately NOT here.
BRAND_TLDS: frozenset[str] = frozenset(
    {
        "microsoft",
        "office",
        "windows",
        "xbox",
        "skype",
        "hotmail",
        "azure",
        "bing",
        "google",
        "gmail",
        "youtube",
        "android",
        "chrome",
        "amazon",
        "apple",
        "netflix",
        "adobe",
        "dhl",
        "fedex",
        "orange",
        "sfr",
        "bnpparibas",
        "sap",
        "ovh",
    }
)

_BRAND_DOMAINS: dict[str, tuple[str, ...]] = {
    "microsoft": (
        "microsoft.com",
        "onmicrosoft.com",
        "microsoftonline.com",
        "office.com",
        "office365.com",
        "live.com",
        "outlook.com",
        "hotmail.com",
        "msn.com",
        "sharepointonline.com",
        "sharepoint.com",
        "azure.com",
        "windows.net",
        "windows.com",
        "skype.com",
        "xbox.com",
        "bing.com",
        "yammer.com",
        "mail.microsoft",
        "microsoft.net",
    ),
    "google": ("google.com", "googlemail.com", "gmail.com", "youtube.com", "googleapis.com", "withgoogle.com", "google.fr"),
    "amazon": ("amazon.com", "amazon.fr", "amazon.de", "amazon.co.uk", "amazonaws.com", "amazonses.com"),
    "apple": ("apple.com", "icloud.com", "me.com", "mac.com"),
    "paypal": ("paypal.com", "paypal.fr", "paypalobjects.com"),
    "docusign": ("docusign.com", "docusign.net"),
    "dropbox": ("dropbox.com", "dropboxmail.com"),
    "adobe": ("adobe.com", "adobesign.com"),
    "dhl": ("dhl.com", "dhl.de", "dhl.fr"),
    "ups": ("ups.com",),
    "fedex": ("fedex.com",),
    "chronopost": ("chronopost.fr",),
    "laposte": ("laposte.fr", "laposte.net"),
    "colissimo": ("colissimo.fr",),
    "netflix": ("netflix.com",),
    "facebook": ("facebook.com", "facebookmail.com"),
    "instagram": ("instagram.com",),
    "linkedin": ("linkedin.com",),
    "whatsapp": ("whatsapp.com",),
    "orange": ("orange.fr", "orange.com"),
    "sfr": ("sfr.fr",),
    "free": ("free.fr", "proxad.net"),
    "bouygues": ("bouyguestelecom.fr",),
    "ameli": ("ameli.fr",),
    "caf": ("caf.fr",),
    "edf": ("edf.fr",),
    "engie": ("engie.com", "engie.fr"),
    "bnpparibas": ("bnpparibas.com", "bnpparibas.net"),
    "societegenerale": ("societegenerale.fr", "societegenerale.com", "socgen.com"),
    "creditagricole": ("credit-agricole.fr", "credit-agricole.com"),
    "lcl": ("lcl.fr",),
    "caisse-epargne": ("caisse-epargne.fr",),
    "boursorama": ("boursorama.com",),
    "banquepopulaire": ("banquepopulaire.fr",),
    "cic": ("cic.fr",),
    "creditmutuel": ("creditmutuel.fr",),
    "labanquepostale": ("labanquepostale.fr",),
    "ing": ("ing.fr", "ing.com"),
    "revolut": ("revolut.com",),
    "n26": ("n26.com",),
    "visa": ("visa.com", "visa.fr"),
    "mastercard": ("mastercard.com",),
    "ovh": ("ovh.com", "ovh.net", "ovhcloud.com"),
    "zoom": ("zoom.us", "zoom.com"),
    "webex": ("webex.com",),
    "okta": ("okta.com",),
    "github": ("github.com",),
    "slack": ("slack.com",),
    "servicenow": ("servicenow.com", "service-now.com"),
    "salesforce": ("salesforce.com",),
    "hubspot": ("hubspot.com",),
    "sap": ("sap.com",),
}

BRAND_OWNED_DOMAINS: frozenset[str] = frozenset(d for doms in _BRAND_DOMAINS.values() for d in doms) | frozenset(NOTIFICATION_SENDERS)
