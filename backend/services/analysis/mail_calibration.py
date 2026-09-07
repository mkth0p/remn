"""Versioned mail calibration over retained facts, shared by ingestion and rescoring.

Confidence describes support for an attack hypothesis, not a probability or a
verdict that an authenticated/established sender is safe.
"""

from __future__ import annotations

from typing import Any

from services.analysis.attachments.analyzer import rescore_attachment

VERSION = "mail-2"
IDENTITY_EVIDENCE = {
    "internal_spoof",
    "sender_lookalike_internal",
    "replyto_lookalike_internal",
    "sender_homoglyph",
    "sender_digit_substitution",
    "sender_subdomain_trick",
    "display_name_email_mismatch",
}
LINK_EVIDENCE = {"url_userinfo", "url_script_uri", "url_executable_download", "url_text_href_mismatch", "url_credential_keywords"}
CONTEXT_FLAGS = {"mail_corroborated", "sender_expected", "sender_auth_regression", "sender_history_unknown"}


def aligned_auth(row: dict[str, Any]) -> bool:
    auth = row.get("auth") or {}
    flags = set(row.get("flags") or [])
    if "exchange_internal" in flags:
        return True
    if auth.get("arc") == "pass" and "compauth_fail" not in flags:
        return True
    if auth.get("dmarc") == "pass":
        return True
    if {"dmarc_fail", "compauth_fail"} & flags:
        return False
    domain = str(row.get("fromRegistrable") or "").lower()
    from services.analysis.lookalike import registrable

    # A pass for an unrelated envelope/signing domain never grants sender trust.
    return any(
        auth.get(kind) == "pass" and auth.get(field) and registrable(str(auth[field])) == domain
        for kind, field in (("spf", "spfDomain"), ("dkim", "dkimDomain"))
    )


def calibrate_mail(row: dict[str, Any], settings: dict[str, Any] | None = None) -> dict[str, Any]:
    from services.parsers.mail.common import _score, _user_trusted, score_groups
    from services.reference.notification_senders import NOTIFICATION_SENDERS

    settings = settings or {}
    out = dict(row)
    flags = set(row.get("flags") or []) - CONTEXT_FLAGS
    attachments = [rescore_attachment(a) for a in row.get("attachments") or []]
    # Legacy rows with missing summaries keep their attachment observations.
    if attachments or not row.get("attachmentCount"):
        flags = {f for f in flags if not f.startswith("att_")}
        flags.update("att_" + f for a in attachments for f in a["flags"])
    max_att = max((int(a["risk"]) for a in attachments), default=int(row.get("maxAttachmentRisk") or 0))
    known = row.get("senderSolicited") is True or (int(row.get("senderPriorCount") or 0) >= 5 and int(row.get("senderDaysKnown") or 0) >= 7)
    regression = row.get("senderAuthRegression") is True
    if regression:
        flags.add("sender_auth_regression")
    if row.get("senderPrevalence") is None:
        flags.add("sender_history_unknown")
    auth_ok = aligned_auth(row)
    identity = bool(flags & IDENTITY_EVIDENCE)
    links = bool(flags & LINK_EVIDENCE)
    auth_failure = bool(flags & {"dmarc_fail", "compauth_fail"}) and not auth_ok
    corroborated = identity or links or regression and auth_failure
    if corroborated:
        flags.add("mail_corroborated")
    expected = known and auth_ok and not regression and not identity
    if expected:
        flags.add("sender_expected")

    # Recompute old wording composites: free webmail / a different Reply-To alone
    # are not independent evidence of BEC or credential theft.
    hits = set((row.get("keywordHits") or {}).keys())
    flags -= {"bec_pattern", "credential_phishing_pattern"}
    pressure = bool(hits & {"urgency", "secrecy", "availability"})
    if hits & {"financial", "gift_card"} and pressure and "authority" in hits and corroborated:
        flags.add("bec_pattern")
    if "credentials" in hits and "urgency" in hits and corroborated:
        flags.add("credential_phishing_pattern")

    internal = str(row.get("fromRegistrable") or "").lower() in {str(d).lower().lstrip("@") for d in settings.get("internal_domains", [])}
    trusted = _user_trusted(
        str(row.get("fromAddr") or ""), str(row.get("fromDomain") or ""), str(row.get("fromRegistrable") or ""), settings.get("trusted_senders") or []
    )
    notification = row.get("fromRegistrable") in NOTIFICATION_SENDERS and auth_ok
    flags.discard("trusted_sender")
    if trusted or notification:
        flags.add("trusted_sender")
    trust = {
        "authenticated": auth_ok,
        "internal": internal,
        "bulk": "bulk_mailer" in flags or bool(row.get("listId")),
        "notification": notification,
        "user_trusted": trusted,
        "synthetic_internal": bool(row.get("syntheticHeaders")) and internal,
    }
    risk = _score(flags, max_att, trust)
    # History reduces only weak/anomaly-based concern. Payloads, phishing forms,
    # deceptive links and identity evidence retain their score.
    strong_content = flags & {"bec_pattern", "credential_phishing_pattern", "html_form_password", "html_form_external"}
    if expected and not corroborated and not strong_content:
        risk = max(min(risk, 35), int(max_att * 0.9))
    confidence = "high" if max_att >= 80 or strong_content and corroborated else "medium" if corroborated or risk >= 40 else "low"
    limitations: list[str] = []
    if any(a.get("rescoreLimited") for a in attachments) or (row.get("attachmentCount") or 0) > len(attachments):
        limitations.append("Some attachment details are incomplete; re-ingest the original evidence for full analysis.")
    out.update(
        flags=sorted(flags),
        attachments=attachments,
        maxAttachmentRisk=max_att,
        risk=risk,
        assessment={
            "version": VERSION,
            "confidence": confidence,
            "groups": score_groups(flags),
            "attachmentRisk": max_att,
            "expectedSender": expected,
            "limitations": limitations,
        },
    )
    return out
