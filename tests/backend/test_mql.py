"""Sublime MQL -> REMN converter: structural subset translates exactly, the rest is skipped."""
from __future__ import annotations

import uuid

import pytest

from services.parsers.mail.common import ParseContext, build_row
from services.rules import mql
from services.store import rules as R
from services.store.casestore import StoreRegistry
from services.store.sqlfilter import Ctx, compile_cond
from services.store.writers import MailWriter


def _rule(source: str, **meta) -> dict:
    doc = {"name": meta.get("name", "Test rule"), "id": meta.get("id", "aaaaaaaa-1111-2222-3333-444444444444"), "severity": meta.get("severity", "high"),
           "type": "rule", "source": source, "attack_types": ["Credential Phishing"], "tactics_and_techniques": ["Impersonation: Brand"]}
    return mql.convert_rule(doc)


@pytest.fixture
def store(tmp_path):
    reg = StoreRegistry()
    reg.configure(tmp_path / "cases")
    st = reg.get(str(uuid.uuid4()))
    yield st
    reg.close_all()


def test_simple_sender_rule():
    r = _rule("type.inbound\nand sender.email.domain.root_domain == 'domainsbyproxy.com'", name="Service abuse: Domains By Proxy sender")
    assert r["ok"], r
    assert r["rule"]["where"] == {"fromRegistrable": "domainsbyproxy.com"}
    assert r["rule"]["id"] == "sublime-aaaaaaaa-1111-2222-3333-444444444444" and r["rule"]["source"] == "mails"
    assert r["rule"]["tags"] == ["sublime", "credential-phishing", "impersonation-brand"]
    compile_cond(r["rule"]["where"], Ctx(source="mails"))


def test_links_lists_and_auth_guard():
    src = """type.inbound
and sender.email.email == "no-reply@accounts.google.com"
and any(body.links, .href_url.domain.domain in $free_file_hosts)
and not (
  sender.email.domain.root_domain in $high_trust_sender_root_domains
  and coalesce(headers.auth_summary.dmarc.pass, false)
)"""
    r = _rule(src)
    assert r["ok"], r
    w = r["rule"]["where"]
    assert w["fromAddr"] == "no-reply@accounts.google.com"
    assert "drive.google.com" in w["urls.host|in"] or "dropbox.com" in w["urls.host|in"]
    assert w["not"]["auth.dmarc"] == "pass" and "microsoft.com" in w["not"]["fromRegistrable|in"]
    assert any("high_trust" in x for x in r["warnings"])
    compile_cond(w, Ctx(source="mails"))


def test_org_settings_strings_and_regex():
    src = """type.inbound
and sender.email.domain.root_domain not in $org_domains
and sender.display_name in~ $org_vips
and (
  strings.ilike(subject.subject, "*invoice*", "urgent*")
  or regex.icontains(body.current_thread.text, "wire\\s+transfer", "gift ?cards?")
)
and strings.istarts_with(sender.email.local_part, "ceo", "president")
and sender.email.domain.tld in ("top", "xyz")
and length(attachments) > 0
and length(body.links) == 0
and subject.is_reply
"""
    r = _rule(src)
    assert r["ok"], r
    w = r["rule"]["where"]
    assert w["fromRegistrable|nin_setting"] == "internal_domains"
    assert w["fromNameNorm|in_setting"] == "vip_names"
    alts = w["any_of"]
    assert {"subject|contains": "invoice"} in alts and {"subject|startswith": "urgent"} in alts
    assert {"bodyText|re": ["wire\\s+transfer", "gift ?cards?"]} in alts
    assert w["fromAddr|re"] == ["^ceo", "^president"]
    assert w["fromRegistrable|endswith"] == [".top", ".xyz"]
    assert w["attachmentCount|gt"] == 0 and w["urlCount"] == 0
    assert w["subject|re"].startswith("^")
    assert any("current_thread" in x for x in r["warnings"])
    compile_cond(w, Ctx(source="mails"))


def test_unsupported_constructs_are_skipped():
    bad = [
        "type.inbound and any(ml.nlu_classifier(body.current_thread.text).intents, .name == 'cred_theft')",
        "type.inbound and profile.by_sender().prevalence == 'new'",
        "type.inbound and length(filter(body.links, .href_url.domain.root_domain == 'x.com')) == 1",
        "type.inbound and all(recipients.to, .email.domain.domain == 'x.com')",
        "type.inbound and sender.email.domain.root_domain == headers.return_path.domain.root_domain",
        "type.inbound and sender.email.email in $recipient_emails",
        "type.inbound",
    ]
    for src in bad:
        r = _rule(src)
        assert not r["ok"], src
    assert "ml.nlu_classifier" in _rule(bad[0])["error"]
    assert "profile.by_sender" in _rule(bad[1])["error"]
    # Sublime's own quantifier and trailing commas
    ok = _rule("type.inbound and 1 of (sender.email.domain.root_domain == 'a.com', subject.subject == 'x',) and sender.email.email in ('a@a.com', 'b@a.com', )")
    assert ok["ok"], ok
    assert ok["rule"]["where"]["any_of"] == [{"fromRegistrable": "a.com"}, {"subject": "x"}]
    assert ok["rule"]["where"]["fromAddr|in"] == ["a@a.com", "b@a.com"]
    assert "every message" in _rule(bad[6])["error"]


def test_filter_all_levenshtein_and_chained_comparisons(store):
    src = """type.inbound
and any(filter(body.links, .href_url.domain.root_domain == 'evil-login.net'), strings.icontains(.display_text, 'login'))
and length(filter(attachments, .file_extension in~ ('exe', 'scr'))) == 0
and all(recipients.to, .email.domain.domain != 'partner.example')
and strings.ilevenshtein(sender.display_name, 'apple developer') <= 2
and 0 < length(body.links) < 10
and sender.display_name !~ 'apple developer team'
"""
    r = _rule(src, name="levenshtein")
    assert r["ok"], r
    w = r["rule"]["where"]
    assert w["urls.domain"] == "evil-login.net" and w["urls.text|contains"] == "login"
    assert w["not"] == {"attachments.ext|in": ["exe", "scr"]}
    assert w["to.domain|ne"] == "partner.example"
    assert w["fromName|levenshtein"] == ["apple developer", 2]
    assert w["urlCount|gt"] == 0 and w["urlCount|lt"] == 10
    assert w["fromName|ne"] == "apple developer team"
    assert any("independently" in x for x in r["warnings"])
    compile_cond(w, Ctx(source="mails"))
    # the operator on the SQL engine
    ctx = ParseContext(internal_domains=["interne.fr"])
    wri = MailWriter(store, 1)
    for name in ("Apple Developer", "Appel Developer", "Apple Support"):
        headers = [("From", f"{name} <x@evil-login.net>"), ("To", "<user@interne.fr>"), ("Subject", "hi"),
                   ("Date", "Tue, 1 Sep 2026 11:00:00 +0200"), ("Message-ID", f"<{uuid.uuid4()}@x>")]
        wri.add(build_row(headers, "body", None, [], ctx, folder="Inbox", size=None, extra={}))
    wri.flush()
    hits = R.run_rule(store, {"id": "lev", "title": "lev", "severity": "low", "source": "mails", "where": {"fromName|levenshtein": ["apple developer", 2]}}, {})
    assert sorted(ref for h in hits for ref in h["refs"]) == [1, 2]


def test_attachment_rule_runs_end_to_end(store):
    src = """type.inbound
and any(attachments, .file_extension in~ $file_extensions_macros or .file_name =~ "invoice.pdf.exe")
and strings.icontains(subject.subject, "invoice", "facture")
"""
    r = _rule(src, name="Macro attachment with invoice subject")
    assert r["ok"], r
    ctx = ParseContext(internal_domains=["interne.fr"])

    def mail(subject, atts):
        headers = [("From", "Vendor <billing@vendor-mail.com>"), ("To", "<user@interne.fr>"), ("Subject", subject),
                   ("Date", "Tue, 1 Sep 2026 11:00:00 +0200"), ("Message-ID", f"<{uuid.uuid4()}@vendor-mail.com>")]
        row = build_row(headers, "please see attached", None, [], ctx, folder="Inbox", size=None, extra={})
        row["attachments"] = [{"name": n, "ext": n.rsplit(".", 1)[-1].lower(), "size": 10, "risk": 0, "flags": [], "sha256": None, "md5": None,
                               "realExt": None, "realMime": None, "category": "document", "inline": False, "details": {}} for n in atts]
        row["attachmentCount"] = len(atts)
        return row

    w = MailWriter(store, 1)
    w.add(mail("Facture 2026-09", ["order.docm"]))          # hit: macro extension
    w.add(mail("Invoice", ["Invoice.PDF.exe"]))             # hit: name match (case-insensitive)
    w.add(mail("Invoice", ["report.pdf"]))                  # no: plain pdf
    w.add(mail("Holiday photos", ["fun.xlsm"]))             # no: subject
    w.flush()
    hits = R.run_rule(store, r["rule"], {"internal_domains": ["interne.fr"]})
    assert sorted(ref for h in hits for ref in h["refs"]) == [1, 2], hits
