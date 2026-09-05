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
        "type.inbound and length(filter(body.links, .href_url.domain.root_domain == 'x.com')) == 1",
        "type.inbound and all(recipients.to, .email.domain.domain == 'x.com')",
        "type.inbound and sender.email.domain.root_domain == headers.return_path.domain.root_domain",
        "type.inbound",
    ]
    for src in bad:
        r = _rule(src)
        assert not r["ok"], src
    assert "ml.nlu_classifier" in _rule(bad[0])["error"]
    assert "length(filter" in _rule(bad[1])["error"]
    # Sublime's own quantifier and trailing commas
    ok = _rule("type.inbound and 1 of (sender.email.domain.root_domain == 'a.com', subject.subject == 'x',) and sender.email.email in ('a@a.com', 'b@a.com', )")
    assert ok["ok"], ok
    assert ok["rule"]["where"]["any_of"] == [{"fromRegistrable": "a.com"}, {"subject": "x"}]
    assert ok["rule"]["where"]["fromAddr|in"] == ["a@a.com", "b@a.com"]
    assert "every message" in _rule(bad[4])["error"]


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


def test_profile_by_sender_maps_to_baseline_columns():
    r = _rule("type.inbound and profile.by_sender().prevalence == 'new' and not profile.by_sender().solicited and profile.by_sender().days_known < 7")
    assert r["ok"], r
    w = r["rule"]["where"]
    assert w["senderPrevalence"] == "new" and w["not"] == {"senderSolicited": True} and w["senderDaysKnown|lt"] == 7
    assert any("baseline" in x for x in r["warnings"])
    compile_cond(w, Ctx(source="mails"))
    assert not _rule("type.inbound and profile.by_sender().any_messages_malicious_or_spam")["ok"]


def test_negative_child_operator_binds_and_means_none_matches(store):
    """urls.domain|nin used to compile the positive form twice, leaving 4 '?' values unbound in DuckDB."""
    ctx = ParseContext(internal_domains=["contoso.com"])
    wri = MailWriter(store, 1)
    for i, links in enumerate((["https://a-site.com/x", "https://b-site.com/y"], ["https://b-site.com/z"])):
        headers = [("From", f"<s{i}@ext.example>"), ("To", "<alice@contoso.com>"), ("Subject", f"m{i}"), ("Date", "Mon, 01 Sep 2026 09:00:00 +0000"), ("Message-ID", f"<m{i}@ext.example>")]
        html = "<html><body>" + "".join(f'<a href="{u}">link</a>' for u in links) + "</body></html>"
        wri.add(build_row(headers, None, html, [], ctx, folder="Inbox", size=None, extra={}))
    wri.flush()
    rule = {"id": "t-nin-child", "title": "t", "severity": "low", "source": "mails", "where": {"urls.domain|nin": ["a-site.com", "x-site.com", "y-site.com", "z-site.com"], "urls.url|contains": "b-site.com"}}
    hits = R.run_rule(store, rule, {})
    assert len(hits) == 1 and hits[0]["entities"].get("subject") == "m1", hits


def test_doubled_quotes_lists_and_new_paths():
    """MQL escapes a quote by doubling it; the environment lists and the extra paths translate."""
    ok = mql.convert_text("""name: q
source: |
  type.inbound
  and strings.icontains(subject.subject, 'I''ll call you')
  and sender.email.email not in $recipient_emails
  and sender.display_name in~ $org_display_names
  and sender.email.domain.root_domain not in $tranco_10k
  and length(subject.subject) < 12
  and strings.ends_with(headers.auth_summary.spf.details.designator, '.onmicrosoft.com')
  and any(body.links, .href_url.domain.subdomain is not null and .href_url.fragment is not null and .href_url.domain.valid)
""", "q.yml")[0]
    assert ok["ok"], ok
    w = ok["rule"]["where"]
    assert w["subject|contains"] == "i'll call you".replace("i'", "I'") or w["subject|contains"] == "I'll call you"
    assert w["fromDomain|nin_setting"] == "internal_domains" and w["fromNameNorm|in_setting"] == "org_display_names"
    assert w["fromRegistrable|nin_setting"] == "tranco_10k" and w["subject|length"] == "< 12"
    assert w["auth.spfDomain|endswith_cs"] == ".onmicrosoft.com"  # strings.ends_with is case-sensitive in MQL
    assert w["urls.subdomain|exists"] is True and w["urls.fragment|exists"] is True and w["urls.domain|exists"] is True
    tranco = mql.convert_text("name: t\nsource: |\n  sender.email.domain.root_domain not in $tranco_1m\n", "t.yml")[0]
    assert tranco["ok"] and any("top 10k" in x for x in tranco["warnings"])
    bad = mql.convert_text("name: d\nsource: |\n  false // disabled\n", "d.yml")[0]
    assert not bad["ok"] and "disabled upstream" in bad["error"]


def test_length_builtin_list_and_derived_url_fields_on_sql_engine(store):
    ctx = ParseContext(internal_domains=["contoso.com"])
    wri = MailWriter(store, 1)
    cases = [("short", "<a href='https://www.tracker.top/p#frag-1'>x</a>", "s0@google.com"),
             ("a rather long subject line", "<a href='https://tracker.top/p'>x</a>", "s1@rare-sender.net")]
    for i, (subject, html, frm) in enumerate(cases):
        headers = [("From", f"<{frm}>"), ("To", "<alice@contoso.com>"), ("Subject", subject), ("Date", "Mon, 01 Sep 2026 09:00:00 +0000"), ("Message-ID", f"<n{i}@x.example>")]
        wri.add(build_row(headers, None, f"<html><body>{html}</body></html>", [], ctx, folder="Inbox", size=None, extra={}))
    wri.flush()

    def hits(where, settings=None):
        rule = {"id": "t", "title": "t", "severity": "low", "source": "mails", "where": where}
        return sorted(h["entities"]["subject"] for h in R.run_rule(store, rule, settings or {}))

    assert hits({"subject|length": "< 10"}) == ["short"]
    assert hits({"subject|length": ">= 10"}) == ["a rather long subject line"]
    assert hits({"subject|length": 5}) == ["short"]
    assert hits({"urls.subdomain|exists": True}) == ["short"]
    assert hits({"urls.subdomain": "www"}) == ["short"]
    assert hits({"urls.fragment|contains": "frag"}) == ["short"]
    assert hits({"urls.fragment|exists": False}) == ["a rather long subject line"]
    assert hits({"fromRegistrable|in_setting": "tranco_10k"}) == ["short"]  # google.com is in the bundled list
    assert hits({"fromRegistrable|nin_setting": "tranco_10k"}) == ["a rather long subject line"]
    assert hits({"fromRegistrable|in_setting": "tranco_10k"}, {"tranco_10k": ["rare-sender.net"]}) == ["a rather long subject line"]  # a case setting overrides
    assert R.diagnose_zero(store, {"id": "t", "title": "t", "severity": "low", "source": "mails", "where": {"fromRegistrable|in_setting": "tranco_10k", "subject": "zzz"}}, {})["reason"] == "no_selector_match"


def test_case_sensitive_string_functions_keep_their_case(store):
    r = _rule("type.inbound and strings.contains(subject.subject, 'hTTPs://') and strings.icontains(sender.display_name, 'DocuSign') and strings.starts_with(subject.subject, 'RE:') and strings.ends_with(sender.email.local_part, 'Admin')")
    assert r["ok"], r
    w = r["rule"]["where"]
    assert w["subject|contains_cs"] == "hTTPs://" and w["fromName|contains"] == "DocuSign" and w["subject|startswith_cs"] == "RE:"
    assert "fromAddr|re" in w  # derived kinds (local part) fall back to the case-insensitive regex, with a warning
    assert any("case-sensitive in MQL" in x for x in r["warnings"])
    ctx = ParseContext(internal_domains=["interne.fr"])
    wri = MailWriter(store, 1)
    for subject in ("Click https://x.example/a", "Click hTTPs://x.example/a", "RE: hello"):
        headers = [("From", "<a@ext.example>"), ("To", "<u@interne.fr>"), ("Subject", subject), ("Date", "Tue, 1 Sep 2026 11:00:00 +0200"), ("Message-ID", f"<{uuid.uuid4()}@x>")]
        wri.add(build_row(headers, subject, None, [], ctx, folder="Inbox", size=None, extra={}))  # the link is in the body too
    wri.flush()
    def refs(where):
        return sorted(ref for h in R.run_rule(store, {"id": "cs", "title": "cs", "severity": "low", "source": "mails", "where": where}, {}) for ref in h["refs"])
    assert refs({"subject|contains_cs": "hTTPs://"}) == [2]
    assert refs({"subject|contains": "hTTPs://"}) == [1, 2]
    assert refs({"subject|startswith_cs": "RE:"}) == [3] and refs({"subject|startswith_cs": "re:"}) == []
    assert refs({"subject|endswith_cs": ["/a", "HELLO"]}) == [1, 2]
    assert refs({"urls.url|contains_cs": "hTTPs://"}) == [2]  # child table
