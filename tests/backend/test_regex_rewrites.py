"""The patterns made linear answer as they did before, and the code that applies them stays fast.

Each rewritten pattern is compared with the pattern it replaced on random text built from the
pieces that pattern reads (thousands of short strings per pattern), in the way the code uses its
answer: the match and its groups, every match, or only whether there is one. A tag pattern searched
up to the next opening of the same tag answers differently only for a tag that holds its own opening
("<form action=a <form action=b>"), which no well-formed page has: there the random text leaves those
out and the whole answer is compared on representative pages instead. All text here is invented.
"""

from __future__ import annotations

import random
import re
import time
from collections.abc import Callable
from typing import Any

import pytest

from services.ai.claude_code import _FENCE_RE, parse_tool_calls
from services.analysis import headers, urls
from services.analysis.attachments import archive, html, office, pdf
from services.analysis.attachments.html import analyze_html
from services.analysis.body import _SCRIPT_TAG_RE, _SCRIPT_TYPE_RE
from services.analysis.lineage import _SERVICE_PROGRAM
from services.parsers import evtx_parser
from services.parsers.collection import REG_VALUE
from services.parsers.m365 import _CULTURE_RE
from services.parsers.mail.common import normalize_name
from services.store.rules import _DUR, _THR
from services.store.sqlfilter import _THRESHOLD_RE

SAMPLES = 1500


def soup(rng: random.Random, pieces: list, longest: int = 24) -> Any:
    """A random string (or bytes) of up to `longest` pieces."""
    picked = [rng.choice(pieces) for _ in range(rng.randint(0, longest))]
    return (b"" if isinstance(pieces[0], bytes) else "").join(picked)


def first(how: str) -> Callable[[re.Pattern, Any], Any]:
    """The match the code reads, as its text and groups (None when there is none)."""

    def answer(p: re.Pattern, s: Any) -> Any:
        m = getattr(p, how)(s)
        return None if m is None else (m.group(0), m.groups())

    return answer


def groups(how: str) -> Callable[[re.Pattern, Any], Any]:
    """The groups of the match the code reads (None when there is none)."""

    def answer(p: re.Pattern, s: Any) -> Any:
        m = getattr(p, how)(s)
        return None if m is None else m.groups()

    return answer


def found(p: re.Pattern, s: Any) -> bool:
    return p.search(s) is not None


def every(p: re.Pattern, s: Any) -> list:
    return p.findall(s)


TAGS = ["<", ">", " ", "a", "=", '"', "'", "/"]

# where the code reads it | the pattern before | the pattern now | what the code reads | pieces | a
# text to leave out (a tag holding its own opening)
EXACT: list[tuple[str, re.Pattern, re.Pattern, Callable[[re.Pattern, Any], Any], list, str | bytes | None]] = [
    (
        "html.py password input",
        re.compile(r"(?i)<input[^>]*type\s*=\s*[\"']?password"),
        html._PASSWORD_INPUT,
        found,
        [*TAGS, "<input", "<INPUT", "type", "password"],
        None,
    ),
    (
        "html.py email input",
        re.compile(r"(?i)<input[^>]*(?:type\s*=\s*[\"']?email|name\s*=\s*[\"']?(?:email|user(?:name)?|login|login_email|identifier))"),
        html._EMAIL_INPUT,
        found,
        [*TAGS, "<input", "type", "name", "email", "user", "username", "login"],
        None,
    ),
    (
        "html.py form action",
        re.compile(r"(?i)<form[^>]*action\s*=\s*[\"']?([^\"'\s>]+)"),
        html._FORM_ACTION,
        every,
        [*TAGS, "<form", "<FORM", "action", "https://login.example.invalid/x"],
        r"(?i)<form[^>]*<form",
    ),
    (
        "html.py meta refresh",
        re.compile(r"(?i)<meta[^>]*http-equiv\s*=\s*[\"']?refresh[^>]*content\s*=\s*[\"']?\s*\d+\s*;\s*url\s*=\s*([^\"'>\s]+)"),
        html._META_REFRESH,
        groups("search"),
        [*TAGS, "<meta", "http-equiv", "refresh", "content", "0", "5", ";", "url", "x.invalid"],
        r"(?i)<meta[^>]*<meta",
    ),
    (
        "html.py script source",
        re.compile(r"(?i)<script[^>]*src\s*=\s*[\"']([^\"']+)"),
        html._SCRIPT_SRC,
        every,
        [*TAGS, "<script", "<scripts", "src", "x.js"],
        r"(?i)<script[^>]*<script",
    ),
    (
        "html.py hidden iframe",
        re.compile(r"(?is)<iframe[^>]*(?:width\s*=\s*[\"']?0|height\s*=\s*[\"']?0|display\s*:\s*none|visibility\s*:\s*hidden)"),
        html._HIDDEN_IFRAME,
        found,
        [*TAGS, "<iframe", "width", "height", "0", "1", "display", ":", "none", "visibility", "hidden"],
        None,
    ),
    (
        "html.py title",
        re.compile(r"(?is)<title[^>]*>(.*?)</title>"),
        re.compile(r"(?is)\A(?>.*?<title(?:(?!<title)[^>])*>)(.*?)</title>"),
        groups("search"),
        [*TAGS, "<title", "<TITLE", "</title>", "</TITLE>", "\n"],
        None,
    ),
    (
        "html.py location redirect",
        re.compile(r"(?i)(?:window\.)?location(?:\.href|\.replace\(|\s*=)\s*[\"'(]?\s*[\"']([^\"']{6,400})"),
        re.compile(r"(?i)(?:window\.)?location(?:\.href|\.replace\(|\s*=)\s*(?:[\"'(]\s*)?[\"']([^\"']{6,400})"),
        first("search"),
        ["location", "window.", ".href", ".replace(", "=", " ", '"', "'", "(", "https://x.invalid/", "a"],
        None,
    ),
    (
        "body.py script tag",
        re.compile(r"(?is)<script\b([^>]*)>"),
        _SCRIPT_TAG_RE,
        every,
        [*TAGS, "<script", "<scripts", "type", "json"],
        r"(?i)<script\b[^>]*<script\b",
    ),
    (
        "body.py script type",
        re.compile(r"""(?is)\btype\s*=\s*["']?\s*([^"'\s>]+)"""),
        _SCRIPT_TYPE_RE,
        first("search"),
        ["type", "=", " ", "\t", '"', "'", "application/ld+json", "text/javascript", ">", "a"],
        None,
    ),
    (
        "magic.py padded file name",
        re.compile(r"\s{5,}\."),
        re.compile(r"(?<!\s)\s{5,}\."),
        found,
        [" ", "\t", ".", "a", "pdf", "exe"],
        None,
    ),
    (
        "office.py DDE field",
        re.compile(rb"(?i)(?:<w:instrText[^>]*>\s*)?DDE(?:AUTO)?[\s\"'\\][^<]{0,200}"),
        office._DDE_FIELD_RE,
        every,
        [b"<w:instrText", b">", b" ", b"DDE", b"AUTO", b'"', b"a", b"<", b"cmd"],
        rb"(?i)<w:instrText[^>]*<w:instrText",
    ),
    (
        "office.py relationship",
        re.compile(rb"(?is)<Relationship\b[^>]*?/?>"),
        office._EXT_REL_RE,
        every,
        [b"<Relationship", b"<Relationships", b">", b"/>", b"/", b" ", b"Target", b"=", b'"', b"a"],
        rb"(?i)<Relationship\b[^>]*<Relationship\b",
    ),
    (
        "office.py RTF autolink",
        re.compile(rb"(?i)\\object[^{}]*\\objautlink"),
        re.compile(rb"(?i)\\object(?:(?!\\object)[^{}])*\\objautlink"),
        found,
        [b"\\object", b"\\OBJECT", b"\\objautlink", b"\\obj", b"{", b"}", b"a", b"\\"],
        None,
    ),
    (
        "office.py CSV formula",
        re.compile(rb"(?m)^\s*[=+\-@].*(?:cmd|powershell|mshta|http|dde)", re.I),
        re.compile(rb"(?m)^[^\S\n]*[=+\-@].*(?:cmd|powershell|mshta|http|dde)", re.I),
        found,
        [b"\n", b"\r\n", b"\r", b" ", b"\t", b"=", b"+", b"-", b"@", b"CMD", b"http", b"a", b","],
        None,
    ),
    (
        "archive.py executable name",
        re.compile(rb"(?i)[A-Z0-9_\-. ]{1,60}\.(exe|lnk|dll|js|vbs|bat|cmd|hta|ps1|scr|msi|wsf|cpl)\b"),
        archive._ASCII_EXE_RE,
        every,
        [b"a", b".", b"exe", b"EXE", b"lnk", b"js", b"ps1", b" ", b"-", b"_", b"\x00", b"b"],
        None,
    ),
    (
        "archive.py executable name in UTF-16",
        re.compile(r"[\w\-. ]{1,60}\.(?:exe|lnk|dll|js|vbs|bat|cmd|hta|ps1|scr|msi|wsf|cpl)", re.I),
        re.compile(r"[\w\-. ]{1,60}\.(?=[bcdehjlmpsvw])(?:exe|lnk|dll|js|vbs|bat|cmd|hta|ps1|scr|msi|wsf|cpl)", re.I),
        every,
        ["a", ".", "exe", "Exe", "dll", "cpl", " ", "-", "é", "!"],
        None,
    ),
    (
        "pdf.py URI",
        re.compile(rb"/URI\s*\(\s*([^)]{1,600})\)|/URI\s*<([0-9A-Fa-f]{2,1200})>"),
        pdf._URI_RE,
        every,
        [b"/URI", b" ", b"\t", b"\n", b"(", b")", b"a", b"<", b"41", b">"],
        None,
    ),
    (
        "headers.py Received from",
        re.compile(r"(?is)\bfrom\s+(?P<from>.+?)(?=\s+\b(?:by|with|id|for|via)\b|;|$)"),
        headers._FROM_RE,
        first("search"),
        ["from", " ", "\t", "\n", "by", "with", "id", "for", "via", ";", "a", "mx.example.invalid", "(", ")"],
        None,
    ),
    (
        "headers.py IP address, first",
        re.compile(r"\[?((?:\d{1,3}\.){3}\d{1,3}|[0-9a-fA-F:]{2,}:[0-9a-fA-F:.]+)\]?"),
        headers._IP_RE,
        first("search"),
        ["1", "12", "255", ".", ":", "::", "a", "f", "[", "]", " ", "g", "("],
        None,
    ),
    (
        "lineage.py service program",
        re.compile(r"(?i)([^\\/\"\s]+\.(?:exe|com|bat|cmd|ps1|dll|sys|scr))(?=$|[\"\s])"),
        _SERVICE_PROGRAM,
        first("search"),
        ["a", "svc", ".", ".exe", ".DLL", ".sys", "\\", "/", '"', " ", "C:", "-k"],
        None,
    ),
    (
        "urls.py Proofpoint v3",
        re.compile(r"/v3/__(.+?)__;"),
        re.compile(r"(?m)^(?>.*?/v3/__)(.+?)__;"),
        groups("search"),
        ["/v3/__", "__;", "_", "a", "https://x.invalid", "\n", "*", ";", "/"],
        None,
    ),
    (
        "urls.py address in a parameter",
        re.compile(r"[?&#](?:email|user|login|e|u|id)=[^&]*@"),
        re.compile(r"[?&#](?:email|user|login|e|u|id)=(?:(?![?#](?:email|user|login|e|u|id)=)[^&])*@"),
        found,
        ["?", "&", "#", "email", "e", "u", "id", "user", "=", "@", "a", "x"],
        None,
    ),
    (
        "urls.py base64 before an address",
        re.compile(r"[A-Za-z0-9+/=]{20,}@"),
        re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/=]{20,}@"),
        found,
        ["AAAA", "a", "0", "+", "/", "=", "@", " ", "-"],
        None,
    ),
    (
        "collection.py reg query value",
        re.compile(r"^\s{2,}(?P<name>.+?)\s{2,}(?P<type>REG_[A-Z_]+)(?:\s{2,}(?P<data>.*))?$"),
        REG_VALUE,
        first("match"),
        ["    ", "  ", " ", "\t", "a", "Run", "x y", "REG_SZ", "REG_DWORD", "REG_", "data", "_"],
        None,
    ),
    (
        "m365.py culture date",
        re.compile(r"^(\d{1,4})([/.-])(\d{1,2})\2(\d{1,4}),?\s+(\d{1,2}):(\d{2})(?::(\d{2})(?:\.(\d{1,7}))?)?\s*([AaPp][Mm])?\s*(Z|[+-]\d{2}:?\d{2})?$"),
        _CULTURE_RE,
        first("match"),
        ["9", "1", "2026", "/", ".", "-", " ", ",", "10", ":", "00", "AM", "pm", "Z", "+02:00", "a"],
        None,
    ),
    (
        "store/rules.py duration",
        re.compile(r"^\s*(\d+(?:\.\d+)?)\s*(ms|s|m|h|d|w)?\s*$", re.I),
        _DUR,
        first("match"),
        ["1", "10", ".", "5", " ", "\t", "ms", "s", "m", "H", "x"],
        None,
    ),
    (
        "store/rules.py threshold",
        re.compile(r"^\s*(>=|<=|==|=|>|<|!=)?\s*(\d+)\s*$"),
        _THR,
        first("match"),
        [">=", "<", "=", "==", "!=", " ", "\t", "1", "23", "x"],
        None,
    ),
    (
        "sqlfilter.py threshold",
        re.compile(r"^\s*(>=|<=|==|=|!=|>|<)?\s*(\d+)\s*$"),
        _THRESHOLD_RE,
        first("match"),
        [">=", "<", "=", "==", "!=", " ", "\t", "1", "23", "x"],
        None,
    ),
]


@pytest.mark.parametrize("where, before, now, answer, pieces, leave_out", EXACT, ids=[e[0] for e in EXACT])
def test_a_rewritten_pattern_answers_as_before_on_random_text(where, before, now, answer, pieces, leave_out):
    rng = random.Random(where)
    skip = re.compile(leave_out) if leave_out else None
    compared = 0
    for _ in range(SAMPLES):
        s = soup(rng, pieces, 48 if "base64" in where else 24)
        if skip is not None and skip.search(s):
            continue
        assert answer(now, s) == answer(before, s), (where, s)
        compared += 1
    assert compared > SAMPLES // 3


def test_a_tag_that_holds_its_own_opening_is_still_found():
    # the only text the tag patterns answer differently: found from the inner opening
    assert html._PASSWORD_INPUT.search('<input name="a" <input type="password">')
    assert html._FORM_ACTION.findall("<form action=a <form action=b>") == ["a", "b"]


def test_a_fenced_reply_gives_the_same_text():
    before = re.compile(r"^\s*```(?:json)?\s*(.*?)\s*```\s*$", re.S)
    rng = random.Random("fence")
    for _ in range(SAMPLES):
        s = soup(rng, ["```", "json", " ", "\n", "a", "{}", "`"]).strip()
        old, new = before.match(s), _FENCE_RE.match(s)
        assert (old is None) == (new is None), s
        if old and new:
            assert new.group(1).strip() == old.group(1).strip(), s
    assert parse_tool_calls('```json\n{"tool_calls": [{"name": "search", "arguments": {}}]}\n```') == [{"name": "search", "arguments": {}}]


def test_every_address_of_a_received_header_is_read_as_before():
    before = re.compile(r"\[?((?:\d{1,3}\.){3}\d{1,3}|[0-9a-fA-F:]{2,}:[0-9a-fA-F:.]+)\]?")
    for value in [
        "from mx.example.invalid (mx.example.invalid [192.0.2.10]) by relay.example.invalid (Postfix) with ESMTPS id 4F2; Tue, 1 Sep 2026",
        "from [IPv6:2001:db8::25] (helo) by mail.example.invalid with SMTP",
        "from unknown (HELO x) (198.51.100.7) by mx with ESMTP; 1 Sep 2026",
        "from host ([2001:db8:0:1::5]:52310) by mx id abc",
        "(::ffff:203.0.113.9) 2001:db8::1 192.0.2.1:25 fe80::1%eth0",
    ]:
        assert headers._IP_RE.findall(value) == before.findall(value), value
        assert headers.parse_received(value) is not None


@pytest.mark.parametrize("sub", [r"<[^>]*>", r"<[^>]+>"])
def test_removing_tags_up_to_the_last_closing_bracket_changes_nothing(sub):
    # what normalize_name and extract_urls now do: the search stops after the last ">"
    rng = random.Random(sub)
    for _ in range(SAMPLES):
        s = soup(rng, ["<", ">", "a", " ", "<b>", "@"])
        cut = s.rfind(">") + 1
        assert re.sub(sub, " ", s[:cut]) + s[cut:] == re.sub(sub, " ", s), s
    assert normalize_name("Lefevre Marie <marie.lefevre@interne.example>") == "lefevre marie"
    assert normalize_name("Support <<noreply>") == "support"


def test_scripts_are_read_as_before_when_the_search_stops_at_the_last_closing_tag():
    before = re.compile(r"(?is)<script\b[^>]*>(.*?)</script>")
    rng = random.Random("scripts")
    for _ in range(SAMPLES):
        s = soup(rng, ["<script", "<scripts", "<SCRIPT", ">", "</script>", "</SCRIPT>", "a", " ", "<", "src=x"])
        last = html._SCRIPT_END.match(s)
        assert html._SCRIPT_RE.findall(s, 0, last.end() if last else 0) == before.findall(s), s


def test_a_repaired_event_record_is_as_before():
    before = re.compile(r"(<Data(?:\s[^>]*)?(?<!/)>)(.*?)(</Data>)", re.S)

    def repaired_before(text: str) -> str:
        text = evtx_parser._XML_AMP.sub("&amp;", evtx_parser._XML_INVALID.sub("\ufffd", text))
        return before.sub(lambda m: m.group(1) + m.group(2).replace("<", "&lt;").replace(">", "&gt;") + m.group(3), text)

    rng = random.Random("data")
    for _ in range(SAMPLES):
        s = soup(rng, ["<Data>", "<Data Name='a'>", "</Data>", "<Data/>", "<Data ", "a", "<", ">", "&", "/", "\n"])
        assert evtx_parser._xml_repaired(s) == repaired_before(s), s


def test_an_event_export_head_is_recognised_as_before():
    for head in [
        "<Events><Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>",
        "\ufeff<?xml version='1.0' encoding='utf-8'?>\n<Events>\n",
        "<?xml version='1.0'?><!-- exported by an invented tool --><!-- second --><Event>",
        "<!--\nmulti\nline - comment\n-->\n  <Events>",
        "<!-- a --->\n<Event>",
    ]:
        assert evtx_parser.looks_like_event_xml(head.encode("utf-8"))
    for head in ["<Eventsx>", "<html><Events>", "<!-- unclosed <Events>", "text", ""]:
        assert not evtx_parser.looks_like_event_xml(head.encode("utf-8"))


REPRESENTATIVE_PAGES = [
    # an invented credential page of the kind phishing kits ship
    """<!DOCTYPE html><html><head><title>Sign in to your account</title>
    <meta http-equiv="refresh" content="30; url=https://login.example.invalid/next">
    <script src="https://cdn.example.invalid/jquery.min.js"></script>
    <script type="text/javascript">var e = atob("aGVsbG8="); document.write('<script src="x.js"></scr' + 'ipt>');</script>
    </head><body><form method="post" action="https://collect.example.invalid/post.php">
    <input type="email" name="loginfmt" value="marie.lefevre@interne.example">
    <input type="password" name="passwd"><input type=submit value="Next"></form>
    <iframe src="https://x.invalid" width="0" height="0" style="display:none"></iframe></body></html>""",
    # an invented newsletter
    """<html><head><title>News</title><script type="application/ld+json">{"@type": "Organization"}</script>
    <META HTTP-EQUIV='Refresh' CONTENT='0;URL=https://news.example.invalid/'></head>
    <body><FORM ACTION=/subscribe><INPUT TYPE=text NAME=username></FORM>
    <SCRIPT SRC='https://news.example.invalid/a.js'></SCRIPT></body></html>""",
    # an invented OOXML relationships part, as text
    """<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
    <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/oleObject"
     Target="https://x.example.invalid/a.doc" TargetMode="External"/><Relationship Id="rId2" Target="media/a.png"/></Relationships>""",
]


TAG_PATTERNS = [
    ("form action", r"(?i)<form[^>]*action\s*=\s*[\"']?([^\"'\s>]+)", html._FORM_ACTION.pattern),
    (
        "meta refresh",
        r"(?i)<meta[^>]*http-equiv\s*=\s*[\"']?refresh[^>]*content\s*=\s*[\"']?\s*\d+\s*;\s*url\s*=\s*([^\"'>\s]+)",
        html._META_REFRESH.pattern,
    ),
    ("script source", r"(?i)<script[^>]*src\s*=\s*[\"']([^\"']+)", html._SCRIPT_SRC.pattern),
    ("script tag", r"(?is)<script\b([^>]*)>", _SCRIPT_TAG_RE.pattern),
    ("relationship", r"(?is)<Relationship\b[^>]*?/?>", office._EXT_REL_RE.pattern.decode()),
]


@pytest.mark.parametrize("where, before, now", TAG_PATTERNS, ids=[t[0] for t in TAG_PATTERNS])
def test_a_tag_pattern_reads_a_representative_page_as_before(where, before, now):
    for page in REPRESENTATIVE_PAGES:
        assert re.findall(now, page) == re.findall(before, page), where


def test_a_representative_page_is_described_as_before():
    # the values the code gave before the patterns changed, on the same invented pages
    first, second = (analyze_html(page.encode(), "html") for page in REPRESENTATIVE_PAGES[:2])
    assert first["title"] == "Sign in to your account"
    assert first["forms"] == ["https://collect.example.invalid/post.php"]
    assert first["redirect"] == "https://login.example.invalid/next"
    assert first["externalScripts"] == ["https://cdn.example.invalid/jquery.min.js", "x.js"]
    assert first["scripts"] == 4
    assert first["apis"] == ["atob", "document_write"]
    assert first["flags"] == [
        "html_brand_lure",
        "html_credential_harvest",
        "html_hidden_iframe",
        "html_meta_refresh",
        "html_password_form",
        "html_prefilled_email",
        "html_redirect_only",
        "html_script",
    ]
    assert (second["title"], second["forms"], second["redirect"]) == ("News", ["/subscribe"], "https://news.example.invalid/")
    assert (second["externalScripts"], second["scripts"]) == (["https://news.example.invalid/a.js"], 3)
    assert second["flags"] == ["html_email_form", "html_meta_refresh", "html_redirect_only", "html_script"]


@pytest.mark.parametrize(
    "what, run",
    [
        ("a display name of 200,000 '<'", lambda: normalize_name("<" * 200_000)),
        ("a body of 200,000 '<'", lambda: urls.extract_urls(None, "<" * 200_000)),
        ("an HTML page of unclosed script tags", lambda: analyze_html(b"<script>" * 25_000, "html")),
        ("an HTML page of unclosed title tags", lambda: analyze_html(b"<title>" * 25_000, "html")),
        ("an HTML page of unclosed input tags", lambda: analyze_html(b"<input type= " * 15_000, "html")),
        ("an event record of unclosed Data tags", lambda: evtx_parser._xml_repaired("<Data>" * 30_000)),
        ("an event export head of comments", lambda: evtx_parser.looks_like_event_xml(b"<!---->" * 40 + b"<Eventx")),
        ("a reg query line of spaces", lambda: REG_VALUE.match(" " * 3_000 + "x")),
        ("a reply of blanks", lambda: parse_tool_calls("```" + " " * 3_000 + "x")),
        ("a URL of Proofpoint markers", lambda: urls.unwrap_rewritten("https://urldefense.com" + "/v3/__" * 20_000)),
        ("a Received header of hexadecimal digits", lambda: headers.parse_received("from " + "a" * 100_000 + " by mx")),
    ],
)
def test_hostile_text_is_read_in_under_a_second(what, run):
    # each of these ran for more than eight seconds on the code it replaces
    t0 = time.process_time()
    run()
    assert time.process_time() - t0 < 1.0, what
