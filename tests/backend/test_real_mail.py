"""Mail written by real mail clients, read as an upload reads it.

The committed files and where they come from are listed in tests/fixtures/real/mail/README.md.
The others name real people, so they are not committed and their names are not written here:
the tests marked heavy download them, and compare REMN's reading with one made independently
of it, by Python's own mail parser or from the message's property streams read directly. The
expected values of the committed files are those Apache Tika's own tests give, or what the
files' own headers say; none is REMN's output.
"""

from __future__ import annotations

import email
import hashlib
import mailbox
import shutil
import struct
from datetime import datetime
from email import policy
from email.utils import parseaddr, parsedate_to_datetime

import olefile
import pytest
from real_samples import FIXTURES, download

from services.ingest.pipeline import MailSource
from services.parsers.mail import pst
from services.parsers.mail.common import ParseContext

MAIL = FIXTURES / "mail"
TIKA = "https://raw.githubusercontent.com/apache/tika/8cbd68506d8827e9fd5ae958f4608f81dcc10c75/tika-parsers/tika-parsers-standard"
MICROSOFT = f"{TIKA}/tika-parsers-standard-modules/tika-parser-microsoft-module/src/test/resources/test-documents"
MAILMODULE = f"{TIKA}/tika-parsers-standard-modules/tika-parser-mail-module/src/test/resources/test-documents"
INTEGRATION = f"{TIKA}/tika-parsers-standard-integration-tests/src/test/resources/test-documents"


def ms(text: str) -> int:
    return int(datetime.fromisoformat(text).timestamp() * 1000)


def read(tmp_path, path, **context):
    source = MailSource(path.name, str(path), None, ParseContext(**({"analyze_attachments": False} | context)), str(tmp_path))
    return list(source)


def stream(path, name: str) -> bytes:
    with olefile.OleFileIO(str(path)) as ole:
        return ole.openstream(name).read()


def test_an_outlook_message_in_8_bit_strings_gives_its_sender_subject_and_date(tmp_path):
    rows = read(tmp_path, MAIL / "test-outlook.msg")
    assert len(rows) == 1
    mail = rows[0]
    assert mail["subject"] == "Microsoft Outlook Express 6"
    assert mail["fromName"] == "L'Équipe Microsoft Outlook Express"
    assert mail["fromAddr"] == "msoe@microsoft.com"
    # Tika: "Stored as Thu, 5 Apr 2007 09:26:06 -0700"
    assert mail["date"] == ms("2007-04-05T16:26:06+00:00")


def test_an_outlook_message_whose_strings_only_the_internet_code_page_names_is_read_in_that_code_page(tmp_path):
    """The committed Outlook message, changed here and nowhere else: its internet code page is set
    to Big5 (950), and the start of its body is written in Big5. That is how Tika's Chinese sample,
    which a heavy test below reads, declares its strings; the change keeps every stream's size."""
    path = tmp_path / "big5.msg"
    shutil.copy(MAIL / "test-outlook.msg", path)
    with olefile.OleFileIO(str(path), write_mode=True) as ole:
        props = ole.openstream("__properties_version1.0").read()
        at = props.find(struct.pack("<I", 0x3FDE0003))
        assert at > 0
        ole.write_stream("__properties_version1.0", props[: at + 8] + struct.pack("<I", 950) + props[at + 12 :])
        body = ole.openstream("__substg1.0_1000001E").read()
        # the body's Latin-1 letters are not Big5, so they become question marks first
        body = bytes(b if b < 0x80 else 0x3F for b in body)
        ole.write_stream("__substg1.0_1000001E", body.replace(b"La r?ponse", "測試郵件".encode("cp950") + b"  ", 1))
    rows = read(tmp_path, path)
    assert "測試郵件" in rows[0]["bodyText"]


def test_a_lotus_notes_message_gives_its_addresses_and_date(tmp_path):
    rows = read(tmp_path, MAIL / "testLotusEml.eml")
    assert len(rows) == 1
    assert rows[0]["fromAddr"] == "xxx.xxx@xxxx.de"
    assert [r["addr"] for r in rows[0]["to"]] == ["xxxx@alfresco.com"]
    # Date: Thu, 4 Oct 2012 13:02:39 +0200
    assert rows[0]["date"] == ms("2012-10-04T11:02:39+00:00")


def test_a_groupwise_message_gives_its_sender_subject_date_and_text_attachment(tmp_path):
    rows = read(tmp_path, MAIL / "testGroupWiseEml.eml", analyze_attachments=True)
    assert len(rows) == 1
    assert rows[0]["subject"] == "test333"
    assert rows[0]["fromName"] == "Novell GroupWise"
    # Date: Thu, 27 Jun 2013 13:29:57 +0200
    assert rows[0]["date"] == ms("2013-06-27T11:29:57+00:00")
    # Tika: the text file is attached as "Neues Textdokument.txt", holding a line of 22 letters s
    text = next(a for a in rows[0]["attachments"] if a["name"] == "Neues Textdokument.txt")
    assert text["sha256"] == hashlib.sha256(b"s" * 22).hexdigest()


def test_an_mbox_of_one_outlook_message_gives_one_message(tmp_path):
    rows = read(tmp_path, MAIL / "testMBOX_complex.mbox")
    # Tika: one message. Its text part says "body 1" and its HTML part "body 2"; Tika shows the
    # HTML part, and REMN keeps both
    assert len(rows) == 1
    assert "body 1" in rows[0]["bodyText"] and "body 2" not in rows[0]["bodyText"]
    assert "body 2" in rows[0]["bodyHtml"]
    assert rows[0]["fromAddr"] == "hey@example.com"
    # Date: Mon, 20 Jul 2015 00:01:07 -0700
    assert rows[0]["date"] == ms("2015-07-20T07:01:07+00:00")


def test_an_mbox_of_two_messages_with_no_headers_gives_two_messages_and_no_invented_date(tmp_path):
    rows = read(tmp_path, MAIL / "simple.mbox")
    assert [r["bodyText"].strip() for r in rows] == ["Test content 1", "Test content 2"]
    assert [r.get("date") for r in rows] == [None, None]


def independent(message: email.message.Message) -> tuple[str, str, int]:
    """The sender's address, the subject and the date, as Python's mail parser reads them."""
    return parseaddr(str(message["From"]))[1].lower(), str(message["Subject"]), int(parsedate_to_datetime(str(message["Date"])).timestamp() * 1000)


@pytest.mark.heavy
def test_tika_s_chinese_outlook_message_is_read_in_its_code_page(tmp_path):
    path = download(f"{MICROSOFT}/testMSG_chinese.msg", "b84c12748155dc57b41de02c6d43aa47e82b879020df070290633e9fd5ce7fdd")
    rows = read(tmp_path, path)
    assert len(rows) == 1
    # the subject and body streams, decoded in the code page the message declares (950)
    assert rows[0]["subject"] == stream(path, "__substg1.0_0037001E").decode("cp950").rstrip("\x00")
    first_line = stream(path, "__substg1.0_1000001E").decode("cp950").strip().splitlines()[0].strip()
    assert any("一" <= c <= "鿿" for c in first_line)
    assert first_line in rows[0]["bodyText"]
    # the MTS identifier Tika reads, l=FTM02-110329085248Z-89735, holds the submit time
    assert rows[0]["date"] == ms("2011-03-29T08:52:48+00:00")


@pytest.mark.heavy
def test_tika_s_outlook_message_with_transport_headers_gives_their_sender_subject_and_date(tmp_path):
    path = download(f"{MICROSOFT}/testMSG.msg", "972901d1a0049ed54dc993ba57f6612db4c370acea818601b2133423885070cf")
    rows = read(tmp_path, path)
    assert len(rows) == 1
    # the stream opens with a line of Outlook's own before the headers themselves
    text = stream(path, "__substg1.0_007D001E").rstrip(b"\x00").split(b"\r\n", 1)[1]
    headers = email.message_from_bytes(text, policy=policy.compat32)
    assert (rows[0]["fromAddr"], rows[0]["subject"], rows[0]["date"]) == independent(headers)


@pytest.mark.heavy
def test_a_thunderbird_message_gives_its_sender_subject_and_date(tmp_path):
    path = download(f"{INTEGRATION}/testThunderbirdEml.eml", "4a8c263fefb76311314f961d3733b9f8859a717626e089f47e6d682bbd12bac5")
    rows = read(tmp_path, path)
    assert len(rows) == 1
    assert (rows[0]["fromAddr"], rows[0]["subject"], rows[0]["date"]) == independent(email.message_from_bytes(path.read_bytes(), policy=policy.compat32))


@pytest.mark.heavy
def test_a_mailing_list_mbox_gives_every_message_with_its_sender_subject_and_date(tmp_path):
    path = download(f"{MAILMODULE}/complex.mbox", "c07ad5e7af40a6dcc2b8f96c65cd55455748cc19f24ed7e2fd32ac6340f3b2cf")
    rows = read(tmp_path, path)
    expected = [independent(m) for m in mailbox.mbox(str(path), create=False)]
    # Tika counts three messages
    assert len(expected) == 3
    assert [(r["fromAddr"], r["subject"], r["date"]) for r in rows] == expected


@pytest.mark.heavy
@pytest.mark.skipif(not pst.available(), reason="needs the optional PST reader (libpff-python)")
def test_tika_s_outlook_data_file_gives_its_messages(tmp_path):
    path = download(f"{MICROSOFT}/testPST.pst", "f2a6b1d2cad00f574e3d1c1211c4b1c854d6526caea77213adc3da92b7813ae3")
    rows = read(tmp_path, path)
    # Tika (OutlookPSTParserTest) names the first message's subject, its submit and delivery
    # times, and the sixth message's sender, a company's address
    first = [r for r in rows if r["subject"] == "Re: Feature Generators"]
    assert len(first) == 1
    assert ms("2014-02-26T07:50:04+00:00") <= first[0]["date"] <= ms("2014-02-26T07:51:02+00:00")
    assert "couchbase@couchbase.com" in {r["fromAddr"] for r in rows}
