"""The identity resolver: which forms name one account, how surely, and which never join."""

from __future__ import annotations

import uuid

import pytest

from services.analysis.identity import MEDIUM, STRONG, WEAK, Form, account_forms, event_record, header_forms, kind_of, records_for_store, resolve
from services.store.casestore import StoreRegistry
from services.store.writers import EventWriter, MailWriter

SETTINGS = {"internal_domains": ["northstar.example"], "service_accounts": ["svc.backup"]}
ALICE_SID = "S-1-5-21-111-222-333-1101"


def _logon(n, user, domain, sid=None, host="WS-001.northstar.example", **extra):
    return {"id": n, "eventId": 4624, "computer": host, "targetUser": user, "targetDomain": domain, "targetSid": sid, "logonType": 3, **extra}


def _signin(n, upn, object_id, display=None):
    data = {"userId": object_id}
    if display:
        data["userDisplayName"] = display
    return {"id": n, "operation": "SignIn", "recordKey": f"entra:{n}", "user": upn, "upn": upn, "subjectUser": upn, "targetUser": upn, "data": data}


def _ident(r, kind, value):
    iid = r.of_form(Form(kind, value))
    assert iid, (kind, value)
    return r.by_id[iid]


def test_each_form_of_an_account_joins_with_its_basis_and_confidence():
    events = [
        _logon(1, "alice.martin", "NORTHSTAR", ALICE_SID),
        _signin(2, "alice.martin@northstar.example", "1b94c5cd-f948-4290-8596-48e0511961d5"),
        # a group change names the member by distinguished name and SID
        {
            "id": 3,
            "eventId": 4732,
            "subjectUser": "lab.admin",
            "subjectDomain": "NORTHSTAR",
            "targetUser": "Administrators",
            "targetDomain": "Builtin",
            "targetSid": "S-1-5-32-544",
            "memberName": "CN=alice.martin,OU=Staff,DC=northstar,DC=example",
            "memberSid": ALICE_SID,
        },
        # NTLM validation names the account without its domain
        {"id": 4, "eventId": 4776, "targetUser": "alice.martin", "workstation": "WS-001"},
    ]
    r = resolve(events, (), SETTINGS)
    alice = _ident(r, "addr", "alice.martin@northstar.example")
    assert alice["kind"] == "person" and alice["org"] == "northstar.example"
    forms = {(f["kind"], f["value"]): f["confidence"] for f in alice["forms"]}
    assert forms == {
        ("addr", "alice.martin@northstar.example"): STRONG,
        # the object id is stated with the address in one sign-in
        ("object", "1b94c5cd-f948-4290-8596-48e0511961d5"): STRONG,
        # the NetBIOS form joins by the organisation rule, the SID and DN through it
        ("netbios", "northstar\\alice.martin"): MEDIUM,
        ("sid", ALICE_SID.lower()): MEDIUM,
        ("dn", "cn=alice.martin,ou=staff,dc=northstar,dc=example"): MEDIUM,
        # the bare name is the only account of that name in the case
        ("name", "alice.martin"): MEDIUM,
    }
    bases = {j["basis"] for j in alice["joins"]}
    assert "stated together in one record" in bases
    assert "the same account in its organisation (the NetBIOS name of its domain)" in bases
    assert "the only account of that name in the case" in bases
    # the group is not an identity; the member is, from its DN and SID
    assert r.of_form(Form("netbios", "builtin\\administrators")) is None
    assert [(iid, role, c) for iid, role, c in r.of_event(events[2]) if role == "member"] == [(alice["id"], "member", MEDIUM)]


def test_an_account_of_another_organisation_never_joins_and_is_named_a_namesake():
    events = [
        _logon(1, "alice.martin", "NORTHSTAR", ALICE_SID),
        _signin(2, "alice.martin@northstar.example", "1b94c5cd-f948-4290-8596-48e0511961d5"),
        # the lab's planted control: the same name in another tenant, its NetBIOS name shown beside its UPN
        {
            "id": 3,
            "eventId": 4624,
            "computer": "OTHER-WS-001.other-tenant.example",
            "subjectUser": "alice.martin@other-tenant.example",
            "subjectDomain": "OTHER",
            "targetUser": "alice.martin",
            "targetDomain": "OTHER",
        },
    ]
    r = resolve(events, (), SETTINGS)
    home, other = _ident(r, "addr", "alice.martin@northstar.example"), _ident(r, "addr", "alice.martin@other-tenant.example")
    assert home["id"] != other["id"] and other["org"] == "other-tenant.example"
    # OTHER\alice.martin is the other tenant's account, shown beside its UPN
    assert r.of_form(Form("netbios", "other\\alice.martin")) == other["id"]
    assert [n["id"] for n in home["namesakes"]] == [other["id"]] and "kept apart" in home["namesakes"][0]["basis"]
    assert not home["possibly"] and not other["possibly"]


def test_a_display_name_only_says_possibly_and_a_mail_header_is_the_senders_word():
    events = [
        _signin(1, "alice.martin@northstar.example", "1b94c5cd-f948-4290-8596-48e0511961d5", display="Alice Martin (Finance)"),
        _logon(2, "a.martin", "NORTHSTAR"),
    ]
    mails = [{"id": 7, "fromAddr": "billing@northstar.example", "fromName": "Alice Martin", "to": [{"addr": "benoit.durand@northstar.example"}]}]
    r = resolve(events, mails, SETTINGS)
    alice, sender = _ident(r, "addr", "alice.martin@northstar.example"), _ident(r, "addr", "billing@northstar.example")
    assert alice["id"] != sender["id"]
    # the directory's display name is kept as a weak form of the account; one equal to the account name adds nothing
    assert {"kind": "display", "value": "alice martin (finance)", "seen": 1, "ref": None, "confidence": WEAK} in alice["forms"]
    header = next(p for p in sender["possibly"] if p["id"] == alice["id"])
    assert "which the sender chooses" in header["basis"] and header["ref"] == "mail:7"
    # a.martin is another account: nothing but a guess would join it
    assert r.of_form(Form("netbios", "northstar\\a.martin")) not in (alice["id"], sender["id"])


def test_a_bare_name_two_accounts_share_joins_neither():
    events = [
        _logon(1, "admin", "WS-001", "S-1-5-21-9-9-9-1001"),
        _logon(2, "admin", "WS-002", "S-1-5-21-8-8-8-1001", host="WS-002"),
        {"id": 3, "eventId": 4776, "targetUser": "admin", "workstation": "WS-003"},
    ]
    r = resolve(events, (), {})
    bare = _ident(r, "name", "admin")
    assert {p["label"] for p in bare["possibly"]} == {"ws-001\\admin", "ws-002\\admin"}
    # the record names the bare account for sure, and each of the two only possibly
    named = {r.by_id[iid]["label"]: c for iid, _, c in r.of_record(event_record(events[2]))}
    assert named == {"admin": STRONG, "ws-001\\admin": WEAK, "ws-002\\admin": WEAK}


def test_machine_builtin_and_service_accounts_are_their_own_kinds():
    assert kind_of(Form("netbios", "northstar\\ws-001$")) == "machine"
    assert kind_of(Form("netbios", "nt authority\\system")) == "builtin"
    assert kind_of(Form("name", "dwm-3")) == "builtin"
    assert kind_of(Form("sid", "s-1-5-32-544")) == "builtin"
    assert kind_of(Form("addr", "krbtgt@northstar.example")) == "builtin"
    # the built-in Administrator (RID 500) is an account people log on with
    assert kind_of(Form("sid", "s-1-5-21-1-2-3-500")) is None
    assert kind_of(Form("netbios", "ws-001\\administrator")) == "person"
    assert kind_of(Form("name", "svc.backup"), {"svc.backup"}) == "service"
    assert kind_of(Form("name", "healthmailbox0ab31b3")) == "service"
    events = [
        _logon(1, "WS-001$", "NORTHSTAR", "S-1-5-21-111-222-333-1500"),
        # a user named like the machine, without the $: the organisation rule does not join them
        _logon(2, "ws-001", "NORTHSTAR", "S-1-5-21-111-222-333-1600"),
        {"id": 3, "eventId": 4688, "subjectUser": "SYSTEM", "subjectDomain": "NT AUTHORITY", "subjectSid": "S-1-5-18"},
    ]
    r = resolve(events, (), SETTINGS)
    assert _ident(r, "netbios", "northstar\\ws-001$")["kind"] == "machine"
    assert _ident(r, "netbios", "northstar\\ws-001")["kind"] == "person"
    assert r.of_form(Form("netbios", "northstar\\ws-001$")) != r.of_form(Form("netbios", "northstar\\ws-001"))
    assert _ident(r, "netbios", "nt authority\\system")["kind"] == "builtin"


def test_a_renamed_machine_account_stays_one_identity_and_says_so():
    sid = "S-1-5-21-4230534742-2542757381-3142984815-1296"
    events = [
        {"id": 1, "eventId": 4741, "subjectUser": "hack1", "subjectDomain": "OFFSEC", "targetUser": "compnay-88$", "targetDomain": "OFFSEC", "targetSid": sid},
        {
            "id": 2,
            "eventId": 4781,
            "subjectUser": "hack1",
            "subjectDomain": "OFFSEC",
            "targetDomain": "OFFSEC",
            "targetSid": sid,
            "data": {"OldTargetUserName": "compnay-88$", "NewTargetUserName": "rootdc1", "TargetDomainName": "OFFSEC", "TargetSid": sid},
        },
        {"id": 3, "eventId": 4768, "targetUser": "rootdc1", "targetDomain": "OFFSEC", "targetSid": sid},
    ]
    r = resolve(events, (), {})
    acct = _ident(r, "sid", sid.lower())
    assert acct["kind"] == "machine" and acct["label"] == "offsec\\compnay-88$"
    assert r.of_form(Form("netbios", "offsec\\rootdc1")) == acct["id"]
    assert any(j["basis"] == "renamed from offsec\\compnay-88$ to offsec\\rootdc1" for j in acct["joins"])
    assert any("sAMAccountName spoofing" in n for n in acct["notes"])


def test_the_sid_an_event_was_logged_under_names_its_account():
    """A script block (4104) names its user only in its System header (UserID); a logon joins that SID to the account."""
    host = "WS-001.northstar.example"
    events = [
        _logon(1, "alice.martin", "NORTHSTAR", ALICE_SID, host=host),
        {"id": 2, "eventId": 4104, "computer": host, "userSid": ALICE_SID, "scriptBlockText": "IEX (New-Object Net.WebClient)"},
        # Sysmon logs as SYSTEM: its header names no one, its User field does
        {"id": 3, "eventId": 1, "computer": host, "userSid": "S-1-5-18", "user": "NORTHSTAR\\alice.martin"},
        # nor does a service's own SID
        {"id": 4, "eventId": 2004, "computer": host, "userSid": "S-1-5-80-3088073201-1464728630-1879813800-1107566885-823218052"},
    ]
    r = resolve(events, (), SETTINGS)
    alice = _ident(r, "netbios", "northstar\\alice.martin")
    assert [(iid, role) for iid, role, _ in r.of_event(events[1])] == [(alice["id"], "user")]
    assert [iid for iid, _, _ in r.of_event(events[2])] == [alice["id"]]
    assert r.of_event(events[3]) == []
    # the header does not say which of a record's accounts it is: it is joined to none of them
    rec = event_record({"eventId": 4104, "userSid": ALICE_SID, "subjectUser": "bob", "subjectDomain": "NORTHSTAR"})
    assert rec.groups == [[Form("netbios", "northstar\\bob")], [Form("sid", ALICE_SID.lower())]]
    assert header_forms("S-1-5-21-111-222-333-500") == [Form("sid", "s-1-5-21-111-222-333-500")]


@pytest.mark.parametrize(
    "sid",
    [
        "S-1-5-80-3088073201-1464728630-1879813800-1107566885-823218052",  # a service's (the firewall's)
        "S-1-5-82-3006700770-424185619-1745488364-794895919-4004696415",  # an IIS application pool's
        "S-1-5-83-1-1234567890-1234567890-1234567890-1234567890",  # a virtual machine's
        "S-1-5-90-0-1",  # Window Manager's
        "S-1-5-96-0-1",  # the font driver host's
        "S-1-5-32-544",  # BUILTIN\Administrators
        "S-1-5-21-111-222-333-512",  # the domain's admins
    ],
)
def test_a_sid_written_where_a_name_goes_is_a_sid_of_no_person(sid):
    """A firewall rule's ModifyingUser is a SID: it is read as one, and a service's SID is no one a story is about."""
    assert account_forms(sid) == [Form("sid", sid.lower())]
    assert account_forms(sid, None, sid) == [Form("sid", sid.lower())]
    assert kind_of(Form("sid", sid.lower())) == "builtin" and header_forms(sid) == []
    r = resolve([{"id": 1, "eventId": 2004, "computer": "WS-001", "subjectUser": sid}], (), SETTINGS)
    ident = _ident(r, "sid", sid.lower())
    assert ident["kind"] == "builtin" and [f["kind"] for f in ident["forms"]] == ["sid"]
    assert r.of_form(Form("name", sid.lower())) is None


def test_a_netbios_name_joins_the_one_domain_it_starts_never_a_lookalike():
    """With no internal domain set, CONTOSO is the first label of contoso.com and of contoso.co, an attacker's lookalike."""
    events = [_logon(1, "alice", "CONTOSO", host="WS-001")]
    lookalike = {"id": 1, "fromAddr": "alice@contoso.co", "to": [{"addr": "bob@contoso.com"}]}
    real = {"id": 2, "fromAddr": "bob@contoso.com", "to": [{"addr": "alice@contoso.com"}]}
    # the lookalike alone beside the organisation's own mail, then both addresses
    for mails, maybe in (([lookalike], {"alice@contoso.co"}), ([lookalike, real], {"alice@contoso.co", "alice@contoso.com"})):
        r = resolve(events, mails, {})
        alice = _ident(r, "netbios", "contoso\\alice")
        assert [f["value"] for f in alice["forms"]] == ["contoso\\alice"], mails
        assert {p["label"] for p in alice["possibly"]} == maybe
        assert all("the case does not say which one it names" in p["basis"] for p in alice["possibly"])
    # the record names contoso\alice, and each address only possibly
    assert sorted(c for _, _, c in r.of_event(events[0])) == [STRONG, WEAK, WEAK]
    # one domain of the case starts with CONTOSO: that is its domain
    r = resolve(events, [real], {})
    assert _ident(r, "netbios", "contoso\\alice")["label"] == "alice@contoso.com"
    # the internal domain says which: the lookalike is a namesake, kept apart
    r = resolve(events, [lookalike, real], {"internal_domains": ["contoso.com"]})
    alice = _ident(r, "netbios", "contoso\\alice")
    assert alice["label"] == "alice@contoso.com" and not alice["possibly"]
    assert [n["label"] for n in alice["namesakes"]] == ["alice@contoso.co"] and "kept apart" in alice["namesakes"][0]["basis"]


def test_a_bare_name_never_joins_another_organisations_account():
    events = [
        # a guess from outside names the bare account on a Northstar host
        {"id": 1, "eventId": 4625, "computer": "WS-001.northstar.example", "targetUser": "alice.martin", "ipAddress": "203.0.113.9", "logonType": 3},
        _signin(2, "alice.martin@other-tenant.example", "7c1b2a90-0000-4000-8000-000000000002"),
    ]
    r = resolve(events, (), SETTINGS)
    bare, other = _ident(r, "name", "alice.martin"), _ident(r, "addr", "alice.martin@other-tenant.example")
    assert bare["id"] != other["id"]
    assert [p["id"] for p in bare["possibly"]] == [other["id"]] and "neither internal nor the domain of a host" in bare["possibly"][0]["basis"]
    assert {r.by_id[i]["label"]: c for i, _, c in r.of_event(events[0])} == {"alice.martin": STRONG, "alice.martin@other-tenant.example": WEAK}
    # seen on a host of that organisation, the bare name is its account
    events[0]["computer"] = "OTHER-WS-001.other-tenant.example"
    r = resolve(events, (), SETTINGS)
    assert r.of_form(Form("name", "alice.martin")) == r.of_form(Form("addr", "alice.martin@other-tenant.example"))


def test_one_name_under_two_sids_of_its_domain_is_noted():
    """SIDs are never reused: bob deleted and created again is a new account under the old name."""
    events = [
        _logon(1, "bob", "NORTHSTAR", "S-1-5-21-111-222-333-1105"),
        _logon(2, "bob", "NORTHSTAR", "S-1-5-21-111-222-333-2231"),
        # an account migrated from another domain keeps its old SID beside its new one: no note
        _logon(3, "carol", "NORTHSTAR", "S-1-5-21-111-222-333-1301"),
        _logon(4, "carol", "NORTHSTAR", "S-1-5-21-777-888-999-1301"),
    ]
    r = resolve(events, (), SETTINGS)
    [note] = _ident(r, "netbios", "northstar\\bob")["notes"]
    assert note.startswith("2 SIDs of one domain under one name (s-1-5-21-111-222-333-1105, s-1-5-21-111-222-333-2231)") and "deleted and created again" in note
    assert not _ident(r, "netbios", "northstar\\carol")["notes"]


def test_the_server_store_gives_the_same_identities_as_the_rows(tmp_path):
    reg = StoreRegistry()
    reg.configure(tmp_path / "cases")
    store = reg.get(str(uuid.uuid4()))
    try:
        events = [
            _logon(None, "alice.martin", "NORTHSTAR", ALICE_SID, ts=1_000),
            _logon(None, "alice.martin", "NORTHSTAR", ALICE_SID, ts=2_000),
            _signin(None, "alice.martin@northstar.example", "1b94c5cd-f948-4290-8596-48e0511961d5"),
            {"eventId": 4688, "computer": "WS-001", "subjectUser": "SYSTEM", "subjectDomain": "NT AUTHORITY", "ts": 3_000},
        ]
        ew = EventWriter(store, 1)
        for e in events:
            e.pop("id", None)
            e["recordKey"] = None
            ew.add(dict(e))
        ew.flush()
        mw = MailWriter(store, 2)
        mw.add({"fromAddr": "documents@consent-review.example", "fromName": "Documents", "to": [{"addr": "alice.martin@northstar.example"}], "date": 5_000})
        mw.flush()
        records, pairs, stats = records_for_store(store)
        from_store = resolve(records=records, netbios_pairs=pairs, settings=SETTINGS)
        from_rows = resolve(events, [{"fromAddr": "documents@consent-review.example", "to": [{"addr": "alice.martin@northstar.example"}]}], SETTINGS)
        assert stats["truncated"] is False
        assert {i["label"]: sorted(f["value"] for f in i["forms"]) for i in from_store.identities} == {
            i["label"]: sorted(f["value"] for f in i["forms"]) for i in from_rows.identities
        }
        # the two logons are one distinct combination, counted twice
        alice = _ident(from_store, "netbios", "northstar\\alice.martin")
        assert next(f["seen"] for f in alice["forms"] if f["kind"] == "netbios") == 2
    finally:
        reg.close_all()


@pytest.mark.parametrize(
    ("user", "domain", "sid", "forms"),
    [
        ("NORTHSTAR\\alice", None, None, [Form("netbios", "northstar\\alice")]),
        ("alice", "NORTHSTAR", "S-1-5-21-1-2-3-1001", [Form("netbios", "northstar\\alice"), Form("sid", "s-1-5-21-1-2-3-1001")]),
        ("alice", "NORTHSTAR.EXAMPLE", None, [Form("addr", "alice@northstar.example")]),
        ("Alice@Northstar.example", None, None, [Form("addr", "alice@northstar.example")]),
        ("SYSTEM", "NT AUTHORITY", "S-1-5-18", [Form("netbios", "nt authority\\system")]),
        ("-", "-", "S-1-0-0", []),
        ("alice", None, None, [Form("name", "alice")]),
    ],
)
def test_account_forms(user, domain, sid, forms):
    from services.analysis.identity import account_forms

    assert account_forms(user, domain, sid) == forms
