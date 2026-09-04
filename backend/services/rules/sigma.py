"""
Sigma -> REMN rule converter (Windows event-log rules).

Sigma (https://sigmahq.io) is the community standard for log detection rules: SigmaHQ ships
thousands of Windows rules, and Chainsaw / Hayabusa run them against EVTX. REMN's own DSL is
close enough that a faithful translation exists for the large structural subset:

* logsource category / service  -> channel + eventId conditions (Sysmon 1 <-> Security 4688 ...)
* field names                   -> the flattened columns produced by the EVTX parser (same
                                    EventData names), with per-category aliases; anything else
                                    is reachable as ``data.<Field>``
* value modifiers               -> contains / startswith / endswith / re / in / gt ...; globs
                                    become the right operator or an anchored regex
* condition expressions         -> any_of / all_of / not trees (1 of x*, all of them, ...)

What is NOT translated (the rule is reported as skipped, never silently weakened):
base64 / base64offset / utf16 / wide / fieldref / expand modifiers, aggregation expressions
(``| count() > 5``), ``N of`` with 1 < N < all, non-Windows products, CIDR prefixes that are not
/8, /16, /24 or /32, and correlation rules.
"""
from __future__ import annotations

import fnmatch
import re
from typing import Any

import yaml

from services.parsers.evtx_parser import FIELD_MAP

LEVELS = {"informational": "info", "info": "info", "low": "low", "medium": "medium", "high": "high", "critical": "critical"}

# System-level fields (not EventData) and Sigma conveniences
SPECIAL_FIELDS: dict[str, str] = {
    "EventID": "eventId", "Channel": "channel", "Provider_Name": "provider", "Provider": "provider",
    "Computer": "computer", "ComputerName": "computer", "Level": "level", "Keywords": "keywords", "Task": "task",
    "OpCode": "opcode", "Opcode": "opcode", "EventRecordID": "recordId", "Version": "version",
}

# Sysmon channel / PowerShell channels are matched by a distinctive token (case-insensitive contains)
_SYSMON = {"channel|contains": "sysmon"}
_PS_OPERATIONAL = {"channel|contains": "powershell/operational"}
_PS_CLASSIC = {"channel": "Windows PowerShell"}


def _sysmon(*ids: int) -> dict[str, Any]:
    return {**_SYSMON, "eventId": ids[0]} if len(ids) == 1 else {**_SYSMON, "eventId|in": list(ids)}


# category -> {"where": condition, "aliases": {SigmaField: [remn fields...]}}
CATEGORY_MAP: dict[str, dict[str, Any]] = {
    "process_creation": {
        "where": {"any_of": [_sysmon(1), {"channel": "Security", "eventId": 4688}]},
        "aliases": {"Image": ["image", "processName"], "ParentImage": ["parentImage", "parentProcessName"],
                    "User": ["user", "subjectUser"], "ProcessId": ["processId", "newProcessId"],
                    "ParentProcessId": ["parentProcessId"], "LogonId": ["subjectLogonId"]},
    },
    "process_termination": {"where": _sysmon(5)},
    "driver_load": {"where": _sysmon(6)},
    "image_load": {"where": _sysmon(7)},
    "create_remote_thread": {"where": _sysmon(8)},
    "raw_access_thread": {"where": _sysmon(9)},
    "process_access": {"where": _sysmon(10)},
    "file_event": {"where": _sysmon(11)},
    "registry_event": {"where": _sysmon(12, 13, 14)},
    "registry_add": {"where": _sysmon(12)},
    "registry_set": {"where": _sysmon(13)},
    "registry_delete": {"where": _sysmon(12)},
    "registry_rename": {"where": _sysmon(14)},
    "create_stream_hash": {"where": _sysmon(15)},
    "pipe_created": {"where": _sysmon(17, 18)},
    "wmi_event": {"where": _sysmon(19, 20, 21)},
    "dns_query": {"where": _sysmon(22)},
    "file_delete": {"where": _sysmon(23, 26)},
    "clipboard_capture": {"where": _sysmon(24)},
    "process_tampering": {"where": _sysmon(25)},
    "file_block_executable": {"where": _sysmon(27)},
    "file_block_shredding": {"where": _sysmon(28)},
    "file_executable_detected": {"where": _sysmon(29)},
    "network_connection": {"where": _sysmon(3)},
    "sysmon_status": {"where": _sysmon(4)},
    "sysmon_error": {"where": _sysmon(255)},
    "ps_script": {"where": {**_PS_OPERATIONAL, "eventId": 4104}},
    "ps_module": {"where": {**_PS_OPERATIONAL, "eventId": 4103}},
    "ps_classic_start": {"where": {**_PS_CLASSIC, "eventId": 400}},
    "ps_classic_provider_start": {"where": {**_PS_CLASSIC, "eventId": 600}},
    "ps_classic_script": {"where": {**_PS_CLASSIC, "eventId": 800}},
}

# service -> channel condition (exact name when it is stable, a distinctive token otherwise)
SERVICE_MAP: dict[str, dict[str, Any]] = {
    "security": {"channel": "Security"},
    "system": {"channel": "System"},
    "application": {"channel": "Application"},
    "sysmon": dict(_SYSMON),
    "powershell": dict(_PS_OPERATIONAL),
    "powershell-classic": dict(_PS_CLASSIC),
    "taskscheduler": {"channel|contains": "taskscheduler"},
    "windefend": {"channel|contains": "windows defender"},
    "terminalservices-localsessionmanager": {"channel|contains": "terminalservices-localsessionmanager"},
    "bits-client": {"channel|contains": "bits-client"},
    "dns-server": {"channel|contains": "dns server"},
    "dns-server-analytic": {"channel|contains": "dns-server/analytical"},
    "dns-client": {"channel|contains": "dns-client"},
    "ntlm": {"channel|contains": "ntlm"},
    "firewall-as": {"channel|contains": "firewall with advanced security"},
    "printservice-admin": {"channel|contains": "printservice/admin"},
    "printservice-operational": {"channel|contains": "printservice/operational"},
    "msexchange-management": {"channel|contains": "msexchange management"},
    "wmi": {"channel|contains": "wmi-activity"},
    "codeintegrity-operational": {"channel|contains": "codeintegrity/operational"},
    "applocker": {"channel|contains": "applocker"},
    "smbclient-security": {"channel|contains": "smbclient/security"},
    "smbclient-connectivity": {"channel|contains": "smbclient/connectivity"},
    "openssh": {"channel|contains": "openssh"},
    "shell-core": {"channel|contains": "shell-core"},
    "appxdeployment-server": {"channel|contains": "appxdeployment-server"},
    "appxpackaging-om": {"channel|contains": "appxpackaging"},
    "capi2": {"channel|contains": "capi2"},
    "certificateservicesclient-lifecycle-system": {"channel|contains": "certificateservicesclient-lifecycle-system"},
    "dhcp": {"channel|contains": "dhcp"},
    "ldap_debug": {"channel|contains": "ldap-client"},
    "lsa-server": {"channel|contains": "lsa"},
    "security-mitigations": {"channel|contains": "security-mitigations"},
    "sense": {"channel|contains": "sense"},
    "vhdmp": {"channel|contains": "vhdmp"},
    "bitlocker": {"channel|contains": "bitlocker"},
    "hyper-v-worker": {"channel|contains": "hyper-v-worker"},
    "kernel-event-tracing": {"channel|contains": "kernel-eventtracing"},
    "iis-configuration": {"channel|contains": "iis-configuration"},
    "driver-framework": {"channel|contains": "driverframeworks"},
    "appmodel-runtime": {"channel|contains": "appmodel-runtime"},
    "diagnosis-scripted": {"channel|contains": "diagnosis-scripted"},
    "microsoft-servicebus-client": {"channel|contains": "servicebus-client"},
    "audit": {"channel": "Security"},
    "windows-defender": {"channel|contains": "windows defender"},
    "wmi-activity": {"channel|contains": "wmi-activity"},
    "eventlog": {"channel|in": ["Security", "System", "Application"]},
}

UNSUPPORTED_MODIFIERS = {"base64", "base64offset", "utf16", "utf16le", "utf16be", "wide", "fieldref", "expand", "exists_ref"}
STRING_MODIFIERS = {"contains", "startswith", "endswith"}
NUMERIC_MODIFIERS = {"gt", "gte", "lt", "lte"}


class Unsupported(Exception):
    """A Sigma construct REMN cannot express without changing what the rule detects."""


# ---------------------------------------------------------------------------
# Values
# ---------------------------------------------------------------------------
def _glob_to_regex(value: str, anchor_start: bool, anchor_end: bool) -> str:
    """Sigma wildcards: * any, ? one, backslash escapes (\\* \\? \\\\)."""
    out: list[str] = []
    i = 0
    while i < len(value):
        c = value[i]
        if c == "\\" and i + 1 < len(value) and value[i + 1] in "*?\\":
            out.append(re.escape(value[i + 1]))
            i += 2
            continue
        if c == "*":
            out.append(".*")
        elif c == "?":
            out.append(".")
        else:
            out.append(re.escape(c))
        i += 1
    return ("^" if anchor_start else "") + "".join(out) + ("$" if anchor_end else "")


def _has_wildcard(value: str) -> bool:
    i = 0
    while i < len(value):
        if value[i] == "\\" and i + 1 < len(value):
            i += 2
            continue
        if value[i] in "*?":
            return True
        i += 1
    return False


def _unescape(value: str) -> str:
    return re.sub(r"\\([*?\\])", r"\1", value)


def _plain_string(value: str) -> tuple[str, str]:
    """A bare Sigma string: leading/trailing * decide the operator; inner wildcards need a regex."""
    core = value
    lead = trail = False
    while core.startswith("*") and not core.startswith("\\*"):
        core = core[1:]
        lead = True
    while core.endswith("*") and not core.endswith("\\*"):
        core = core[:-1]
        trail = True
    if _has_wildcard(core):
        return "re", _glob_to_regex(core, not lead, not trail)
    core = _unescape(core)
    if lead and trail:
        return "contains", core
    if trail:
        return "startswith", core
    if lead:
        return "endswith", core
    return "eq", core


def _windash(value: str) -> list[str]:
    """Sigma windash: every '-' switch may also be written '/' (and the unicode dashes)."""
    variants = {value}
    for dash in ("-", "/", "–", "—", "―"):
        variants.add(re.sub(r"(?<!\S)[-/–—―](?=\w)", dash, value))
    return sorted(variants)


def _octet_range_regex(lo: int, hi: int) -> str:
    """Regex matching the decimal numbers lo..hi (0-255), built from digit-class runs."""
    if lo == hi:
        return str(lo)
    parts: list[str] = []
    n = lo
    while n <= hi:
        # widest power-of-ten block starting at n that stays within hi
        step = 1
        while n % (step * 10) == 0 and n + step * 10 - 1 <= hi:
            step *= 10
        end = n + step - 1
        if step == 1:
            parts.append(str(n))
        else:
            width = len(str(step)) - 1
            prefix = str(n)[:-width] if len(str(n)) > width else ""
            parts.append(prefix + "[0-9]" * width)
        n = end + 1
    return "(?:" + "|".join(parts) + ")"


def _cidr_prefix(cidr: str) -> tuple[str, str]:
    net, _, bits = cidr.partition("/")
    if ":" in net:
        raise Unsupported(f"IPv6 cidr {cidr}")
    parts = net.split(".")
    if len(parts) != 4:
        raise Unsupported(f"cidr {cidr}")
    b = int(bits or 32)
    if b == 32:
        return "eq", net
    if b in (8, 16, 24):
        return "startswith", ".".join(parts[: b // 8]) + "."
    if not 0 < b < 32:
        raise Unsupported(f"cidr /{b}")
    # arbitrary prefix: fixed octets, one ranged octet, then anything
    ip = 0
    for o in parts:
        ip = (ip << 8) | int(o)
    mask = (0xFFFFFFFF << (32 - b)) & 0xFFFFFFFF
    lo_ip, hi_ip = ip & mask, (ip & mask) | (~mask & 0xFFFFFFFF)
    lo_o = [(lo_ip >> s) & 255 for s in (24, 16, 8, 0)]
    hi_o = [(hi_ip >> s) & 255 for s in (24, 16, 8, 0)]
    fixed = b // 8
    pattern = "".join(f"{lo_o[i]}\\." for i in range(fixed))
    pattern += _octet_range_regex(lo_o[fixed], hi_o[fixed])
    pattern += "(?:\\.[0-9]{1,3}){" + str(3 - fixed) + "}" if fixed < 3 else ""
    return "re", "^" + pattern + "$"


def _cond(field: str, op: str, value: Any) -> dict[str, Any]:
    return {f"{field}|{op}" if op != "eq" else field: value}


def compile_field(raw_field: str, value: Any, aliases: dict[str, list[str]], warnings: list[str]) -> dict[str, Any]:
    name, *mods = raw_field.split("|")
    mods = [m for m in mods if m]
    for m in mods:
        if m in UNSUPPORTED_MODIFIERS:
            raise Unsupported(f"modifier |{m} on {name}")
    if "cased" in mods:
        warnings.append(f"{name}: |cased ignored (REMN matches case-insensitively)")
    targets = aliases.get(name) or [SPECIAL_FIELDS.get(name) or FIELD_MAP.get(name) or f"data.{name}"]
    all_mode = "all" in mods
    values = value if isinstance(value, list) else [value]

    # numeric comparisons
    num = next((m for m in mods if m in NUMERIC_MODIFIERS), None)
    if num:
        if len(values) != 1:
            raise Unsupported(f"{name}: |{num} with a list")
        return _spread(targets, num, values[0])
    if "exists" in mods:
        return _spread(targets, "exists", bool(values[0]))
    if "cidr" in mods:
        return _any_of([_spread(targets, *_cidr_prefix(str(v))) for v in values])
    if "re" in mods:
        pats = [str(v) for v in values]
        if all_mode:
            return {"all_of": [_spread(targets, "re", p) for p in pats]}
        return _spread(targets, "re", pats if len(pats) > 1 else pats[0])

    if values == [None] or values == []:
        return _spread(targets, "exists", False)

    smod = next((m for m in mods if m in STRING_MODIFIERS), None)
    if "windash" in mods:
        values = [v2 for v in values for v2 in _windash(str(v))]
        smod = smod or "contains"

    if smod:
        strs = [str(v) for v in values]
        wild = [s for s in strs if _has_wildcard(s)]
        if wild:
            # a glob inside a contains/startswith/endswith value: regex with the matching anchors
            pats = [_glob_to_regex(s, smod == "startswith", smod == "endswith") for s in strs]
            if all_mode:
                return {"all_of": [_spread(targets, "re", p) for p in pats]}
            return _spread(targets, "re", pats if len(pats) > 1 else pats[0])
        strs = [_unescape(s) for s in strs]
        if all_mode:
            if smod == "contains":
                return _spread(targets, "contains_all", strs)
            return {"all_of": [_spread(targets, smod, s) for s in strs]}
        op = "contains_any" if (smod == "contains" and len(strs) > 1) else smod
        return _spread(targets, op, strs if len(strs) > 1 else strs[0])

    # bare values: numbers / booleans are equality, strings decide by their wildcards
    if all(isinstance(v, (int, float, bool)) and not isinstance(v, bool) or isinstance(v, bool) for v in values):
        vals = [int(v) if isinstance(v, bool) else v for v in values]
        return _spread(targets, "in" if len(vals) > 1 else "eq", vals if len(vals) > 1 else vals[0])
    strs = [str(v) for v in values]
    parsed = [_plain_string(s) for s in strs]
    if all_mode:
        return {"all_of": [_spread(targets, op, v) for op, v in parsed]}
    ops = {op for op, _ in parsed}
    if len(ops) == 1:
        op = ops.pop()
        vals = [v for _, v in parsed]
        if op == "eq":
            return _spread(targets, "in" if len(vals) > 1 else "eq", vals if len(vals) > 1 else vals[0])
        if op == "contains":
            return _spread(targets, "contains_any" if len(vals) > 1 else "contains", vals if len(vals) > 1 else vals[0])
        return _spread(targets, op, vals if len(vals) > 1 else vals[0])
    return _any_of([_spread(targets, op, v) for op, v in parsed])


def _spread(targets: list[str], op: str, value: Any) -> dict[str, Any]:
    """One Sigma field can map to several REMN columns (Image -> image | processName): OR them."""
    if len(targets) == 1:
        return _cond(targets[0], op, value)
    return _any_of([_cond(t, op, value) for t in targets])


# ---------------------------------------------------------------------------
# Selections and conditions
# ---------------------------------------------------------------------------
def compile_selection(sel: Any, aliases: dict[str, list[str]], warnings: list[str]) -> dict[str, Any]:
    if isinstance(sel, dict):
        parts = [compile_field(k, v, aliases, warnings) for k, v in sel.items()]
        return _all_of(parts)
    if isinstance(sel, list):
        if all(isinstance(x, (str, int, float)) for x in sel):
            # keyword list: anywhere in the event
            return {"raw|contains_any": [str(x) for x in sel]}
        alts = [compile_selection(x, aliases, warnings) if isinstance(x, (dict, list)) else {"raw|contains": str(x)} for x in sel]
        return _any_of(alts)
    if isinstance(sel, (str, int, float)):
        return {"raw|contains": str(sel)}
    raise Unsupported(f"selection of type {type(sel).__name__}")


_COMBINATOR_RE = re.compile(r"^(any_of|all_of)(_\d+)?$")


def _all_of(parts: list[dict[str, Any]]) -> dict[str, Any]:
    """AND of conditions as one flat mapping (the DSL ANDs the keys of a mapping). Nested all_of
    blocks are spliced in; a second any_of gets the DSL's numeric suffix (any_of_2); a genuine
    key collision (the same field|op twice) or a second `not` keeps an explicit all_of list."""
    flat: list[dict[str, Any]] = []
    for p in parts:
        if not p:
            continue
        if len(p) == 1 and next(iter(p)) == "all_of":
            flat.extend(_all_of_children(p["all_of"]))
        else:
            flat.append(p)
    if not flat:
        return {}
    if len(flat) == 1:
        return flat[0]
    merged: dict[str, Any] = {}
    for p in flat:
        for k, v in p.items():
            key = k
            if _COMBINATOR_RE.match(k):
                base = k.split("_")[0] + "_" + k.split("_")[1]  # any_of / all_of
                n = 2
                while key in merged:
                    key = f"{base}_{n}"
                    n += 1
            elif key in merged:
                return {"all_of": flat}
            merged[key] = v
    return merged


def _all_of_children(items: Any) -> list[dict[str, Any]]:
    return [x for x in (items if isinstance(items, list) else [items]) if isinstance(x, dict)]


def _any_of(parts: list[dict[str, Any]]) -> dict[str, Any]:
    """OR of conditions; nested pure any_of blocks are spliced in."""
    flat: list[dict[str, Any]] = []
    for p in parts:
        if not p:
            continue
        if len(p) == 1 and next(iter(p)) == "any_of":
            flat.extend(_all_of_children(p["any_of"]))
        else:
            flat.append(p)
    if not flat:
        return {}
    return flat[0] if len(flat) == 1 else {"any_of": flat}


_TOKEN_RE = re.compile(r"\s*(\(|\)|\||[A-Za-z0-9_*.\-]+)")


class _CondParser:
    def __init__(self, text: str, selections: dict[str, dict[str, Any]]):
        if "|" in text:
            raise Unsupported("aggregation / correlation expression (| count() ...)")
        self.tokens = self._tokenize(text)
        self.pos = 0
        self.selections = selections

    @staticmethod
    def _tokenize(text: str) -> list[str]:
        out: list[str] = []
        i = 0
        while i < len(text):
            m = _TOKEN_RE.match(text, i)
            if not m:
                if text[i:].strip():
                    raise Unsupported(f"condition syntax near {text[i:i + 20]!r}")
                break
            out.append(m.group(1))
            i = m.end()
        return out

    def peek(self) -> str | None:
        return self.tokens[self.pos] if self.pos < len(self.tokens) else None

    def take(self) -> str:
        tok = self.peek()
        if tok is None:
            raise Unsupported("unexpected end of condition")
        self.pos += 1
        return tok

    def parse(self) -> dict[str, Any]:
        node = self.parse_or()
        if self.peek() == "|":
            raise Unsupported("aggregation / correlation expression (| count() ...)")
        if self.peek() is not None:
            raise Unsupported(f"condition syntax near {self.peek()!r}")
        return node

    def parse_or(self) -> dict[str, Any]:
        parts = [self.parse_and()]
        while self.peek() and self.peek().lower() == "or":
            self.take()
            parts.append(self.parse_and())
        return _any_of(parts)

    def parse_and(self) -> dict[str, Any]:
        parts = [self.parse_not()]
        while self.peek() and self.peek().lower() == "and":
            self.take()
            parts.append(self.parse_not())
        return _all_of(parts) if len(parts) > 1 else parts[0]

    def parse_not(self) -> dict[str, Any]:
        if self.peek() and self.peek().lower() == "not":
            self.take()
            return {"not": self.parse_not()}
        return self.parse_primary()

    def parse_primary(self) -> dict[str, Any]:
        tok = self.take()
        if tok == "(":
            node = self.parse_or()
            if self.take() != ")":
                raise Unsupported("unbalanced parentheses in condition")
            return node
        low = tok.lower()
        if low in ("1", "all") or low.isdigit():
            if not (self.peek() and self.peek().lower() == "of"):
                raise Unsupported(f"condition syntax near {tok!r}")
            self.take()
            pattern = self.take()
            names = list(self.selections) if pattern.lower() == "them" else [n for n in self.selections if fnmatch.fnmatchcase(n, pattern)]
            if not names:
                raise Unsupported(f"no selection matches {pattern!r}")
            nodes = [self.selections[n] for n in names]
            if low == "all" or (low.isdigit() and int(low) == len(names)):
                return _all_of(nodes) if len(nodes) > 1 else nodes[0]
            if low == "1":
                return _any_of(nodes)
            raise Unsupported(f"{low} of {pattern}: only '1 of' and 'all of' translate exactly")
        if tok not in self.selections:
            raise Unsupported(f"unknown selection {tok!r} in condition")
        return self.selections[tok]


# ---------------------------------------------------------------------------
# Rule
# ---------------------------------------------------------------------------
def _logsource(ls: dict[str, Any], warnings: list[str]) -> tuple[dict[str, Any], dict[str, list[str]]]:
    product = str(ls.get("product") or "").lower()
    category = str(ls.get("category") or "").lower()
    service = str(ls.get("service") or "").lower()
    if product and product != "windows":
        raise Unsupported(f"product {product!r} (REMN parses Windows event logs)")
    if category in CATEGORY_MAP:
        entry = CATEGORY_MAP[category]
        return dict(entry["where"]), dict(entry.get("aliases") or {})
    if category and category not in CATEGORY_MAP and not service:
        raise Unsupported(f"logsource category {category!r}")
    if service in SERVICE_MAP:
        return dict(SERVICE_MAP[service]), {}
    if service:
        warnings.append(f"unknown service {service!r}: matched as channel contains {service!r}")
        return {"channel|contains": service}, {}
    if not product:
        raise Unsupported("logsource has no product/category/service")
    return {}, {}


def _attack_tags(tags: list[Any]) -> tuple[list[str], list[str]]:
    attack: list[str] = []
    other: list[str] = []
    for t in tags or []:
        s = str(t)
        m = re.match(r"(?i)^attack\.(t\d{4}(?:\.\d{3})?)$", s)
        if m:
            attack.append(m.group(1).upper())
        elif s.lower().startswith("attack."):
            other.append(s[7:].replace("_", "-"))
        else:
            other.append(s)
    return attack, other


def _slug(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")[:60] or "rule"


def convert_rule(doc: dict[str, Any]) -> dict[str, Any]:
    """Convert one parsed Sigma document. Returns {ok, id, title, rule, yaml, warnings} or {ok: False, error}."""
    title = str(doc.get("title") or "").strip()
    sigma_id = str(doc.get("id") or "").strip()
    warnings: list[str] = []
    try:
        if not title:
            raise Unsupported("no title")
        if doc.get("correlation") is not None:
            raise Unsupported("correlation rule")
        detection = doc.get("detection")
        if not isinstance(detection, dict) or "condition" not in detection:
            raise Unsupported("no detection/condition")
        ls = doc.get("logsource") or {}
        if not isinstance(ls, dict):
            raise Unsupported("logsource is not a mapping")
        ls_where, aliases = _logsource(ls, warnings)
        selections: dict[str, dict[str, Any]] = {}
        for name, sel in detection.items():
            if name in ("condition", "timeframe"):
                continue
            selections[str(name)] = compile_selection(sel, aliases, warnings)
        if detection.get("timeframe"):
            warnings.append("timeframe ignored (aggregation not translated)")
        conditions = detection["condition"]
        conditions = conditions if isinstance(conditions, list) else [conditions]
        trees = [_CondParser(str(c), selections).parse() for c in conditions]
        det = _any_of(trees)
        where = _all_of([ls_where, det]) if ls_where else det
        level = str(doc.get("level") or "medium").lower()
        attack, tags = _attack_tags(doc.get("tags") or [])
        cat_or_service = (ls.get("category") or ls.get("service") or "").lower()
        rule: dict[str, Any] = {
            "id": f"sigma-{sigma_id or _slug(title)}",
            "title": title,
            "description": " ".join(str(doc.get("description") or "").split()) or None,
            "severity": LEVELS.get(level, "medium"),
            "source": "events",
            "attack": attack or None,
            "tags": ["sigma"] + ([cat_or_service] if cat_or_service else []) + tags,
            "references": [str(r) for r in (doc.get("references") or [])] or None,
            "where": where,
            "sigma": {k: v for k, v in {
                "id": sigma_id or None, "status": doc.get("status"), "author": doc.get("author"),
                "date": str(doc.get("date")) if doc.get("date") else None,
                "modified": str(doc.get("modified")) if doc.get("modified") else None,
                "level": level, "logsource": ls,
                "falsepositives": [str(x) for x in (doc.get("falsepositives") or [])] or None,
            }.items() if v},
        }
        rule = {k: v for k, v in rule.items() if v is not None}
        text = yaml.safe_dump(rule, sort_keys=False, allow_unicode=True, width=120)
        return {"ok": True, "id": rule["id"], "title": title, "sigmaId": sigma_id or None, "rule": rule, "yaml": text, "warnings": warnings}
    except Unsupported as exc:
        return {"ok": False, "id": f"sigma-{sigma_id or _slug(title)}", "title": title or "(untitled)", "sigmaId": sigma_id or None,
                "error": str(exc), "warnings": warnings}
    except Exception as exc:  # noqa: BLE001 - never let one odd rule abort a bulk import
        return {"ok": False, "id": f"sigma-{sigma_id or _slug(title)}", "title": title or "(untitled)", "sigmaId": sigma_id or None,
                "error": f"{type(exc).__name__}: {exc}"[:200], "warnings": warnings}


def convert_text(text: str, source_name: str = "") -> list[dict[str, Any]]:
    """Convert every Sigma document in a YAML text (multi-document files are common)."""
    out: list[dict[str, Any]] = []
    try:
        docs = [d for d in yaml.safe_load_all(text) if isinstance(d, dict)]
    except yaml.YAMLError as exc:
        return [{"ok": False, "id": source_name or "?", "title": source_name or "(invalid yaml)", "error": f"yaml: {str(exc)[:160]}", "warnings": []}]
    for doc in docs:
        res = convert_rule(doc)
        if source_name:
            res["file"] = source_name
        out.append(res)
    return out
