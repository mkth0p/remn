"""Explicit aliases and conservative process resolution within one collection snapshot."""

from services.parsers.collection import timestamp


def prepare(events, options=None, process_context=None):
    aliases = (options or {}).get("aliases", {})
    if not isinstance(aliases, dict):
        raise ValueError("aliases must be an object")
    maps = {}
    for kind in ("hosts", "accounts"):
        mapping = aliases.get(kind, {})
        if not isinstance(mapping, dict) or len(mapping) > 1000 or any(not isinstance(v, str) or not v.strip() for v in mapping.values()):
            raise ValueError("alias maps accept at most 1000 non-empty string values")
        maps[kind] = {k.strip().casefold().rstrip("."): v.strip().casefold().rstrip(".") for k, v in mapping.items()}

    def canonical(kind, value):
        value = str(value or "").strip().casefold().rstrip(".")
        seen = set()
        while value in maps[kind] and maps[kind][value] != value:
            if value in seen:
                raise ValueError("alias maps must not contain cycles")
            seen.add(value)
            value = maps[kind][value]
        return value

    for kind, mapping in maps.items():
        for value in mapping:
            canonical(kind, value)
    rows = [dict(row) for row in events]
    identities = {(r.get("id"), r.get("evidenceId")) for r in rows if r.get("id") is not None}
    context = [dict(r) for r in (process_context or []) if r.get("id") is None or (r.get("id"), r.get("evidenceId")) not in identities]
    candidates = {}

    def snapshot(row):
        observed = row.get("observedAt")
        return (
            row.get("computer"),
            str(row.get("processId") or row.get("newProcessId") or ""),
            row.get("packageId"),
            observed if type(observed) is int else timestamp(observed),
        )

    for row in rows + context:
        if row.get("computer"):
            row["computer"] = canonical("hosts", row["computer"])
        for field, realm in (
            ("targetUser", "targetDomain"),
            ("subjectUser", "subjectDomain"),
            ("user", "targetDomain"),
            ("upn", None),
            ("serviceAccount", None),
        ):
            value = str(row.get(field) or "")
            qualified = value if "@" in value or "\\" in value else f"{row[realm]}\\{value}" if realm and row.get(realm) and value else ""
            if qualified:
                row[field] = canonical("accounts", qualified)
        key = snapshot(row)
        start = timestamp(row.get("processStart"))
        if row.get("artifactType") == "process" and all(v is not None and v != "" for v in key) and start is not None and start <= key[3]:
            candidates.setdefault(key, []).append(row)
    for row in rows:
        if (options or {}).get("resolveSnapshots") is False:
            break
        matches = candidates.get(snapshot(row), [])
        if row.get("artifactType") == "connection" and not row.get("processGuid") and timestamp(row.get("processStart")) is None and len(matches) == 1:
            row["processStart"] = matches[0]["processStart"]
            if matches[0].get("processGuid"):
                row["processGuid"] = matches[0]["processGuid"]
            row["_processResolution"] = "Unique process with the same host, PID, package and explicit collection time; contextual snapshot match"
            row["_processEvidence"] = matches[0]
    return rows
