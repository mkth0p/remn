"""Compare explicit collection expectations with the actual member inventory.

Two shapes of expectation reach this module. A *collection summary* row names an artifact
category ("Processes", "Services") and counts what the collector saw; a *manifest* entry names
a specific file with an optional size and digest. They need different treatment: a category has
no single file to point at, so any member of that category answers it, while a declared path
that is absent must read as missing. Matching a missing path against an unrelated file of the
same category would tell the analyst that evidence was collected when it never was, which is
the failure this whole check exists to catch.

Both inputs are attacker-controlled and separately capped high, so the comparison indexes the
inventory once rather than rescanning it per expectation.
"""

from collections import defaultdict

from services.parsers.collection import category, key

# Expectations reconciled per package. Beyond it the surplus is reported rather than dropped.
MAX_EXPECTATIONS = 10_000
_NOT_A_MEMBER = ("archive", "cab")


def _names_a_file(name: str) -> bool:
    """True when the expectation points at a specific member rather than an artifact category.

    A path separator or a trailing extension both mean "this exact file"; a bare word such as
    "Processes" is a category from an Artifact,Count summary row.
    """
    normalised = name.replace("\\", "/")
    if "/" in normalised:
        return True
    tail = normalised.rsplit(".", 1)
    return len(tail) == 2 and 1 <= len(tail[1]) <= 5 and tail[1].isalnum()


def reconcile(files, expectations):
    # Index the inventory once: the loop below would otherwise be O(expectations x members),
    # with a category() call per pair, which a single upload can drive into minutes of CPU.
    by_name = defaultdict(list)
    by_category = defaultdict(list)
    for f in files:
        by_name[str(f["name"]).replace("\\", "/").casefold()].append(f)
        artifact_type = f.get("artifactType")
        if artifact_type and f.get("format") not in _NOT_A_MEMBER:
            by_category[artifact_type].append(f)

    out = []
    for raw in expectations[:MAX_EXPECTATIONS]:
        fields = {key(k): v for k, v in raw.items()}
        name = str(fields.get("path") or fields.get("file") or fields.get("artifact") or "")
        if not name:
            continue
        exact = by_name.get(name.replace("\\", "/").casefold(), [])
        matches = exact
        if not exact and not _names_a_file(name):
            matches = by_category.get(category(name) or "", [])
        result = {"name": name, "status": "matched", "actual": sum(f["count"] for f in matches)}
        expected = fields.get("expectedcount", fields.get("count"))
        if expected is not None:
            try:
                result["expected"] = int(expected)
                if str(expected).strip() != str(int(expected)) or int(expected) < 0:
                    raise ValueError()
            except (ValueError, TypeError):
                result.update(status="unresolved", reason="expected count is not a nonnegative integer")
                out.append(result)
                continue
        if not matches:
            result.update(status="missing", reason="no matching member was collected")
        elif any(f["status"] not in ("parsed", "metadata") for f in matches):
            result.update(status="incomplete", reason="one or more members could not be parsed")
        elif expected is not None and result["actual"] != int(expected):
            result.update(status="mismatch", reason="parsed record count differs from collection summary")
        # A digest or size is only evidence of a mismatch when the member actually produced one.
        # An unparsed member has neither, and reporting that as "differs from manifest" would
        # both invent a discrepancy and mask the real reason the member is unusable.
        if exact and exact[0].get("status") in ("parsed", "metadata"):
            for field in ("sha256", "size"):
                if field in fields and exact[0].get(field) is not None and str(exact[0][field]).casefold() != str(fields[field]).casefold():
                    result.update(status="mismatch", reason=f"member {field} differs from manifest")
        out.append(result)

    # Never drop the surplus silently: an analyst reading a clean reconciliation must be able to
    # tell "everything was checked" from "the first ten thousand were checked".
    surplus = len(expectations) - MAX_EXPECTATIONS
    if surplus > 0:
        out.append(
            {
                "name": "(collection expectations)",
                "status": "unresolved",
                "reason": f"{surplus} further expectation(s) beyond the {MAX_EXPECTATIONS:,} reconciled here were not checked",
            }
        )
    return out
