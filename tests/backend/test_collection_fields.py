"""Collected artifacts have to land in the fields the rules look at, or no rule ever fires on them.

Each case here is an export shape from a real collection where the parser produced rows that no
rule could reach: the command of a scheduled task under a header the mapping did not know, a
prefetch entry with no executable path, a Defender threat named only inside free text, and an
autoruns member that is concatenated `reg query` output read one line per row.
"""

from __future__ import annotations

from services.parsers.collection import native_rows, normalize, records

CTX = {"host": "WS01"}


def parse(tmp_path, body: bytes, name):
    path = tmp_path / "member"
    path.write_bytes(body)
    notes: dict = {}
    return [normalize(raw, name, i, CTX) for i, raw in enumerate(records(str(path), name, notes))], notes


def test_a_french_schtasks_export_reaches_the_persistence_fields(tmp_path):
    """schtasks /fo csv writes its headers in the host's language. A French host put the command
    under "Tâche à exécuter", which no rule could see, so 434 tasks were invisible to every
    persistence rule."""
    header = "Nom de l'hôte,Nom de la tâche,Prochaine exécution,Statut,Auteur,Tâche à exécuter,Démarrer dans,Exécuter en tant qu'utilisateur"
    body = (
        header + "\n"
        'WS01,\\Updater,N/A,Prêt,Contoso,"""C:\\Users\\jdoe\\AppData\\Roaming\\upd.exe"" /silent",N/A,WS01\\jdoe\n'
    ).encode("cp1252")

    rows, notes = parse(tmp_path, body, "Scheduled Tasks/ScheduledTasks.csv")

    row = rows[0]
    assert notes["encoding"] == "cp1252"
    assert row["artifactType"] == "task"
    assert row["taskName"] == "\\Updater"
    assert row["commandLine"] == '"C:\\Users\\jdoe\\AppData\\Roaming\\upd.exe" /silent'
    assert row["image"] == "C:\\Users\\jdoe\\AppData\\Roaming\\upd.exe", "the quoted executable, without its arguments"
    assert row["targetUser"] == "WS01\\jdoe"


def test_an_english_schtasks_export_reaches_the_same_fields(tmp_path):
    header = "HostName,TaskName,Next Run Time,Status,Logon Mode,Last Run Time,Last Result,Author,Task To Run,Start In,Run As User"
    body = (header + "\n" "WS01,\\Backup,N/A,Ready,Interactive,N/A,0,SYSTEM,C:\\Windows\\system32\\wbadmin.exe start backup,N/A,SYSTEM\n").encode()

    rows, _ = parse(tmp_path, body, "Scheduled Tasks/ScheduledTasks.csv")

    assert rows[0]["commandLine"] == "C:\\Windows\\system32\\wbadmin.exe start backup"
    assert rows[0]["image"] == "C:\\Windows\\system32\\wbadmin.exe"
    assert rows[0]["targetUser"] == "SYSTEM"


def test_reg_query_output_becomes_one_row_per_autostart_value(tmp_path):
    """The autoruns member is `reg query /s` over the autostart keys, in the host's language."""
    body = (
        "ERREUR : Impossible de trouver la clé ou la valeur de Registre spécifiée.\n"
        "\n"
        "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\n"
        "    SecurityHealth    REG_EXPAND_SZ    %windir%\\system32\\SecurityHealthSystray.exe\n"
        "    Dropper    REG_SZ    \"C:\\Users\\Public\\svc.exe\" -k\n"
        "    Description    REG_SZ    @%SystemRoot%\\system32\\shell32.dll,-4161\n"
        "    Enabled    REG_DWORD    0x1\n"
        "\n"
        "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce\n"
        "    Cleanup    REG_SZ    cmd.exe /c del %TEMP%\\stage.bin\n"
    ).encode("cp1252")

    rows, _ = parse(tmp_path, body, "Autoruns/Autoruns.txt")

    by_name = {r["name"]: r for r in rows if r.get("name")}
    assert set(by_name) == {"SecurityHealth", "Dropper", "Description", "Enabled", "Cleanup"}
    dropper = by_name["Dropper"]
    assert dropper["artifactType"] == "autorun"
    assert dropper["targetObject"] == "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"
    assert dropper["image"] == '"C:\\Users\\Public\\svc.exe" -k'
    assert dropper["data"]["Type"] == "REG_SZ"
    assert "Dropper" in dropper["summary"] and "svc.exe" in dropper["summary"]
    assert by_name["Cleanup"]["image"] == "cmd.exe /c del %TEMP%\\stage.bin"
    # a resource string and a flag are values, not launches
    assert by_name["Description"]["image"] is None
    assert by_name["Enabled"]["image"] is None
    # the collector's own error line is kept as a message row, not lost and not mistaken for a value
    errors = [r for r in rows if (r.get("message") or "").startswith("ERREUR")]
    assert len(errors) == 1 and errors[0]["name"] is None


def test_a_prefetch_entry_names_the_executable_it_ran():
    """Prefetch carried only the executable's file name. The rules that ask where something ran
    from look at image, which was never set."""
    raw = [
        {
            "Name": "UPD.EXE",
            "LastRunTime": "2026-09-09T09:59:00+00:00",
            "RunCount": 2,
            "ReferencedFiles": [
                "\\VOLUME{01d9}\\WINDOWS\\SYSTEM32\\NTDLL.DLL",
                "\\VOLUME{01d9}\\USERS\\JDOE\\DOWNLOADS\\UPD.EXE",
            ],
            "PrefetchVersion": 30,
        }
    ]
    rows = list(native_rows("prefetch", raw, "UPD.EXE-1A2B3C4D.pf", CTX))

    assert rows[0]["processName"] == "UPD.EXE"
    assert rows[0]["image"] == "\\VOLUME{01d9}\\USERS\\JDOE\\DOWNLOADS\\UPD.EXE"
    assert rows[0]["path"] == rows[0]["image"]


def test_an_installed_program_has_a_path(tmp_path):
    body = (b"Name,Vendor,Version,InstallLocation,InstallSource\n" b"Helper,,1.0,C:\\Users\\jdoe\\AppData\\Local\\Helper\\,C:\\Users\\jdoe\\Downloads\\\n")
    rows, _ = parse(tmp_path, body, "Installed Programs/InstalledPrograms.csv")

    assert rows[0]["artifactType"] == "program"
    assert rows[0]["path"] == "C:\\Users\\jdoe\\AppData\\Local\\Helper\\"


def test_a_defender_line_yields_its_threat_name(tmp_path):
    """Whatever log it appears in, a Defender threat name has one shape, so it can be lifted into
    a field the rules can group on instead of matched by phrase."""
    body = (
        "\n".join(
            [
                "2026-08-19T01:34:26.112Z Begin Resource Scan",
                "Threat Name:Trojan:Win32/Synthetic.A!ml",
                "2026-08-19T01:34:26.113Z DETECTION_ADD PUA:Win32/Presenoker file:C:\\Users\\Public\\tool.exe",
                "Internal signature match: lowfi:Nothing/ToSee",
                "Engine version: 1.1.24050.5",
            ]
        )
        + "\n"
    ).encode()

    rows, _ = parse(tmp_path, body, "WdSupportLogs/MPLog-20260819.log")

    names = [r.get("threatName") for r in rows]
    assert names == [None, "Trojan:Win32/Synthetic.A!ml", "PUA:Win32/Presenoker", None, None]
