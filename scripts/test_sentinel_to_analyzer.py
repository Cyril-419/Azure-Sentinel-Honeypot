import json

from sentinel_to_analyzer import convert, main

HEADER = "TimeCreated,EventID,Computer,TargetUserName,IpAddress,LogonType\n"


def test_convert_keeps_logon_events_sorted_and_marks_utc():
    rows = [
        {"TimeCreated": "2026-11-16T18:00:05.0000000", "EventID": "4625", "IpAddress": "203.0.113.5", "TargetUserName": "admin"},
        {"TimeCreated": "2026-11-16T18:00:01.0000000", "EventID": "4624", "IpAddress": "198.51.100.1", "TargetUserName": "labadmin"},
        {"TimeCreated": "2026-11-16T18:00:02.0000000", "EventID": "4634", "IpAddress": "-"},
    ]
    records, skipped = convert(rows)
    assert skipped == 1
    assert [r["EventID"] for r in records] == [4624, 4625]
    assert records[0]["TimeCreated"].endswith("Z")


def test_handles_bom_and_utc_suffix_headers():
    rows = [{"﻿TimeCreated [UTC]": "2026-11-16T18:00:00", "EventID": "4625", "IpAddress": "1.2.3.4"}]
    records, _ = convert(rows)
    assert records[0]["TimeCreated"] == "2026-11-16T18:00:00Z"


def test_cli_writes_json(tmp_path, capsys):
    src = tmp_path / "export.csv"
    src.write_text(HEADER + "2026-11-16T18:00:00.0000000,4625,HONEYPOT-VM,admin,203.0.113.5,3\n")
    assert main([str(src)]) == 0
    data = json.loads((tmp_path / "export.json").read_text())
    assert data[0]["IpAddress"] == "203.0.113.5"
    assert "1 logon events (1 failures)" in capsys.readouterr().out


def test_cli_rejects_wrong_export(tmp_path, capsys):
    src = tmp_path / "wrong.csv"
    src.write_text("Foo,Bar\n1,2\n")
    assert main([str(src)]) == 2
    assert "missing column" in capsys.readouterr().err
