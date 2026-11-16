"""Convert a Microsoft Sentinel CSV export into my log analyzer's Windows format.

Workflow:
  1. Run query 9 from hunting/hunting_queries.kql in Sentinel and export as CSV.
  2. python scripts/sentinel_to_analyzer.py honeypot_export.csv -o honeypot_events.json
  3. python -m loganalyzer analyze honeypot_events.json --format windows
     (run from the Security-Log-Analyzer repo)

This lets me check my Python detections against real attack traffic and
compare them with what Sentinel's KQL rules flagged.
"""
from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path

# The analyzer expects these keys (see loganalyzer/parsers.py: parse_windows)
FIELDS = ["TimeCreated", "EventID", "Computer", "TargetUserName", "IpAddress", "LogonType"]
KEEP_EVENT_IDS = {"4624", "4625"}


def _clean_header(name: str) -> str:
    # Log Analytics exports can add " [UTC]" to datetime columns and a BOM to the first header.
    return name.replace("﻿", "").split(" [")[0].strip()


def convert(rows: list[dict]) -> tuple[list[dict], int]:
    """Return (records, skipped). Rows that aren't logon events or lack a time are skipped."""
    records, skipped = [], 0
    for row in rows:
        row = {_clean_header(k): (v or "").strip() for k, v in row.items() if k}
        event_id = row.get("EventID", "").replace(",", "")
        if event_id not in KEEP_EVENT_IDS or not row.get("TimeCreated"):
            skipped += 1
            continue
        rec = {f: row.get(f, "") for f in FIELDS}
        rec["EventID"] = int(event_id)
        # TimeGenerated in Sentinel is UTC; mark it so it's unambiguous.
        if not rec["TimeCreated"].endswith("Z") and "+" not in rec["TimeCreated"][10:]:
            rec["TimeCreated"] += "Z"
        records.append(rec)
    records.sort(key=lambda r: r["TimeCreated"])  # the analyzer expects time order
    return records, skipped


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("csv_file", type=Path)
    ap.add_argument("-o", "--output", type=Path, help="output JSON (default: <input>.json)")
    args = ap.parse_args(argv)

    if not args.csv_file.exists():
        print(f"error: {args.csv_file} not found", file=sys.stderr)
        return 2
    with args.csv_file.open(newline="", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        headers = {_clean_header(h) for h in (reader.fieldnames or [])}
        missing = {"TimeCreated", "EventID", "IpAddress"} - headers
        if missing:
            print(f"error: CSV is missing column(s): {', '.join(sorted(missing))}. "
                  "Use query 9 in hunting/hunting_queries.kql.", file=sys.stderr)
            return 2
        records, skipped = convert(list(reader))

    out = args.output or args.csv_file.with_suffix(".json")
    out.write_text(json.dumps(records, indent=1))
    fails = sum(r["EventID"] == 4625 for r in records)
    print(f"Wrote {len(records):,} logon events ({fails:,} failures) to {out}"
          + (f"; skipped {skipped:,} other rows" if skipped else ""))
    return 0


if __name__ == "__main__":
    sys.exit(main())
