from __future__ import annotations

import argparse
import json
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ALLOWED_TYPES = {"sense", "transition", "commit"}
REQUIRED_FIELDS = {"id", "type", "ts", "thread_id"}


def parse_ts(value: Any) -> float:
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        iso = value.replace("Z", "+00:00")
        dt = datetime.fromisoformat(iso)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.timestamp()
    raise ValueError("ts must be ISO8601 string or unix epoch number")


def validate_records(records: list[dict[str, Any]]) -> list[str]:
    errors: list[str] = []
    seen_ids: set[str] = set()
    last_ts_by_thread: dict[str, float] = {}
    seen_sense_or_transition = defaultdict(bool)
    seen_transition = defaultdict(bool)

    for idx, record in enumerate(records, start=1):
        if not isinstance(record, dict):
            errors.append(f"line {idx}: record must be JSON object")
            continue

        missing = REQUIRED_FIELDS - set(record.keys())
        if missing:
            errors.append(f"line {idx}: missing required fields: {sorted(missing)}")
            continue

        rec_id = record["id"]
        rec_type = record["type"]
        thread_id = record["thread_id"]

        if not isinstance(rec_id, str) or not rec_id.strip():
            errors.append(f"line {idx}: id must be non-empty string")
            continue

        if rec_id in seen_ids:
            errors.append(f"line {idx}: duplicate id '{rec_id}'")
            continue
        seen_ids.add(rec_id)

        if rec_type not in ALLOWED_TYPES:
            errors.append(f"line {idx}: type '{rec_type}' is not allowed")
            continue

        if not isinstance(thread_id, str) or not thread_id.strip():
            errors.append(f"line {idx}: thread_id must be non-empty string")
            continue

        try:
            ts_value = parse_ts(record["ts"])
        except Exception as exc:
            errors.append(f"line {idx}: invalid ts ({exc})")
            continue

        previous_ts = last_ts_by_thread.get(thread_id)
        if previous_ts is not None and ts_value < previous_ts:
            errors.append(f"line {idx}: non-monotonic ts in thread '{thread_id}'")
            continue
        last_ts_by_thread[thread_id] = ts_value

        if rec_type == "transition" and not seen_sense_or_transition[thread_id]:
            errors.append(f"line {idx}: transition requires prior sense/transition in same thread")
            continue

        if rec_type == "commit" and not seen_transition[thread_id]:
            errors.append(f"line {idx}: commit requires prior transition in same thread")
            continue

        if rec_type in {"sense", "transition"}:
            seen_sense_or_transition[thread_id] = True
        if rec_type == "transition":
            seen_transition[thread_id] = True

    return errors


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as handle:
        for idx, line in enumerate(handle, start=1):
            raw = line.strip()
            if not raw:
                continue
            try:
                parsed = json.loads(raw)
            except json.JSONDecodeError as exc:
                raise ValueError(f"line {idx}: invalid JSON ({exc.msg})") from exc
            records.append(parsed)
    return records


def validate_file(path: Path) -> int:
    try:
        records = read_jsonl(path)
    except Exception as exc:
        print(f"FAIL {path}: {exc}")
        return 1

    errors = validate_records(records)
    if errors:
        print(f"FAIL {path}")
        for error in errors:
            print(f"  - {error}")
        return 1

    print(f"PASS {path} ({len(records)} records)")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate T-Trace JSONL files")
    parser.add_argument("paths", nargs="+", help="Path(s) to .jsonl files")
    args = parser.parse_args()

    exit_code = 0
    for raw_path in args.paths:
        path = Path(raw_path)
        if not path.exists():
            print(f"FAIL {path}: file does not exist")
            exit_code = 1
            continue
        exit_code |= validate_file(path)
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())