from pathlib import Path
import json
import importlib.util

ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "scripts" / "validate_ttrace.py"
spec = importlib.util.spec_from_file_location("validate_ttrace", MODULE_PATH)
module = importlib.util.module_from_spec(spec)
assert spec is not None and spec.loader is not None
spec.loader.exec_module(module)


def test_valid_trace_passes():
    records = module.read_jsonl(ROOT / "tests" / "fixtures" / "valid.ttrace.jsonl")
    errors = module.validate_records(records)
    assert errors == []


def test_duplicate_id_fails():
    records = module.read_jsonl(ROOT / "tests" / "fixtures" / "invalid_duplicate_id.ttrace.jsonl")
    errors = module.validate_records(records)
    assert any("duplicate id" in e for e in errors)


def test_non_monotonic_ts_fails():
    records = module.read_jsonl(ROOT / "tests" / "fixtures" / "invalid_non_monotonic_ts.ttrace.jsonl")
    errors = module.validate_records(records)
    assert any("non-monotonic ts" in e for e in errors)


def test_commit_without_transition_fails():
    records = module.read_jsonl(ROOT / "tests" / "fixtures" / "invalid_commit_without_transition.ttrace.jsonl")
    errors = module.validate_records(records)
    assert any("commit requires prior transition" in e for e in errors)


def test_json_schema_required_fields_present():
    schema_path = ROOT / "schemas" / "t-trace-record.schema.json"
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    required = set(schema["required"])
    assert {"id", "type", "ts", "thread_id"}.issubset(required)