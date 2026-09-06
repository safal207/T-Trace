import importlib.util
from pathlib import Path

from openpoc import verify_assurance, verify_cross_source
from ttrace import validation

ROOT = Path(__file__).resolve().parents[1]


def test_openpoc_uses_the_packaged_base_validator():
    assert verify_assurance._VALIDATOR is validation
    assert verify_cross_source._VALIDATOR is validation


def test_source_entry_point_preserves_base_api_identity():
    spec = importlib.util.spec_from_file_location(
        "source_validator_wrapper", ROOT / "scripts" / "validate_ttrace.py",
    )
    assert spec is not None and spec.loader is not None
    wrapper = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(wrapper)
    for name in (
        "ALLOWED_TYPES", "REQUIRED_FIELDS", "parse_ts", "read_jsonl",
        "validate_records", "validate_file", "main",
    ):
        assert getattr(wrapper, name) is getattr(validation, name)


def test_packaged_core_keeps_base_validation_results():
    valid = validation.read_jsonl(ROOT / "tests" / "fixtures" / "valid.ttrace.jsonl")
    duplicate = validation.read_jsonl(
        ROOT / "tests" / "fixtures" / "invalid_duplicate_id.ttrace.jsonl",
    )
    assert validation.validate_records(valid) == []
    assert any("duplicate id" in error for error in validation.validate_records(duplicate))
