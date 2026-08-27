from __future__ import annotations

import argparse
import importlib.util
import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Iterable

ROOT = Path(__file__).resolve().parents[1]
VALIDATOR_PATH = ROOT / "scripts" / "validate_ttrace.py"


def _load_validator() -> Any:
    spec = importlib.util.spec_from_file_location("validate_ttrace", VALIDATOR_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load validator from {VALIDATOR_PATH}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


_VALIDATOR = _load_validator()


@dataclass(frozen=True)
class AssuranceReport:
    trace_valid: bool
    capture_complete: bool
    capture_status: str
    effect_bound: bool | None
    overall_assurance: str
    missing_effect_ids: tuple[str, ...]
    unexpected_receipt_ids: tuple[str, ...]
    trace_errors: tuple[str, ...]
    trust_assumptions: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def load_trace(path: Path) -> list[dict[str, Any]]:
    return _VALIDATOR.read_jsonl(path)


def assess_assurance(
    records: list[dict[str, Any]],
    *,
    receipt_effect_ids: Iterable[str],
    external_effect_ids: Iterable[str] | None = None,
    non_bypassable_gate_attested: bool = False,
) -> AssuranceReport:
    """Separate trace validity from effect-capture assurance.

    `external_effect_ids` is optional because a trace-only verifier normally
    lacks ground truth about effects outside the evidence path. Supplying it in
    a fixture simulates an independent witness and can demonstrate a violation.

    `non_bypassable_gate_attested` is a trust assumption in OpenPoC-01, not a
    production attestation mechanism.
    """

    trace_errors = tuple(_VALIDATOR.validate_records(records))
    trace_valid = not trace_errors
    receipt_ids = set(receipt_effect_ids)

    if external_effect_ids is None:
        effect_bound: bool | None = None
        missing_effect_ids: tuple[str, ...] = ()
        unexpected_receipt_ids: tuple[str, ...] = ()
    else:
        external_ids = set(external_effect_ids)
        missing_effect_ids = tuple(sorted(external_ids - receipt_ids))
        unexpected_receipt_ids = tuple(sorted(receipt_ids - external_ids))
        effect_bound = not missing_effect_ids

    if not trace_valid:
        capture_complete = False
        capture_status = "invalid-trace"
    elif effect_bound is False:
        capture_complete = False
        capture_status = "violated"
    elif non_bypassable_gate_attested:
        capture_complete = True
        capture_status = "supported-under-stated-assumptions"
    else:
        capture_complete = False
        capture_status = "unproven"

    overall_assurance = (
        "sufficient-under-stated-assumptions"
        if trace_valid and capture_complete
        else "insufficient"
    )

    assumptions = []
    if non_bypassable_gate_attested:
        assumptions.append("all relevant effects must traverse the attested gate")
        assumptions.append("a valid precommitment is required before each effect")
    else:
        assumptions.append("no non-bypassable capture path is attested")
    if external_effect_ids is not None:
        assumptions.append("external effect inventory is independent ground truth")

    return AssuranceReport(
        trace_valid=trace_valid,
        capture_complete=capture_complete,
        capture_status=capture_status,
        effect_bound=effect_bound,
        overall_assurance=overall_assurance,
        missing_effect_ids=missing_effect_ids,
        unexpected_receipt_ids=unexpected_receipt_ids,
        trace_errors=trace_errors,
        trust_assumptions=tuple(assumptions),
    )


def load_manifest(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        manifest = json.load(handle)
    if not isinstance(manifest, dict):
        raise ValueError("scenario manifest must be a JSON object")
    return manifest


def evaluate_manifest(path: Path) -> AssuranceReport:
    manifest = load_manifest(path)
    trace_path = path.parent / manifest["trace"]
    records = load_trace(trace_path)
    return assess_assurance(
        records,
        receipt_effect_ids=manifest.get("receipt_effect_ids", []),
        external_effect_ids=manifest.get("external_effect_ids"),
        non_bypassable_gate_attested=bool(
            manifest.get("non_bypassable_gate_attested", False)
        ),
    )


def _expected_mismatches(
    report: AssuranceReport,
    expected: dict[str, Any],
) -> list[str]:
    actual = report.to_dict()
    mismatches: list[str] = []
    for key, expected_value in expected.items():
        actual_value = actual.get(key)
        if isinstance(actual_value, tuple):
            actual_value = list(actual_value)
        if actual_value != expected_value:
            mismatches.append(
                f"{key}: expected {expected_value!r}, got {actual_value!r}"
            )
    return mismatches


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Evaluate T-Trace validity separately from capture assurance"
    )
    parser.add_argument("manifest", help="Path to an OpenPoC scenario manifest")
    args = parser.parse_args()

    manifest_path = Path(args.manifest)
    try:
        manifest = load_manifest(manifest_path)
        report = evaluate_manifest(manifest_path)
    except Exception as exc:
        print(json.dumps({"error": str(exc)}, indent=2))
        return 1

    print(json.dumps(report.to_dict(), indent=2))

    expected = manifest.get("expected")
    if isinstance(expected, dict):
        mismatches = _expected_mismatches(report, expected)
        if mismatches:
            print("EXPECTED RESULT MISMATCH")
            for mismatch in mismatches:
                print(f"  - {mismatch}")
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
