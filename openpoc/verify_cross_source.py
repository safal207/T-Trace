from __future__ import annotations

import argparse
import importlib.util
import json
import re
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Mapping

ROOT = Path(__file__).resolve().parents[1]
VALIDATOR_PATH = ROOT / "scripts" / "validate_ttrace.py"
DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


def _load_validator() -> Any:
    spec = importlib.util.spec_from_file_location("validate_ttrace", VALIDATOR_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load validator from {VALIDATOR_PATH}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


_VALIDATOR = _load_validator()


def _jsonable(value: Any) -> Any:
    if isinstance(value, tuple):
        return [_jsonable(item) for item in value]
    if isinstance(value, dict):
        return {key: _jsonable(item) for key, item in value.items()}
    return value


@dataclass(frozen=True)
class CrossSourceReport:
    trace_valid: bool
    pairwise_consistency_status: str
    matched_in_supplied_snapshots: tuple[str, ...]
    missing_counterparts: tuple[dict[str, Any], ...]
    digest_conflicts: tuple[dict[str, Any], ...]
    out_of_scope_records: tuple[dict[str, Any], ...]
    global_completeness_status: str
    attribution: str
    overall_assurance: str
    trace_errors: tuple[str, ...]
    correlation_errors: tuple[str, ...]
    evidence_scope: dict[str, Any]
    trust_assumptions: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return _jsonable(asdict(self))


def load_trace(path: Path) -> list[dict[str, Any]]:
    return _VALIDATOR.read_jsonl(path)


def _normalize_required_sides(
    required_sides: Mapping[str, str],
) -> dict[str, str]:
    if not isinstance(required_sides, Mapping) or len(required_sides) != 2:
        raise ValueError("required_sides must bind exactly two sides to sources")

    normalized: dict[str, str] = {}
    for side, source_id in required_sides.items():
        if not isinstance(side, str) or not side.strip():
            raise ValueError("required side names must be non-empty strings")
        if not isinstance(source_id, str) or not source_id.strip():
            raise ValueError("required source IDs must be non-empty strings")
        normalized[side] = source_id

    if len(set(normalized.values())) != 2:
        raise ValueError("the two required sides must bind distinct sources")
    return normalized


def assess_cross_source(
    records: list[dict[str, Any]],
    *,
    required_sides: Mapping[str, str],
    window_start: str,
    audit_cutoff: str,
) -> CrossSourceReport:
    """Reconcile supplied records without promoting a match to completeness.

    A missing counterpart or conflicting digest falsifies the declared
    pairwise contract for the supplied snapshots. Correlation cannot reveal an
    action omitted by both sources, so global completeness remains unproven.
    """

    normalized_sides = _normalize_required_sides(required_sides)
    side_names = tuple(sorted(normalized_sides))
    try:
        window_start_ts = _VALIDATOR.parse_ts(window_start)
        audit_cutoff_ts = _VALIDATOR.parse_ts(audit_cutoff)
    except Exception as exc:
        raise ValueError(f"invalid comparison window ({exc})") from exc
    if window_start_ts > audit_cutoff_ts:
        raise ValueError("window_start must not be after audit_cutoff")

    evidence_scope = {
        "scope_kind": "supplied-snapshots-only",
        "window_start": window_start,
        "audit_cutoff": audit_cutoff,
        "required_sides": dict(sorted(normalized_sides.items())),
        "observed_correlation_ids": [],
    }
    assumptions = (
        "declared side-to-source bindings are correct",
        "supplied snapshots are final at the declared audit cutoff",
        "equal action_digest values identify the same canonical action projection",
        "correlation_id uniquely identifies the same action phase across sources",
        "the declared one-record-per-side cardinality covers retries and fan-out",
    )

    trace_errors = tuple(_VALIDATOR.validate_records(records))
    if trace_errors:
        return CrossSourceReport(
            trace_valid=False,
            pairwise_consistency_status="invalid-trace",
            matched_in_supplied_snapshots=(),
            missing_counterparts=(),
            digest_conflicts=(),
            out_of_scope_records=(),
            global_completeness_status="unproven",
            attribution="not-evaluable",
            overall_assurance="insufficient-for-global-completeness",
            trace_errors=trace_errors,
            correlation_errors=(),
            evidence_scope=evidence_scope,
            trust_assumptions=assumptions,
        )

    records_by_correlation: dict[str, dict[str, dict[str, Any]]] = {}
    correlation_errors: list[str] = []
    out_of_scope_records: list[dict[str, Any]] = []

    for index, record in enumerate(records, start=1):
        record_ts = _VALIDATOR.parse_ts(record["ts"])
        if record_ts < window_start_ts or record_ts > audit_cutoff_ts:
            out_of_scope_records.append(
                {
                    "id": record["id"],
                    "correlation_id": record.get("correlation_id"),
                    "source_id": record.get("source_id"),
                    "side": record.get("side"),
                    "ts": record["ts"],
                    "reason": (
                        "before-window-start"
                        if record_ts < window_start_ts
                        else "after-audit-cutoff"
                    ),
                }
            )
            continue

        missing_fields = {
            "correlation_id",
            "source_id",
            "side",
            "action_digest",
        } - set(record)
        if missing_fields:
            correlation_errors.append(
                f"line {index}: missing correlation fields: {sorted(missing_fields)}"
            )
            continue

        correlation_id = record["correlation_id"]
        source_id = record["source_id"]
        side = record["side"]
        action_digest = record["action_digest"]

        if not isinstance(correlation_id, str) or not correlation_id.strip():
            correlation_errors.append(
                f"line {index}: correlation_id must be a non-empty string"
            )
            continue
        if not isinstance(side, str) or not side.strip():
            correlation_errors.append(
                f"line {index}: side must be a non-empty string"
            )
            continue
        if side not in normalized_sides:
            correlation_errors.append(
                f"line {index}: side {side!r} is not declared in required_sides"
            )
            continue
        if not isinstance(source_id, str) or not source_id.strip():
            correlation_errors.append(
                f"line {index}: source_id must be a non-empty string"
            )
            continue
        expected_source = normalized_sides[side]
        if source_id != expected_source:
            correlation_errors.append(
                f"line {index}: side {side!r} requires source_id "
                f"{expected_source!r}, got {source_id!r}"
            )
            continue
        if not isinstance(action_digest, str) or not DIGEST_RE.fullmatch(
            action_digest
        ):
            correlation_errors.append(
                f"line {index}: action_digest must be lowercase sha256:<64 hex>"
            )
            continue

        side_records = records_by_correlation.setdefault(correlation_id, {})
        if side in side_records:
            correlation_errors.append(
                f"line {index}: duplicate side {side!r} for "
                f"correlation_id {correlation_id!r}"
            )
            continue
        side_records[side] = record

    observed_ids = tuple(sorted(records_by_correlation))
    evidence_scope["observed_correlation_ids"] = list(observed_ids)

    if not observed_ids:
        correlation_errors.append("no records are available for correlation")

    if correlation_errors:
        return CrossSourceReport(
            trace_valid=True,
            pairwise_consistency_status="not-evaluable",
            matched_in_supplied_snapshots=(),
            missing_counterparts=(),
            digest_conflicts=(),
            out_of_scope_records=tuple(out_of_scope_records),
            global_completeness_status="unproven",
            attribution="not-evaluable",
            overall_assurance="insufficient-for-global-completeness",
            trace_errors=(),
            correlation_errors=tuple(correlation_errors),
            evidence_scope=evidence_scope,
            trust_assumptions=assumptions,
        )

    matched: list[str] = []
    missing_counterparts: list[dict[str, Any]] = []
    digest_conflicts: list[dict[str, Any]] = []

    for correlation_id in observed_ids:
        side_records = records_by_correlation[correlation_id]
        observed_sides = tuple(sorted(side_records))
        missing_sides = tuple(
            side for side in side_names if side not in side_records
        )
        if missing_sides:
            missing_counterparts.append(
                {
                    "correlation_id": correlation_id,
                    "counterpart_status": "missing",
                    "observed_sides": observed_sides,
                    "missing_sides": missing_sides,
                }
            )
            continue

        digests_by_side = {
            side: side_records[side]["action_digest"] for side in side_names
        }
        if len(set(digests_by_side.values())) != 1:
            digest_conflicts.append(
                {
                    "correlation_id": correlation_id,
                    "counterpart_status": "conflicting",
                    "digests_by_side": digests_by_side,
                }
            )
            continue
        matched.append(correlation_id)

    violated = bool(missing_counterparts or digest_conflicts)
    return CrossSourceReport(
        trace_valid=True,
        pairwise_consistency_status=(
            "violated" if violated else "consistent-in-supplied-snapshots"
        ),
        matched_in_supplied_snapshots=tuple(matched),
        missing_counterparts=tuple(missing_counterparts),
        digest_conflicts=tuple(digest_conflicts),
        out_of_scope_records=tuple(out_of_scope_records),
        global_completeness_status="unproven",
        attribution="undetermined" if violated else "not-applicable",
        overall_assurance="insufficient-for-global-completeness",
        trace_errors=(),
        correlation_errors=(),
        evidence_scope=evidence_scope,
        trust_assumptions=assumptions,
    )


def load_manifest(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        manifest = json.load(handle)
    if not isinstance(manifest, dict):
        raise ValueError("scenario manifest must be a JSON object")
    return manifest


def evaluate_manifest(path: Path) -> CrossSourceReport:
    manifest = load_manifest(path)
    trace_name = manifest.get("trace")
    if not isinstance(trace_name, str) or not trace_name.strip():
        raise ValueError("scenario trace must be a non-empty relative path")

    scenario_dir = path.parent.resolve()
    trace_path = (scenario_dir / trace_name).resolve()
    try:
        trace_path.relative_to(scenario_dir)
    except ValueError as exc:
        raise ValueError("scenario trace must stay inside the scenario directory") from exc

    comparison = manifest.get("comparison")
    if not isinstance(comparison, dict):
        raise ValueError("scenario comparison must be a JSON object")

    records = load_trace(trace_path)
    return assess_cross_source(
        records,
        required_sides=comparison.get("required_sides", {}),
        window_start=comparison.get("window_start", ""),
        audit_cutoff=comparison.get("audit_cutoff", ""),
    )


def _expected_mismatches(
    report: CrossSourceReport,
    expected: dict[str, Any],
) -> list[str]:
    actual = report.to_dict()
    mismatches: list[str] = []
    for key, expected_value in expected.items():
        if key not in actual:
            mismatches.append(f"{key}: unknown expected result field")
            continue
        actual_value = actual.get(key)
        if actual_value != expected_value:
            mismatches.append(
                f"{key}: expected {expected_value!r}, got {actual_value!r}"
            )
    return mismatches


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Reconcile two supplied T-Trace source snapshots"
    )
    parser.add_argument("manifest", help="Path to an OpenPoC-03 manifest")
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

    if report.pairwise_consistency_status in {"invalid-trace", "not-evaluable"}:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
