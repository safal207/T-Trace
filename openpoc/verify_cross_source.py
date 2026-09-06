from __future__ import annotations

import argparse
import importlib.util
import json
import math
import re
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Mapping

ROOT = Path(__file__).resolve().parents[1]
VALIDATOR_PATH = ROOT / "scripts" / "validate_ttrace.py"
DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
TIMESTAMP_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|[+-]\d{2}:\d{2})$"
)
MAX_INPUT_BYTES = 8 * 1024 * 1024
MAX_RECORDS = 10_000
RECORD_FIELDS = {
    "id", "type", "ts", "thread_id", "source_id", "side",
    "correlation_id", "action_digest", "observed_at",
}
COMPARISON_FIELDS = {
    "required_sides", "window_start", "audit_cutoff", "snapshots_final_at_cutoff",
}


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


def _json_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON field: {key}")
        result[key] = value
    return result


def _reject_constant(value: str) -> Any:
    raise ValueError(f"non-finite JSON constant: {value}")


def _json_float(value: str) -> float:
    parsed = float(value)
    if not math.isfinite(parsed):
        raise ValueError("JSON number is outside the finite range")
    return parsed


def _read_bounded(path: Path) -> str:
    with path.open("rb") as handle:
        raw = handle.read(MAX_INPUT_BYTES + 1)
    if len(raw) > MAX_INPUT_BYTES:
        raise ValueError(f"input exceeds {MAX_INPUT_BYTES} bytes")
    return raw.decode("utf-8")


def _parse_json(raw: str) -> Any:
    try:
        return json.loads(
            raw, object_pairs_hook=_json_pairs, parse_constant=_reject_constant,
            parse_float=_json_float,
        )
    except RecursionError as exc:
        raise ValueError("JSON nesting exceeds the supported parser limit") from exc


def load_trace(path: Path) -> list[dict[str, Any]]:
    records = []
    for line in _read_bounded(path).splitlines():
        if line.strip():
            records.append(_parse_json(line))
            if len(records) > MAX_RECORDS:
                raise ValueError(f"trace exceeds {MAX_RECORDS} records")
    return records


def _timestamp(value: Any, *, field: str, allow_epoch: bool = False) -> float:
    if allow_epoch and type(value) in (int, float):
        try:
            parsed = float(value)
        except OverflowError as exc:
            raise ValueError(f"{field} is outside the supported epoch range") from exc
        if math.isfinite(parsed):
            return parsed
    if isinstance(value, str) and TIMESTAMP_RE.fullmatch(value):
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()
            if math.isfinite(parsed):
                return parsed
        except (ValueError, OverflowError, OSError):
            pass
    raise ValueError(f"{field} must be a finite timestamp with an explicit timezone")


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
    snapshots_final_at_cutoff: bool,
) -> CrossSourceReport:
    """Reconcile supplied records without promoting a match to completeness.

    A conflicting digest falsifies the declared pairwise contract. An absent
    counterpart does so only under explicitly declared snapshot finality;
    otherwise the final comparison remains insufficient. Correlation cannot
    reveal an action omitted by both sources, so completeness stays unproven.
    """

    normalized_sides = _normalize_required_sides(required_sides)
    side_names = tuple(sorted(normalized_sides))
    if type(snapshots_final_at_cutoff) is not bool:
        raise ValueError("snapshots_final_at_cutoff must be a JSON boolean")
    if not isinstance(records, list) or len(records) > MAX_RECORDS:
        raise ValueError(f"records must be an array of at most {MAX_RECORDS} records")
    window_start_ts = _timestamp(window_start, field="window_start")
    audit_cutoff_ts = _timestamp(audit_cutoff, field="audit_cutoff")
    if window_start_ts > audit_cutoff_ts:
        raise ValueError("window_start must not be after audit_cutoff")

    evidence_scope = {
        "scope_kind": "supplied-snapshots-only",
        "window_start": window_start,
        "audit_cutoff": audit_cutoff,
        "snapshots_final_at_cutoff": snapshots_final_at_cutoff,
        "required_sides": dict(sorted(normalized_sides.items())),
        "observed_correlation_ids": [],
    }
    assumptions = (
        "declared side-to-source bindings are correct",
        "snapshot finality is caller-declared, not independently authenticated",
        "record and observation timestamps use the declared comparable clock basis",
        "equal action_digest values identify the same canonical action projection",
        "correlation_id uniquely identifies the same action phase across sources",
        "the declared one-record-per-side cardinality covers retries and fan-out",
    )

    envelope_errors = []
    for index, record in enumerate(records, start=1):
        if isinstance(record, dict):
            if "type" in record and not isinstance(record["type"], str):
                envelope_errors.append(f"line {index}: type must be a string")
            if "ts" in record:
                try:
                    _timestamp(record["ts"], field="ts", allow_epoch=True)
                except ValueError as exc:
                    envelope_errors.append(f"line {index}: {exc}")
    trace_errors = tuple(envelope_errors or _VALIDATOR.validate_records(records))
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
        missing_fields = RECORD_FIELDS - set(record)
        unknown_fields = set(record) - RECORD_FIELDS
        if missing_fields:
            correlation_errors.append(
                f"line {index}: missing correlation fields: {sorted(missing_fields)}"
            )
            continue
        if unknown_fields:
            correlation_errors.append(
                f"line {index}: unknown profile fields: {sorted(map(str, unknown_fields))}"
            )
            continue

        record_ts = _timestamp(record["ts"], field="ts", allow_epoch=True)
        try:
            observed_ts = _timestamp(record["observed_at"], field="observed_at")
        except ValueError as exc:
            correlation_errors.append(f"line {index}: {exc}")
            continue
        if observed_ts < record_ts:
            correlation_errors.append(f"line {index}: observed_at precedes ts")
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

        reason = None
        if record_ts < window_start_ts:
            reason = "before-window-start"
        elif record_ts > audit_cutoff_ts:
            reason = "after-audit-cutoff"
        elif observed_ts > audit_cutoff_ts:
            reason = "observed-after-audit-cutoff"
        if reason:
            out_of_scope_records.append(
                {
                    "id": record["id"],
                    "correlation_id": correlation_id,
                    "source_id": source_id,
                    "side": side,
                    "ts": record["ts"],
                    "observed_at": record["observed_at"],
                    "reason": reason,
                }
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
                    "counterpart_status": (
                        "missing" if snapshots_final_at_cutoff else "pending-finality"
                    ),
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

    violated = bool(digest_conflicts or (missing_counterparts and snapshots_final_at_cutoff))
    if violated:
        pairwise_status = "violated"
    elif not snapshots_final_at_cutoff:
        pairwise_status = "insufficient-snapshot-finality"
    else:
        pairwise_status = "consistent-in-supplied-snapshots"
    return CrossSourceReport(
        trace_valid=True,
        pairwise_consistency_status=pairwise_status,
        matched_in_supplied_snapshots=tuple(matched),
        missing_counterparts=tuple(missing_counterparts),
        digest_conflicts=tuple(digest_conflicts),
        out_of_scope_records=tuple(out_of_scope_records),
        global_completeness_status="unproven",
        attribution=(
            "undetermined" if violated or not snapshots_final_at_cutoff else "not-applicable"
        ),
        overall_assurance="insufficient-for-global-completeness",
        trace_errors=(),
        correlation_errors=(),
        evidence_scope=evidence_scope,
        trust_assumptions=assumptions,
    )


def load_manifest(path: Path) -> dict[str, Any]:
    manifest = _parse_json(_read_bounded(path))
    if not isinstance(manifest, dict):
        raise ValueError("scenario manifest must be a JSON object")
    if set(manifest) - {"schema", "scenario", "trace", "comparison", "expected"}:
        raise ValueError("unknown scenario manifest field")
    if manifest.get("schema") != "ttrace.openpoc-cross-source/v1":
        raise ValueError("unsupported cross-source scenario schema")
    if not isinstance(manifest.get("scenario"), str) or not manifest["scenario"].strip():
        raise ValueError("scenario name must be a non-empty string")
    if "expected" in manifest and not isinstance(manifest["expected"], dict):
        raise ValueError("expected must be a JSON object")
    return manifest


def evaluate_manifest(path: Path) -> CrossSourceReport:
    manifest = load_manifest(path)
    trace_name = manifest.get("trace")
    if not isinstance(trace_name, str) or not trace_name.strip():
        raise ValueError("scenario trace must be a non-empty relative path")
    if Path(trace_name).is_absolute() or "\\" in trace_name or ":" in trace_name:
        raise ValueError("scenario trace must use a relative portable path")

    scenario_dir = path.parent.resolve()
    trace_path = (scenario_dir / trace_name).resolve()
    try:
        trace_path.relative_to(scenario_dir)
    except ValueError as exc:
        raise ValueError("scenario trace must stay inside the scenario directory") from exc

    comparison = manifest.get("comparison")
    if not isinstance(comparison, dict):
        raise ValueError("scenario comparison must be a JSON object")
    if set(comparison) != COMPARISON_FIELDS:
        raise ValueError("comparison must contain exactly the supported fields")

    records = load_trace(trace_path)
    return assess_cross_source(
        records,
        required_sides=comparison.get("required_sides", {}),
        window_start=comparison.get("window_start", ""),
        audit_cutoff=comparison.get("audit_cutoff", ""),
        snapshots_final_at_cutoff=comparison["snapshots_final_at_cutoff"],
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
        if json.dumps(actual_value, sort_keys=True, allow_nan=False) != json.dumps(
            expected_value, sort_keys=True, allow_nan=False
        ):
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
