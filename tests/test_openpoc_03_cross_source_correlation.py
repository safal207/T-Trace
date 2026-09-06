import json
import subprocess
import sys
from pathlib import Path

import pytest

from openpoc.verify_cross_source import (
    assess_cross_source,
    evaluate_manifest,
    load_trace,
    load_manifest,
    _expected_mismatches,
)

ROOT = Path(__file__).resolve().parents[1]
SCENARIOS = ROOT / "examples" / "openpoc-03"
TRACE = SCENARIOS / "counterpart-omission.ttrace.jsonl"
REQUIRED_SIDES = {"sender": "agent-a", "receiver": "service-b"}
WINDOW_START = "2026-08-27T10:00:00Z"
AUDIT_CUTOFF = "2026-08-27T10:02:00Z"


def _assess(records, *, finality=True, cutoff=AUDIT_CUTOFF):
    return assess_cross_source(
        records,
        required_sides=REQUIRED_SIDES,
        window_start=WINDOW_START,
        audit_cutoff=cutoff,
        snapshots_final_at_cutoff=finality,
    )


def test_missing_counterpart_violates_pair_scope_not_global_completeness():
    report = evaluate_manifest(SCENARIOS / "counterpart-omission.scenario.json")

    assert report.trace_valid is True
    assert report.pairwise_consistency_status == "violated"
    assert report.matched_in_supplied_snapshots == ("comm-1",)
    assert report.missing_counterparts == (
        {
            "correlation_id": "comm-2",
            "counterpart_status": "missing",
            "observed_sides": ("sender",),
            "missing_sides": ("receiver",),
        },
    )
    assert report.digest_conflicts == ()
    assert report.out_of_scope_records == ()
    assert report.global_completeness_status == "unproven"
    assert report.attribution == "undetermined"
    assert report.overall_assurance == "insufficient-for-global-completeness"
    assert report.evidence_scope == {
        "scope_kind": "supplied-snapshots-only",
        "window_start": WINDOW_START,
        "audit_cutoff": AUDIT_CUTOFF,
        "snapshots_final_at_cutoff": True,
        "required_sides": {"receiver": "service-b", "sender": "agent-a"},
        "observed_correlation_ids": ["comm-1", "comm-2"],
    }
    assert report.trust_assumptions == (
        "declared side-to-source bindings are correct",
        "snapshot finality is caller-declared, not independently authenticated",
        "record and observation timestamps use the declared comparable clock basis",
        "equal action_digest values identify the same canonical action projection",
        "correlation_id uniquely identifies the same action phase across sources",
        "the declared one-record-per-side cardinality covers retries and fan-out",
    )


def test_matching_pair_still_does_not_prove_global_completeness():
    records = load_trace(TRACE)[:2]
    report = _assess(records)

    assert report.pairwise_consistency_status == "consistent-in-supplied-snapshots"
    assert report.matched_in_supplied_snapshots == ("comm-1",)
    assert report.missing_counterparts == ()
    assert report.digest_conflicts == ()
    assert report.global_completeness_status == "unproven"
    assert report.overall_assurance == "insufficient-for-global-completeness"


def test_digest_conflict_is_distinct_from_a_missing_counterpart():
    records = load_trace(TRACE)
    records.append(
        {
            "id": "comm-2-receiver",
            "type": "sense",
            "ts": "2026-08-27T10:01:01Z",
            "observed_at": "2026-08-27T10:01:01Z",
            "thread_id": "cross-source-audit",
            "source_id": "service-b",
            "side": "receiver",
            "correlation_id": "comm-2",
            "action_digest": (
                "sha256:eb44d68a21fc27d079ba847900e49304e7d5af652d4a6230d"
                "13a1924cc52e2b3"
            ),
        }
    )

    report = _assess(records)

    assert report.pairwise_consistency_status == "violated"
    assert report.missing_counterparts == ()
    assert report.digest_conflicts == (
        {
            "correlation_id": "comm-2",
            "counterpart_status": "conflicting",
            "digests_by_side": {
                "receiver": (
                    "sha256:eb44d68a21fc27d079ba847900e49304e7d5af652d4a6230d"
                    "13a1924cc52e2b3"
                ),
                "sender": (
                    "sha256:04f79fe94c2cd897012a54e298f8b54531c95d33ae9a78382"
                    "364e27478c8e871"
                ),
            },
        },
    )
    assert report.global_completeness_status == "unproven"
    assert report.attribution == "undetermined"


def test_duplicate_side_fails_closed_instead_of_selecting_a_record():
    records = load_trace(TRACE)
    duplicate = dict(records[-1])
    duplicate["id"] = "comm-2-sender-duplicate"
    duplicate["ts"] = "2026-08-27T10:01:01Z"
    duplicate["observed_at"] = duplicate["ts"]
    records.append(duplicate)

    report = _assess(records)

    assert report.trace_valid is True
    assert report.pairwise_consistency_status == "not-evaluable"
    assert any("duplicate side" in error for error in report.correlation_errors)
    assert report.global_completeness_status == "unproven"
    assert report.attribution == "not-evaluable"


def test_unhashable_side_fails_closed_instead_of_crashing():
    records = load_trace(TRACE)
    records[0] = dict(records[0])
    records[0]["side"] = []

    report = _assess(records)

    assert report.trace_valid is True
    assert report.pairwise_consistency_status == "not-evaluable"
    assert any(
        "side must be a non-empty string" in error
        for error in report.correlation_errors
    )
    assert report.global_completeness_status == "unproven"


def test_record_after_audit_cutoff_cannot_repair_the_as_of_claim():
    records = load_trace(TRACE)
    records.append(
        {
            "id": "comm-2-receiver-late",
            "type": "sense",
            "ts": "2026-08-27T10:03:00Z",
            "observed_at": "2026-08-27T10:03:00Z",
            "thread_id": "cross-source-audit",
            "source_id": "service-b",
            "side": "receiver",
            "correlation_id": "comm-2",
            "action_digest": (
                "sha256:04f79fe94c2cd897012a54e298f8b54531c95d33ae9a78382"
                "364e27478c8e871"
            ),
        }
    )

    report = _assess(records)

    assert report.pairwise_consistency_status == "violated"
    assert report.missing_counterparts == (
        {
            "correlation_id": "comm-2",
            "counterpart_status": "missing",
            "observed_sides": ("sender",),
            "missing_sides": ("receiver",),
        },
    )
    assert report.out_of_scope_records == (
        {
            "id": "comm-2-receiver-late",
            "correlation_id": "comm-2",
            "source_id": "service-b",
            "side": "receiver",
            "ts": "2026-08-27T10:03:00Z",
            "observed_at": "2026-08-27T10:03:00Z",
            "reason": "after-audit-cutoff",
        },
    )
    assert report.correlation_errors == ()
    assert report.global_completeness_status == "unproven"


def _receiver(records, *, observed_at="2026-08-27T10:01:01Z", digest=None):
    record = dict(records[-1])
    record.update(
        id="comm-2-receiver", source_id="service-b", side="receiver",
        ts="2026-08-27T10:01:01Z", observed_at=observed_at,
    )
    if digest is not None:
        record["action_digest"] = digest
    return record


def test_old_record_received_late_does_not_repair_past_cutoff():
    records = load_trace(TRACE)
    records.append(_receiver(records, observed_at="2026-08-27T10:03:00Z"))
    past = _assess(records)
    later = _assess(records, cutoff="2026-08-27T10:03:00Z")
    assert past.pairwise_consistency_status == "violated"
    assert past.out_of_scope_records[0]["reason"] == "observed-after-audit-cutoff"
    assert later.pairwise_consistency_status == "consistent-in-supplied-snapshots"
    assert later.matched_in_supplied_snapshots == ("comm-1", "comm-2")
    assert later.global_completeness_status == "unproven"


@pytest.mark.parametrize("record_count", [2, 3])
def test_nonfinal_snapshot_cannot_establish_final_pairwise_result(record_count):
    report = _assess(load_trace(TRACE)[:record_count], finality=False)
    assert report.pairwise_consistency_status == "insufficient-snapshot-finality"
    assert report.global_completeness_status == "unproven"
    if record_count == 3:
        assert report.missing_counterparts[0]["counterpart_status"] == "pending-finality"


def test_presented_digest_conflict_is_visible_even_without_finality():
    records = load_trace(TRACE)
    records.append(_receiver(records, digest="sha256:" + "f" * 64))
    report = _assess(records, finality=False)
    assert report.pairwise_consistency_status == "violated"
    assert report.digest_conflicts[0]["correlation_id"] == "comm-2"
    assert report.attribution == "undetermined"


def test_audit_cutoff_is_inclusive_and_offsets_are_compared_as_instants():
    records = load_trace(TRACE)
    records.append(_receiver(records, observed_at="2026-08-27T13:02:00+03:00"))
    assert _assess(records).matched_in_supplied_snapshots == ("comm-1", "comm-2")


@pytest.mark.parametrize("value", [True, False, 0, 1.5, float("nan"), float("inf"),
                                  "", "2026-08-27", "2026-08-27T10:02:00"])
@pytest.mark.parametrize("field", ["window_start", "audit_cutoff"])
def test_comparison_requires_explicit_finite_zoned_times(field, value):
    arguments = dict(
        required_sides=REQUIRED_SIDES, window_start=WINDOW_START,
        audit_cutoff=AUDIT_CUTOFF, snapshots_final_at_cutoff=True,
    )
    arguments[field] = value
    with pytest.raises(ValueError, match="timestamp"):
        assess_cross_source(load_trace(TRACE), **arguments)


@pytest.mark.parametrize("value", [None, 0, 1, "true", [], {}])
def test_snapshot_finality_is_not_coerced(value):
    with pytest.raises(ValueError, match="JSON boolean"):
        _assess(load_trace(TRACE), finality=value)


@pytest.mark.parametrize("field,value", [
    ("ts", True), ("ts", float("nan")), ("ts", float("inf")),
    ("type", []), ("type", {}),
])
def test_malformed_envelope_fails_closed_without_crashing(field, value):
    records = load_trace(TRACE)
    records[0][field] = value
    report = _assess(records)
    assert report.trace_valid is False
    assert report.pairwise_consistency_status == "invalid-trace"


@pytest.mark.parametrize("value", [None, True, 1, "2026-08-27T10:00:00",
                                  "2026-08-27T09:59:00Z"])
def test_invalid_observation_time_does_not_get_inferred(value):
    records = load_trace(TRACE)
    records[0]["observed_at"] = value
    report = _assess(records)
    assert report.pairwise_consistency_status == "not-evaluable"
    assert any("observed_at" in error for error in report.correlation_errors)


def test_unknown_profile_field_is_rejected_even_outside_window():
    records = load_trace(TRACE)
    records.append(_receiver(records, observed_at="2026-08-27T10:03:00Z"))
    records[-1]["unexpected"] = "value"
    assert _assess(records).pairwise_consistency_status == "not-evaluable"


def test_missing_observation_time_is_a_profile_error():
    records = load_trace(TRACE)
    del records[0]["observed_at"]
    assert _assess(records).pairwise_consistency_status == "not-evaluable"


def test_expected_verdict_comparison_preserves_json_scalar_types():
    report = _assess(load_trace(TRACE))
    assert _expected_mismatches(report, {"trace_valid": True}) == []
    assert _expected_mismatches(report, {"trace_valid": 1})
    assert _expected_mismatches(report, {"made_up": True})


@pytest.mark.parametrize("raw", [
    '{"schema":"one","schema":"two"}', '{"value":NaN}',
    '{"value":Infinity}', '{"value":1e9999}',
])
def test_manifest_json_rejects_duplicate_or_nonfinite_values(tmp_path, raw):
    path = tmp_path / "scenario.json"
    path.write_text(raw, encoding="utf-8")
    with pytest.raises(ValueError):
        load_manifest(path)


@pytest.mark.parametrize("change", [
    {"schema": "unsupported/v2"}, {"extra": True}, {"expected": []},
])
def test_manifest_rejects_unsupported_contract_fields(tmp_path, change):
    manifest = json.loads((SCENARIOS / "counterpart-omission.scenario.json").read_text())
    manifest.update(change)
    path = tmp_path / "scenario.json"
    path.write_text(json.dumps(manifest), encoding="utf-8")
    with pytest.raises(ValueError):
        load_manifest(path)


@pytest.mark.parametrize("trace_path", ["../elsewhere.jsonl", "/absolute.jsonl",
                                       "C:/absolute.jsonl", "sub\\trace.jsonl"])
def test_trace_path_must_stay_in_the_scenario_directory(tmp_path, trace_path):
    manifest = json.loads((SCENARIOS / "counterpart-omission.scenario.json").read_text())
    manifest["trace"] = trace_path
    path = tmp_path / "scenario.json"
    path.write_text(json.dumps(manifest), encoding="utf-8")
    with pytest.raises(ValueError, match="path|directory"):
        evaluate_manifest(path)


def test_input_byte_and_record_limits_are_enforced(tmp_path, monkeypatch):
    import openpoc.verify_cross_source as verifier

    monkeypatch.setattr(verifier, "MAX_INPUT_BYTES", 16)
    path = tmp_path / "trace.jsonl"
    path.write_text(" " * 17, encoding="utf-8")
    with pytest.raises(ValueError, match="bytes"):
        load_trace(path)
    monkeypatch.setattr(verifier, "MAX_INPUT_BYTES", 4096)
    monkeypatch.setattr(verifier, "MAX_RECORDS", 1)
    path.write_text('{}\n{}\n', encoding="utf-8")
    with pytest.raises(ValueError, match="records"):
        load_trace(path)
    with pytest.raises(ValueError, match="records"):
        _assess([{}, {}])


@pytest.mark.parametrize("scenario,status", [
    ("counterpart-omission.scenario.json", "violated"),
    ("nonfinal-snapshots.scenario.json", "insufficient-snapshot-finality"),
    ("delayed-observation.scenario.json", "violated"),
])
def test_public_cli_reports_expected_bounded_verdict(scenario, status):
    result = subprocess.run(
        [sys.executable, "-m", "openpoc.verify_cross_source", str(SCENARIOS / scenario)],
        cwd=ROOT, capture_output=True, text=True, check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    report = json.loads(result.stdout)
    assert report["pairwise_consistency_status"] == status
    assert report["global_completeness_status"] == "unproven"
