from pathlib import Path

from openpoc.verify_cross_source import (
    assess_cross_source,
    evaluate_manifest,
    load_trace,
)

ROOT = Path(__file__).resolve().parents[1]
SCENARIOS = ROOT / "examples" / "openpoc-03"
TRACE = SCENARIOS / "counterpart-omission.ttrace.jsonl"
REQUIRED_SIDES = {"sender": "agent-a", "receiver": "service-b"}
WINDOW_START = "2026-08-27T10:00:00Z"
AUDIT_CUTOFF = "2026-08-27T10:02:00Z"


def _assess(records):
    return assess_cross_source(
        records,
        required_sides=REQUIRED_SIDES,
        window_start=WINDOW_START,
        audit_cutoff=AUDIT_CUTOFF,
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
        "required_sides": {"receiver": "service-b", "sender": "agent-a"},
        "observed_correlation_ids": ["comm-1", "comm-2"],
    }
    assert report.trust_assumptions == (
        "declared side-to-source bindings are correct",
        "supplied snapshots are final at the declared audit cutoff",
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
            "reason": "after-audit-cutoff",
        },
    )
    assert report.correlation_errors == ()
    assert report.global_completeness_status == "unproven"
