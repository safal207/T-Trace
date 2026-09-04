import json
from pathlib import Path

import pytest

from openpoc.asqav_omission_compat import (
    CrosswalkError,
    SELECTED_VECTOR_IDS,
    UPSTREAM_COMMIT,
    canonical_payload,
    evaluate_bundle,
    verify_chain,
    verify_document_signature,
)
from openpoc.asqav_upstream_binding import (
    SourceBindingError,
    verify_upstream_binding,
)

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "examples" / "asqav-selective-omission"


def _load(relative: str) -> dict:
    return json.loads((FIXTURES / relative).read_text(encoding="utf-8"))


def _build_synthetic_upstream(tmp_path: Path) -> Path:
    upstream = tmp_path / "asqav-sdk"
    pins = _load("pins.json")

    lock_records: list[dict] = []
    for local_relative, expected in pins["files"].items():
        local_raw = (FIXTURES / local_relative).read_bytes()
        for upstream_relative in expected["upstream_paths"]:
            destination = upstream / upstream_relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(local_raw)
            lock_records.append(
                {
                    "path": upstream_relative.removeprefix(
                        "verifier/conformance-vectors/"
                    ),
                    "sha256": expected["sha256"],
                    "bytes": expected["bytes"],
                }
            )

    manifest = []
    for vector in pins["vectors"]:
        record = _load(f"{vector['id']}/expected.json")
        manifest.append({"dir": vector["id"], **record})

    manifest_path = upstream / pins["source_manifest"]
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    lock_path = upstream / pins["source_manifest_lock"]
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    lock_path.write_text(
        json.dumps({"files": lock_records}),
        encoding="utf-8",
    )
    return upstream


def test_selected_vectors_independently_agree_with_frozen_upstream():
    report = evaluate_bundle(FIXTURES)

    assert report.all_agree is True
    assert report.agree_count == 3
    assert report.pinned_file_count == 10
    assert tuple(vector.vector_id for vector in report.vectors) == SELECTED_VECTOR_IDS
    assert all(vector.signatures_valid for vector in report.vectors)
    assert all(vector.chain_valid for vector in report.vectors)


def test_silent_omission_keeps_chain_valid_without_upgrading_completeness():
    report = evaluate_bundle(FIXTURES)
    vector = report.vectors[0]

    assert vector.semantic == "silent-omission"
    assert vector.observed_state == (
        "valid-selected-two-receipt-chain-without-act-2-receipt"
    )
    assert "does not prove whether act_2 reached any signer" in vector.claim_ceiling


def test_unsigned_gap_reports_signed_marker_not_external_outage_fact():
    report = evaluate_bundle(FIXTURES)
    vector = report.vectors[1]

    assert vector.semantic == "signer-outage-observed"
    assert vector.observed_state == (
        "verified-unsigned-gap-marker-without-policy-or-execution-claim"
    )
    assert "does not independently prove a signer outage" in vector.claim_ceiling


def test_chain_emission_block_is_visible_but_gate_non_bypassability_is_external():
    report = evaluate_bundle(FIXTURES)
    vector = report.vectors[2]

    assert vector.semantic == "fail-closed-interval-observed"
    assert vector.observed_state == (
        "verified-lifecycle-denial-for-chain-emission-block"
    )
    assert "non-bypassable enforcement point" in vector.claim_ceiling


def test_mutating_signed_payload_breaks_signature():
    jwks = _load("jwks.json")
    receipt = _load("asqav-14-omitted-action-chain/receipt.json")
    receipt["payload"]["action_ref"] = "act-attacker"

    with pytest.raises(CrosswalkError, match="signature does not match"):
        verify_document_signature(receipt, jwks)


def test_mutating_chain_link_breaks_chain_even_before_semantic_mapping():
    predecessor = _load("asqav-14-omitted-action-chain/predecessor.json")
    receipt = _load("asqav-14-omitted-action-chain/receipt.json")
    receipt["payload"]["previousReceiptHash"] = "f" * 64

    with pytest.raises(CrosswalkError, match="chain link mismatch"):
        verify_chain(predecessor, receipt)


def test_non_integer_numbers_fail_closed_in_selected_canonicalizer():
    with pytest.raises(CrosswalkError, match="non-integer number"):
        canonical_payload({"amount": 1.5})


def test_raw_file_tamper_fails_the_sha_and_git_blob_pin(tmp_path: Path):
    target = tmp_path / "vectors"
    target.mkdir()

    for source in FIXTURES.rglob("*"):
        if source.is_file():
            destination = target / source.relative_to(FIXTURES)
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(source.read_bytes())

    receipt = target / "asqav-15-unsigned-gap" / "receipt.json"
    receipt.write_bytes(receipt.read_bytes() + b" ")

    with pytest.raises(CrosswalkError, match="bytes"):
        evaluate_bundle(target)


def test_exact_upstream_binding_checks_raw_manifest_and_lock_records(tmp_path: Path):
    upstream = _build_synthetic_upstream(tmp_path)

    report = verify_upstream_binding(
        FIXTURES,
        upstream,
        observed_commit=UPSTREAM_COMMIT,
    )

    assert report.verified is True
    assert report.raw_paths_compared == 12
    assert report.manifest_records_compared == 3
    assert report.lock_records_compared == 12


def test_exact_upstream_binding_rejects_raw_drift(tmp_path: Path):
    upstream = _build_synthetic_upstream(tmp_path)
    target = (
        upstream
        / "verifier/conformance-vectors/asqav-14-omitted-action-chain/receipt.json"
    )
    target.write_bytes(target.read_bytes() + b" ")

    with pytest.raises(SourceBindingError, match="raw source mismatch"):
        verify_upstream_binding(
            FIXTURES,
            upstream,
            observed_commit=UPSTREAM_COMMIT,
        )


def test_report_is_deterministic():
    first = json.dumps(evaluate_bundle(FIXTURES).to_dict(), sort_keys=True)
    second = json.dumps(evaluate_bundle(FIXTURES).to_dict(), sort_keys=True)

    assert first == second
