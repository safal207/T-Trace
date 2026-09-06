from __future__ import annotations

from copy import deepcopy

from ttrace.lineage_consistency import (
    LINEAGE_EQUIVOCATION_NOT_PROVEN_REASON,
    build_lineage_anchor_statement,
    detect_lineage_anchor_equivocation,
    validate_lineage_anchor_statement,
    verify_lineage_root_consistency,
)
from ttrace.portable_causality import digest_json

from test_lineage_consistency import _package, _statements


def _sha(label: str) -> str:
    return digest_json({"label": label})


def test_boolean_old_frontier_start_is_rejected() -> None:
    package = deepcopy(_package(3, 9))
    package["consistency_proof"]["old_frontier"][0]["start"] = False
    decision = verify_lineage_root_consistency(package)
    assert decision.verified is False
    assert decision.reason == "consistency_old_frontier_invalid"


def test_boolean_append_block_start_is_rejected() -> None:
    package = deepcopy(_package(3, 9))
    package["consistency_proof"]["append_blocks"][0]["start"] = False
    decision = verify_lineage_root_consistency(package)
    assert decision.verified is False
    assert decision.reason == "consistency_append_blocks_invalid"


def test_statement_binds_full_membership_context() -> None:
    package = _package(3, 9)
    endpoint = package["old_endpoint"]
    statement, _ = _statements(package)
    anchor = endpoint["membership_anchor"]
    assert statement["tree_algorithm"] == anchor["tree_algorithm"]
    assert statement["membership_contract_sha256"] == anchor[
        "membership_contract_sha256"
    ]

    tampered = dict(statement)
    tampered["membership_contract_sha256"] = _sha(
        "other-membership-contract"
    )
    assert not validate_lineage_anchor_statement(
        tampered,
        anchor,
        endpoint["current_accumulator"],
    )


def test_membership_contract_migration_is_not_false_equivocation() -> None:
    package = _package(3, 9)
    endpoint = package["new_endpoint"]
    _, canonical = _statements(package)

    migrated_anchor = deepcopy(endpoint["membership_anchor"])
    migrated_anchor["membership_contract_sha256"] = _sha(
        "migrated-membership-contract"
    )
    migrated = build_lineage_anchor_statement(
        migrated_anchor,
        endpoint["current_accumulator"],
        verified=True,
        authority_id=canonical["authority_id"],
        statement_sequence=canonical["statement_sequence"],
        previous_statement_sha256=canonical[
            "previous_statement_sha256"
        ],
        statement_provenance_sha256=_sha(
            "migrated-contract-statement-proof"
        ),
    )
    decision = detect_lineage_anchor_equivocation(
        endpoint["membership_anchor"],
        endpoint["current_accumulator"],
        canonical,
        migrated_anchor,
        endpoint["current_accumulator"],
        migrated,
    )
    assert decision.verified is True
    assert decision.equivocation_detected is False
    assert decision.reason == LINEAGE_EQUIVOCATION_NOT_PROVEN_REASON
    assert decision.evidence["membership_contract_sha256"] is None
    assert decision.evidence["tree_algorithm"] is None
    assert decision.evidence["authorization_contract_sha256"] is None
