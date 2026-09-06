from __future__ import annotations

from copy import deepcopy

import pytest

from ttrace.lineage_compaction import (
    advance_lineage_accumulator,
    build_seed_lineage_accumulator,
)
from ttrace.lineage_consistency import (
    GLOBAL_NON_EQUIVOCATION_STATUS,
    LINEAGE_AUTHORIZED_CONSISTENCY_REASON,
    LINEAGE_EQUIVOCATION_DETECTED_REASON,
    LINEAGE_EQUIVOCATION_NOT_PROVEN_REASON,
    LINEAGE_ROOT_CONSISTENCY_REASON,
    build_lineage_anchor_statement,
    build_lineage_root_consistency_package,
    detect_lineage_anchor_equivocation,
    validate_lineage_anchor_statement,
    verify_authorized_lineage_root_consistency,
    verify_lineage_root_consistency,
)
from ttrace.portable_causality import (
    BranchEvidence,
    ReconciliationVote,
    build_branch_tip,
    digest_json,
    make_state_ref,
    reconcile_two_branches,
)


MEMBERSHIP_CONTRACT = digest_json({"contract": "membership/v0.1"})
AUTHORIZATION_CONTRACT = digest_json({"contract": "authorization/v0.1"})


def _sha(label: str) -> str:
    return digest_json({"label": label})


def _branches(common: dict, cycle: int, salt: str = "canonical"):
    shared = {
        "from_state_ref_sha256": digest_json(common),
        "branch_contract_sha256": _sha(f"{salt}-branch-contract"),
        "authorization_contract_sha256": _sha(
            f"{salt}-branch-authorization"
        ),
        "trust_domain": common["trust_domain"],
    }
    return (
        BranchEvidence(
            verified=True,
            provider_id=f"{salt}-provider-{cycle}-left",
            authority_id=f"{salt}-authority-{cycle}-left",
            provenance_sha256=_sha(
                f"{salt}-branch-{cycle}-left-proof"
            ),
            logical_branch_id=f"{salt}-cycle-{cycle}-left",
            to_semantic_state_sha256=_sha(
                f"{salt}-cycle-{cycle}-left-state"
            ),
            **shared,
        ),
        BranchEvidence(
            verified=True,
            provider_id=f"{salt}-provider-{cycle}-right",
            authority_id=f"{salt}-authority-{cycle}-right",
            provenance_sha256=_sha(
                f"{salt}-branch-{cycle}-right-proof"
            ),
            logical_branch_id=f"{salt}-cycle-{cycle}-right",
            to_semantic_state_sha256=_sha(
                f"{salt}-cycle-{cycle}-right-state"
            ),
            **shared,
        ),
    )


def _votes(common: dict, branches, cycle: int, salt: str = "canonical"):
    target = _sha(f"{salt}-cycle-{cycle}-reconciled-state")
    votes = []
    for side, branch in zip(("left", "right"), branches):
        tip = build_branch_tip(common, branch)
        votes.append(
            ReconciliationVote(
                verified=True,
                provider_id=branch.provider_id,
                authority_id=branch.authority_id,
                provenance_sha256=_sha(
                    f"{salt}-vote-{cycle}-{side}-proof"
                ),
                trust_domain=branch.trust_domain,
                logical_reconciliation_id=(
                    f"{salt}-cycle-{cycle}-reconcile"
                ),
                branch_ref_sha256=digest_json(tip["branch_ref"]),
                branch_state_ref_sha256=digest_json(tip["state_ref"]),
                branch_tip_sha256=digest_json(tip),
                target_semantic_state_sha256=target,
                reconciliation_contract_sha256=_sha(
                    f"{salt}-reconciliation-contract"
                ),
                authorization_contract_sha256=_sha(
                    f"{salt}-reconciliation-authorization"
                ),
            )
        )
    return tuple(votes)


def _records(cycle_count: int, salt: str = "canonical"):
    common = make_state_ref(
        trust_domain="example.procurement",
        logical_state_id="authorization-state",
        causal_epoch=0,
        semantic_state_sha256=_sha(f"{salt}-epoch-0"),
    )
    records = []
    accumulator = None
    for cycle in range(1, cycle_count + 1):
        branches = _branches(common, cycle, salt)
        votes = _votes(common, branches, cycle, salt)
        reconciliation = reconcile_two_branches(common, branches, votes)
        assert reconciliation.verified is True
        assert reconciliation.reconciled_state_ref is not None
        if cycle == 1:
            accumulator = build_seed_lineage_accumulator(
                common,
                reconciliation,
                accumulator_contract_sha256=_sha(
                    f"{salt}-accumulator-contract"
                ),
                authorization_contract_sha256=_sha(
                    f"{salt}-accumulator-authorization"
                ),
            )
        else:
            assert accumulator is not None
            advanced = advance_lineage_accumulator(
                previous_accumulator=accumulator,
                common_state_ref=common,
                branches=branches,
                votes=votes,
            )
            assert advanced.verified is True
            assert advanced.lineage_accumulator is not None
            assert advanced.reconciliation is not None
            assert advanced.reconciliation.reconciled_state_ref is not None
            accumulator = advanced.lineage_accumulator
            reconciliation = advanced.reconciliation
        records.append(
            {
                "cycle_index": cycle,
                "common_state_ref": common,
                "reconciliation": reconciliation.to_dict(),
                "lineage_accumulator": accumulator,
            }
        )
        common = reconciliation.reconciled_state_ref
    assert accumulator is not None
    return records, accumulator


def _package(old_size: int = 2, new_size: int = 7):
    records, accumulator = _records(new_size)
    return build_lineage_root_consistency_package(
        records[:old_size],
        records[old_size - 1]["lineage_accumulator"],
        records,
        accumulator,
        membership_contract_sha256=MEMBERSHIP_CONTRACT,
        authorization_contract_sha256=AUTHORIZATION_CONTRACT,
    )


@pytest.mark.parametrize(
    ("old_size", "new_size"),
    [(1, 5), (2, 7), (3, 5), (4, 9), (7, 16), (8, 17)],
)
def test_append_only_consistency_for_multiple_tree_shapes(
    old_size: int, new_size: int
) -> None:
    package = _package(old_size, new_size)
    decision = verify_lineage_root_consistency(package)
    assert decision.verified is True
    assert decision.reason == LINEAGE_ROOT_CONSISTENCY_REASON
    assert decision.old_tree_size == old_size
    assert decision.new_tree_size == new_size
    assert decision.append_only_consistent is True
    assert decision.current_tips_membership_bound is True
    assert decision.raw_cycle_records_disclosed is False


def test_consistency_proof_discloses_hashes_not_cycle_records() -> None:
    package = _package(3, 9)
    proof_text = repr(package["consistency_proof"])
    assert "cycle_records" not in proof_text
    assert "reconciliation" not in proof_text
    assert "provider_id" not in proof_text
    assert "authority_id" not in proof_text
    assert "provenance_sha256" not in proof_text


@pytest.mark.parametrize(
    ("mutation", "reason"),
    [
        (
            lambda value: value["consistency_proof"]["old_frontier"][0].__setitem__(
                "sha256", _sha("tampered-old-frontier")
            ),
            "consistency_old_root_mismatch",
        ),
        (
            lambda value: value["consistency_proof"]["append_blocks"][0].__setitem__(
                "sha256", _sha("tampered-append-block")
            ),
            "consistency_new_root_mismatch",
        ),
        (
            lambda value: value["consistency_proof"].__setitem__(
                "append_blocks",
                value["consistency_proof"]["append_blocks"][:-1],
            ),
            "consistency_append_blocks_invalid",
        ),
        (
            lambda value: value["consistency_proof"]["append_blocks"][0].__setitem__(
                "start",
                value["consistency_proof"]["append_blocks"][0]["start"] + 1,
            ),
            "consistency_append_blocks_invalid",
        ),
        (
            lambda value: value["consistency_proof"].__setitem__(
                "old_current_cycle_sibling_path",
                value["consistency_proof"][
                    "old_current_cycle_sibling_path"
                ][:-1],
            ),
            "consistency_old_current_tip_not_bound",
        ),
        (
            lambda value: value["consistency_proof"].__setitem__(
                "new_current_cycle_sibling_path",
                value["consistency_proof"][
                    "new_current_cycle_sibling_path"
                ][:-1],
            ),
            "consistency_new_current_tip_not_bound",
        ),
        (
            lambda value: value["consistency_proof"].__setitem__(
                "schema", "other-proof/v0.1"
            ),
            "consistency_proof_schema_invalid",
        ),
        (
            lambda value: value["consistency_proof"].__setitem__(
                "extra", True
            ),
            "consistency_proof_shape_invalid",
        ),
    ],
)
def test_consistency_proof_tampering_fails_closed(mutation, reason: str) -> None:
    package = deepcopy(_package(3, 9))
    mutation(package)
    decision = verify_lineage_root_consistency(package)
    assert decision.verified is False
    assert decision.reason == reason


def test_membership_contract_drift_fails_closed() -> None:
    package = deepcopy(_package(2, 7))
    package["new_endpoint"]["membership_anchor"][
        "membership_contract_sha256"
    ] = _sha("other-membership-contract")
    package["consistency_proof"]["new_anchor_sha256"] = digest_json(
        package["new_endpoint"]["membership_anchor"]
    )
    decision = verify_lineage_root_consistency(package)
    assert decision.verified is False
    assert decision.reason == "consistency_membership_contract_mismatch"


def test_same_size_is_not_an_extension() -> None:
    records, accumulator = _records(4)
    with pytest.raises(ValueError, match="consistency_tree_not_extended"):
        build_lineage_root_consistency_package(
            records,
            accumulator,
            records,
            accumulator,
            membership_contract_sha256=MEMBERSHIP_CONTRACT,
            authorization_contract_sha256=AUTHORIZATION_CONTRACT,
        )


def test_different_prefix_is_rejected_by_builder() -> None:
    old_records, old_accumulator = _records(2, "old")
    new_records, new_accumulator = _records(6, "new")
    with pytest.raises(ValueError, match="consistency_prefix_mismatch"):
        build_lineage_root_consistency_package(
            old_records,
            old_accumulator,
            new_records,
            new_accumulator,
            membership_contract_sha256=MEMBERSHIP_CONTRACT,
            authorization_contract_sha256=AUTHORIZATION_CONTRACT,
        )


def _statements(package):
    old_endpoint = package["old_endpoint"]
    new_endpoint = package["new_endpoint"]
    old_statement = build_lineage_anchor_statement(
        old_endpoint["membership_anchor"],
        old_endpoint["current_accumulator"],
        verified=True,
        authority_id="ed25519-sha256:example-authority",
        statement_sequence=1,
        previous_statement_sha256="0" * 64,
        statement_provenance_sha256=_sha("old-statement-proof"),
    )
    new_statement = build_lineage_anchor_statement(
        new_endpoint["membership_anchor"],
        new_endpoint["current_accumulator"],
        verified=True,
        authority_id="ed25519-sha256:example-authority",
        statement_sequence=2,
        previous_statement_sha256=digest_json(old_statement),
        statement_provenance_sha256=_sha("new-statement-proof"),
    )
    return old_statement, new_statement


def test_authorized_consistency_binds_statement_chain() -> None:
    package = _package(3, 9)
    old_statement, new_statement = _statements(package)
    decision = verify_authorized_lineage_root_consistency(
        package, old_statement, new_statement
    )
    assert decision.verified is True
    assert decision.reason == LINEAGE_AUTHORIZED_CONSISTENCY_REASON
    assert decision.append_only_consistent is True
    assert decision.authority_chain_continuous is True
    assert decision.presented_equivocation_detected is False
    assert (
        decision.global_non_equivocation_status
        == GLOBAL_NON_EQUIVOCATION_STATUS
    )


def test_authorized_consistency_rejects_rebound_successor() -> None:
    package = _package(3, 9)
    old_statement, new_statement = _statements(package)
    tampered = dict(new_statement)
    tampered["previous_statement_sha256"] = _sha("other-predecessor")
    decision = verify_authorized_lineage_root_consistency(
        package, old_statement, tampered
    )
    assert decision.verified is False
    assert decision.reason == "anchor_statement_predecessor_mismatch"


def test_statement_schema_and_anchor_binding_are_exact() -> None:
    package = _package(3, 9)
    old_endpoint = package["old_endpoint"]
    old_statement, _ = _statements(package)
    assert validate_lineage_anchor_statement(
        old_statement,
        old_endpoint["membership_anchor"],
        old_endpoint["current_accumulator"],
    )
    extra = dict(old_statement)
    extra["extra"] = True
    assert not validate_lineage_anchor_statement(
        extra,
        old_endpoint["membership_anchor"],
        old_endpoint["current_accumulator"],
    )


def test_same_sequence_conflict_is_attributable_equivocation() -> None:
    package = _package(3, 9)
    new_endpoint = package["new_endpoint"]
    _, canonical = _statements(package)

    alternate_anchor = deepcopy(new_endpoint["membership_anchor"])
    alternate_anchor["cycle_commitment_merkle_root_sha256"] = _sha(
        "alternate-split-view-root"
    )
    alternate = build_lineage_anchor_statement(
        alternate_anchor,
        new_endpoint["current_accumulator"],
        verified=True,
        authority_id=canonical["authority_id"],
        statement_sequence=canonical["statement_sequence"],
        previous_statement_sha256=canonical[
            "previous_statement_sha256"
        ],
        statement_provenance_sha256=_sha(
            "alternate-statement-proof"
        ),
    )
    decision = detect_lineage_anchor_equivocation(
        new_endpoint["membership_anchor"],
        new_endpoint["current_accumulator"],
        canonical,
        alternate_anchor,
        new_endpoint["current_accumulator"],
        alternate,
    )
    assert decision.verified is True
    assert decision.equivocation_detected is True
    assert decision.reason == LINEAGE_EQUIVOCATION_DETECTED_REASON
    assert decision.evidence["detection_mode"] == "same-sequence-conflict"
    assert (
        decision.global_non_equivocation_status
        == GLOBAL_NON_EQUIVOCATION_STATUS
    )


def test_different_authorities_do_not_prove_equivocation() -> None:
    package = _package(3, 9)
    endpoint = package["new_endpoint"]
    _, first = _statements(package)
    second = build_lineage_anchor_statement(
        endpoint["membership_anchor"],
        endpoint["current_accumulator"],
        verified=True,
        authority_id="ed25519-sha256:other-authority",
        statement_sequence=first["statement_sequence"],
        previous_statement_sha256=first["previous_statement_sha256"],
        statement_provenance_sha256=_sha("other-authority-proof"),
    )
    decision = detect_lineage_anchor_equivocation(
        endpoint["membership_anchor"],
        endpoint["current_accumulator"],
        first,
        endpoint["membership_anchor"],
        endpoint["current_accumulator"],
        second,
    )
    assert decision.verified is True
    assert decision.equivocation_detected is False
    assert decision.reason == LINEAGE_EQUIVOCATION_NOT_PROVEN_REASON
    assert (
        decision.global_non_equivocation_status
        == GLOBAL_NON_EQUIVOCATION_STATUS
    )
