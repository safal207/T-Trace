from __future__ import annotations

from copy import deepcopy
from dataclasses import replace

import pytest

from ttrace.lineage_compaction import (
    LINEAGE_COMPACTION_REASON,
    ZERO_SHA256,
    advance_lineage_accumulator,
    build_seed_lineage_accumulator,
    validate_active_lineage_tip,
    validate_lineage_accumulator,
    validate_lineage_compaction,
)
from ttrace.portable_causality import (
    BranchEvidence,
    ReconciliationVote,
    build_branch_tip,
    digest_json,
    make_state_ref,
    reconcile_two_branches,
)


def _sha(label: str) -> str:
    return digest_json({"label": label})


def _branches(common: dict, cycle: int):
    shared = {
        "from_state_ref_sha256": digest_json(common),
        "branch_contract_sha256": _sha("branch-contract"),
        "authorization_contract_sha256": _sha("branch-authorization"),
        "trust_domain": common["trust_domain"],
    }
    left = BranchEvidence(
        verified=True,
        provider_id=f"provider-{cycle}-left",
        authority_id=f"authority-{cycle}-left",
        provenance_sha256=_sha(f"branch-{cycle}-left-proof"),
        logical_branch_id=f"cycle-{cycle}-left",
        to_semantic_state_sha256=_sha(f"cycle-{cycle}-left-state"),
        **shared,
    )
    right = BranchEvidence(
        verified=True,
        provider_id=f"provider-{cycle}-right",
        authority_id=f"authority-{cycle}-right",
        provenance_sha256=_sha(f"branch-{cycle}-right-proof"),
        logical_branch_id=f"cycle-{cycle}-right",
        to_semantic_state_sha256=_sha(f"cycle-{cycle}-right-state"),
        **shared,
    )
    return left, right


def _votes(common: dict, branches, cycle: int):
    target = _sha(f"cycle-{cycle}-reconciled-state")
    result = []
    for side, branch in zip(("left", "right"), branches):
        tip = build_branch_tip(common, branch)
        result.append(
            ReconciliationVote(
                verified=True,
                provider_id=branch.provider_id,
                authority_id=branch.authority_id,
                provenance_sha256=_sha(f"vote-{cycle}-{side}-proof"),
                trust_domain=branch.trust_domain,
                logical_reconciliation_id=f"cycle-{cycle}-reconcile",
                branch_ref_sha256=digest_json(tip["branch_ref"]),
                branch_state_ref_sha256=digest_json(tip["state_ref"]),
                branch_tip_sha256=digest_json(tip),
                target_semantic_state_sha256=target,
                reconciliation_contract_sha256=_sha("reconciliation-contract"),
                authorization_contract_sha256=_sha(
                    "reconciliation-authorization"
                ),
            )
        )
    return tuple(result)


def _first_cycle():
    common = make_state_ref(
        trust_domain="example.procurement",
        logical_state_id="authorization-state",
        causal_epoch=0,
        semantic_state_sha256=_sha("epoch-0"),
    )
    branches = _branches(common, 1)
    votes = _votes(common, branches, 1)
    reconciliation = reconcile_two_branches(common, branches, votes)
    assert reconciliation.verified
    accumulator = build_seed_lineage_accumulator(
        common,
        reconciliation,
        accumulator_contract_sha256=_sha("accumulator-contract"),
        authorization_contract_sha256=_sha("accumulator-authorization"),
    )
    return common, branches, votes, reconciliation, accumulator


def _advance(accumulator: dict, common: dict, cycle: int):
    branches = _branches(common, cycle)
    votes = _votes(common, branches, cycle)
    agreement = advance_lineage_accumulator(
        previous_accumulator=accumulator,
        common_state_ref=common,
        branches=branches,
        votes=votes,
    )
    return branches, votes, agreement


def test_seed_accumulator_is_fixed_shape_and_bound_to_cycle_one() -> None:
    common, _, _, reconciliation, accumulator = _first_cycle()
    assert validate_lineage_accumulator(accumulator)
    assert accumulator["completed_reconciliation_cycles"] == 1
    assert accumulator["current_causal_epoch"] == 2
    assert accumulator["previous_accumulator_sha256"] == ZERO_SHA256
    assert accumulator["previous_lineage_root_sha256"] == ZERO_SHA256
    assert len(accumulator) == 13
    assert validate_active_lineage_tip(accumulator, common, reconciliation)


def test_second_reconciliation_advances_root_without_growing_shape() -> None:
    _, _, _, first, seed = _first_cycle()
    assert first.reconciled_state_ref is not None
    _, _, second = _advance(seed, first.reconciled_state_ref, 2)
    assert second.verified is True
    assert second.reason == LINEAGE_COMPACTION_REASON
    assert second.lineage_accumulator is not None
    assert second.receipt is not None
    assert second.lineage_accumulator["completed_reconciliation_cycles"] == 2
    assert second.lineage_accumulator["current_causal_epoch"] == 4
    assert set(second.lineage_accumulator) == set(seed)
    assert len(second.lineage_accumulator) == 13
    assert second.receipt["accumulator_shape_stable"] is True
    assert second.receipt["raw_ancestry_embedded"] is False
    assert second.receipt["raw_provider_evidence_embedded"] is False


def test_third_cycle_uses_only_compacted_active_tip() -> None:
    _, _, _, first, seed = _first_cycle()
    assert first.reconciled_state_ref is not None
    _, _, second = _advance(seed, first.reconciled_state_ref, 2)
    assert second.verified and second.lineage_accumulator is not None
    assert second.reconciliation is not None
    assert second.reconciliation.reconciled_state_ref is not None

    _, _, third = _advance(
        second.lineage_accumulator,
        second.reconciliation.reconciled_state_ref,
        3,
    )
    assert third.verified is True
    assert third.lineage_accumulator is not None
    assert third.lineage_accumulator["completed_reconciliation_cycles"] == 3
    assert third.lineage_accumulator["current_causal_epoch"] == 6
    assert len(third.lineage_accumulator) == len(seed)


def test_branch_input_order_does_not_change_second_cycle_bytes() -> None:
    _, _, _, first, seed = _first_cycle()
    assert first.reconciled_state_ref is not None
    common = first.reconciled_state_ref
    branches = _branches(common, 2)
    votes = _votes(common, branches, 2)
    forward = advance_lineage_accumulator(
        previous_accumulator=seed,
        common_state_ref=common,
        branches=branches,
        votes=votes,
    )
    reverse = advance_lineage_accumulator(
        previous_accumulator=seed,
        common_state_ref=common,
        branches=tuple(reversed(branches)),
        votes=tuple(reversed(votes)),
    )
    assert forward.verified and reverse.verified
    assert forward.to_dict() == reverse.to_dict()


@pytest.mark.parametrize(
    "field",
    [
        "trust_domain",
        "logical_state_id",
        "completed_reconciliation_cycles",
        "current_causal_epoch",
        "current_state_ref_sha256",
        "current_reconciliation_sha256",
        "previous_accumulator_sha256",
        "previous_lineage_root_sha256",
        "cycle_commitment_sha256",
        "accumulator_contract_sha256",
        "authorization_contract_sha256",
    ],
)
def test_any_root_bound_field_tamper_fails_closed(field: str) -> None:
    _, _, _, first, seed = _first_cycle()
    assert first.reconciled_state_ref is not None
    _, _, second = _advance(seed, first.reconciled_state_ref, 2)
    assert second.lineage_accumulator is not None
    tampered = deepcopy(second.lineage_accumulator)
    if field in {"completed_reconciliation_cycles", "current_causal_epoch"}:
        tampered[field] += 1
    elif field in {"trust_domain", "logical_state_id"}:
        tampered[field] = "tampered"
    else:
        tampered[field] = _sha(f"tampered-{field}")
    assert validate_lineage_accumulator(tampered) is False


def test_extra_accumulator_field_fails_closed() -> None:
    _, _, _, _, seed = _first_cycle()
    tampered = deepcopy(seed)
    tampered["unexpected"] = True
    assert validate_lineage_accumulator(tampered) is False


def test_seed_cannot_claim_previous_lineage() -> None:
    _, _, _, _, seed = _first_cycle()
    tampered = deepcopy(seed)
    tampered["previous_accumulator_sha256"] = _sha("invented-previous")
    assert validate_lineage_accumulator(tampered) is False


def test_later_cycle_cannot_drop_previous_lineage() -> None:
    _, _, _, first, seed = _first_cycle()
    assert first.reconciled_state_ref is not None
    _, _, second = _advance(seed, first.reconciled_state_ref, 2)
    assert second.lineage_accumulator is not None
    tampered = deepcopy(second.lineage_accumulator)
    tampered["previous_lineage_root_sha256"] = ZERO_SHA256
    assert validate_lineage_accumulator(tampered) is False


def test_wrong_compacted_common_state_fails_closed() -> None:
    _, _, _, first, seed = _first_cycle()
    assert first.reconciled_state_ref is not None
    wrong = dict(first.reconciled_state_ref)
    wrong["semantic_state_sha256"] = _sha("wrong-common-state")
    branches = _branches(wrong, 2)
    votes = _votes(wrong, branches, 2)
    result = advance_lineage_accumulator(
        previous_accumulator=seed,
        common_state_ref=wrong,
        branches=branches,
        votes=votes,
    )
    assert result.verified is False
    assert result.reason == "compacted_common_state_mismatch"


def test_non_divergent_second_fork_fails_closed() -> None:
    _, _, _, first, seed = _first_cycle()
    assert first.reconciled_state_ref is not None
    common = first.reconciled_state_ref
    left, right = _branches(common, 2)
    right = replace(
        right,
        to_semantic_state_sha256=left.to_semantic_state_sha256,
    )
    votes = _votes(common, (left, right), 2)
    result = advance_lineage_accumulator(
        previous_accumulator=seed,
        common_state_ref=common,
        branches=(left, right),
        votes=votes,
    )
    assert result.verified is False
    assert result.reason == "fork_semantics_not_divergent"


def test_second_cycle_vote_target_mismatch_fails_closed() -> None:
    _, _, _, first, seed = _first_cycle()
    assert first.reconciled_state_ref is not None
    common = first.reconciled_state_ref
    branches = _branches(common, 2)
    left, right = _votes(common, branches, 2)
    right = replace(right, target_semantic_state_sha256=_sha("other-target"))
    result = advance_lineage_accumulator(
        previous_accumulator=seed,
        common_state_ref=common,
        branches=branches,
        votes=(left, right),
    )
    assert result.verified is False
    assert result.reason == "reconciliation_target_mismatch"


def test_compaction_receipt_is_recomputed_not_trusted() -> None:
    _, _, _, first, seed = _first_cycle()
    assert first.reconciled_state_ref is not None
    _, _, second = _advance(seed, first.reconciled_state_ref, 2)
    assert second.reconciliation is not None
    assert second.lineage_accumulator is not None
    assert second.receipt is not None
    tampered = deepcopy(second.receipt)
    tampered["previous_lineage_committed"] = False
    assert not validate_lineage_compaction(
        previous_accumulator=seed,
        common_state_ref=first.reconciled_state_ref,
        reconciliation=second.reconciliation,
        lineage_accumulator=second.lineage_accumulator,
        receipt=tampered,
    )


def test_provider_evidence_is_absent_from_active_objects() -> None:
    _, _, _, first, seed = _first_cycle()
    assert first.reconciled_state_ref is not None
    branches, votes, second = _advance(seed, first.reconciled_state_ref, 2)
    assert second.verified
    portable = repr(second.to_dict())
    forbidden = {
        *(item.provider_id for item in branches),
        *(item.authority_id for item in branches),
        *(item.provenance_sha256 for item in branches),
        *(item.provenance_sha256 for item in votes),
    }
    assert all(value not in portable for value in forbidden)
