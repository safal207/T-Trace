from __future__ import annotations

from copy import deepcopy
import sys

import pytest

import ttrace.lineage_membership as lineage_membership

from ttrace.lineage_compaction import (
    ZERO_SHA256,
    advance_lineage_accumulator,
    build_seed_lineage_accumulator,
)
from ttrace.lineage_membership import (
    LINEAGE_MEMBERSHIP_REASON,
    LINEAGE_MEMBERSHIP_TREE_ALGORITHM,
    build_lineage_membership_anchor,
    build_selective_lineage_disclosure,
    verify_selective_lineage_disclosure,
)
from ttrace.portable_causality import (
    BranchEvidence,
    ReconciliationVote,
    build_branch_tip,
    canonical_json_bytes,
    digest_json,
    make_state_ref,
    reconcile_two_branches,
)


def _sha(label: str) -> str:
    return digest_json({"label": label})


MEMBERSHIP_CONTRACT = _sha("lineage-membership-contract-v0.1")
MEMBERSHIP_AUTHORIZATION = _sha("lineage-membership-authorization-v0.1")
ACCUMULATOR_CONTRACT = _sha("lineage-accumulator-contract-v0.1")
ACCUMULATOR_AUTHORIZATION = _sha("lineage-accumulator-authorization-v0.1")


def _branches(common: dict, cycle: int):
    shared = {
        "from_state_ref_sha256": digest_json(common),
        "branch_contract_sha256": _sha("branch-contract"),
        "authorization_contract_sha256": _sha("branch-authorization"),
        "trust_domain": common["trust_domain"],
    }
    return (
        BranchEvidence(
            verified=True,
            provider_id=f"provider-{cycle}-left",
            authority_id=f"authority-{cycle}-left",
            provenance_sha256=_sha(f"branch-{cycle}-left-proof"),
            logical_branch_id=f"cycle-{cycle}-left",
            to_semantic_state_sha256=_sha(f"cycle-{cycle}-left-state"),
            **shared,
        ),
        BranchEvidence(
            verified=True,
            provider_id=f"provider-{cycle}-right",
            authority_id=f"authority-{cycle}-right",
            provenance_sha256=_sha(f"branch-{cycle}-right-proof"),
            logical_branch_id=f"cycle-{cycle}-right",
            to_semantic_state_sha256=_sha(f"cycle-{cycle}-right-state"),
            **shared,
        ),
    )


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


def _history(count: int = 5):
    common = make_state_ref(
        trust_domain="example.procurement",
        logical_state_id="authorization-state",
        causal_epoch=0,
        semantic_state_sha256=_sha("epoch-0"),
    )
    records = []
    accumulator = None
    for cycle in range(1, count + 1):
        branches = _branches(common, cycle)
        reconciliation = reconcile_two_branches(
            common, branches, _votes(common, branches, cycle)
        )
        assert reconciliation.verified is True
        assert reconciliation.reconciled_state_ref is not None
        if cycle == 1:
            accumulator = build_seed_lineage_accumulator(
                common,
                reconciliation,
                accumulator_contract_sha256=ACCUMULATOR_CONTRACT,
                authorization_contract_sha256=ACCUMULATOR_AUTHORIZATION,
            )
        else:
            assert accumulator is not None
            advanced = advance_lineage_accumulator(
                previous_accumulator=accumulator,
                common_state_ref=common,
                branches=branches,
                votes=_votes(common, branches, cycle),
            )
            assert advanced.verified is True
            assert advanced.lineage_accumulator is not None
            assert advanced.reconciliation is not None
            reconciliation = advanced.reconciliation
            accumulator = advanced.lineage_accumulator
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


def _disclosure(count: int = 5, selected: int = 3):
    records, accumulator = _history(count)
    disclosure = build_selective_lineage_disclosure(
        records,
        accumulator,
        selected_cycle_index=selected,
        membership_contract_sha256=MEMBERSHIP_CONTRACT,
        authorization_contract_sha256=MEMBERSHIP_AUTHORIZATION,
    )
    return records, accumulator, disclosure


def test_middle_cycle_is_proved_without_disclosing_intervening_cycles() -> None:
    _, _, disclosure = _disclosure(5, 3)
    decision = verify_selective_lineage_disclosure(disclosure)
    assert decision.verified is True
    assert decision.reason == LINEAGE_MEMBERSHIP_REASON
    assert decision.disclosed_cycle_index == 3
    assert decision.sibling_hash_count == 3

    serialized = canonical_json_bytes(disclosure).decode("utf-8")
    assert "cycle-3-left" in serialized
    assert "cycle-3-right" in serialized
    for hidden in (1, 2, 4, 5):
        assert f"cycle-{hidden}-left" not in serialized
        assert f"cycle-{hidden}-right" not in serialized


def test_first_and_last_cycles_verify() -> None:
    for selected in (1, 5):
        _, _, disclosure = _disclosure(5, selected)
        assert verify_selective_lineage_disclosure(disclosure).verified is True


def test_eight_cycle_proof_has_logarithmic_path() -> None:
    _, _, disclosure = _disclosure(8, 5)
    proof = disclosure["membership_proof"]
    assert len(proof["sibling_path"]) == 3
    assert proof["tree_size"] == 8


def test_odd_last_leaf_uses_canonical_duplicate_last_rule() -> None:
    _, _, disclosure = _disclosure(5, 5)
    proof = disclosure["membership_proof"]
    assert proof["tree_algorithm"] == LINEAGE_MEMBERSHIP_TREE_ALGORITHM
    assert proof["sibling_path"][0]["side"] == "right"
    assert proof["sibling_path"][0]["sha256"] == proof["leaf_sha256"]
    assert verify_selective_lineage_disclosure(disclosure).verified is True


def test_same_size_tree_omitting_current_cycle_fails_closed() -> None:
    records, _, disclosure = _disclosure(5, 3)
    forged_commitments = [
        record["lineage_accumulator"]["cycle_commitment_sha256"]
        for record in records
    ]
    forged_commitments[-1] = _sha("omitted-current-cycle")
    forged_leaves = [
        lineage_membership._leaf_hash(index, commitment)
        for index, commitment in enumerate(forged_commitments, start=1)
    ]

    tampered = deepcopy(disclosure)
    anchor = tampered["anchor"]
    proof = tampered["membership_proof"]
    anchor["cycle_commitment_merkle_root_sha256"] = lineage_membership._merkle_root(
        forged_leaves
    )
    proof["anchor_sha256"] = digest_json(anchor)
    proof["sibling_path"] = lineage_membership._merkle_path(
        forged_leaves, proof["leaf_index"]
    )
    proof["current_cycle_sibling_path"] = lineage_membership._merkle_path(
        forged_leaves, len(forged_leaves) - 1
    )

    decision = verify_selective_lineage_disclosure(tampered)
    assert decision.verified is False
    assert decision.reason == "current_cycle_membership_path_invalid"


def test_provider_evidence_and_full_history_are_not_disclosed() -> None:
    records, _, disclosure = _disclosure(5, 2)
    serialized = canonical_json_bytes(disclosure).decode("utf-8")
    forbidden = {
        "provider_id",
        "authority_id",
        "provenance_sha256",
        "cycle_records",
        "all_cycles",
    }
    assert all(item not in serialized for item in forbidden)
    assert len(disclosure["disclosed_cycle"]) == 6
    assert len(records) == 5


@pytest.mark.parametrize(
    "mutation,reason",
    [
        (
            lambda value: value["anchor"].__setitem__(
                "cycle_commitment_merkle_root_sha256", _sha("wrong-root")
            ),
            "proof_anchor_mismatch",
        ),
        (
            lambda value: value["membership_proof"].__setitem__(
                "anchor_sha256", _sha("wrong-anchor")
            ),
            "proof_anchor_mismatch",
        ),
        (
            lambda value: value["membership_proof"].__setitem__(
                "cycle_index", 1
            ),
            "proof_cycle_index_mismatch",
        ),
        (
            lambda value: value["membership_proof"].__setitem__(
                "leaf_index", 0
            ),
            "proof_leaf_index_mismatch",
        ),
        (
            lambda value: value["membership_proof"]["sibling_path"][0].__setitem__(
                "sha256", _sha("wrong-sibling")
            ),
            "membership_path_invalid",
        ),
        (
            lambda value: value["membership_proof"]["sibling_path"][0].__setitem__(
                "side",
                "left"
                if value["membership_proof"]["sibling_path"][0]["side"] == "right"
                else "right",
            ),
            "membership_path_invalid",
        ),
        (
            lambda value: value["disclosed_cycle"]["cycle_summary"].__setitem__(
                "fork_causal_epoch", 999
            ),
            "disclosed_cycle_summary_mismatch",
        ),
        (
            lambda value: value["disclosed_cycle"].__setitem__(
                "cycle_commitment_sha256", _sha("wrong-commitment")
            ),
            "disclosed_cycle_commitment_mismatch",
        ),
        (
            lambda value: value["disclosed_cycle"]["reconciliation"][
                "branch_tips"
            ].__setitem__(
                1,
                deepcopy(
                    value["disclosed_cycle"]["reconciliation"]["branch_tips"][0]
                ),
            ),
            "disclosed_reconciliation_invalid",
        ),
        (
            lambda value: value["anchor"].__setitem__("unexpected", True),
            "membership_anchor_invalid",
        ),
    ],
)
def test_tampering_fails_closed(mutation, reason: str) -> None:
    _, _, disclosure = _disclosure(5, 3)
    tampered = deepcopy(disclosure)
    mutation(tampered)
    decision = verify_selective_lineage_disclosure(tampered)
    assert decision.verified is False
    assert decision.reason == reason


def test_membership_proof_schema_is_required_exactly() -> None:
    _, _, disclosure = _disclosure(5, 3)
    assert verify_selective_lineage_disclosure(disclosure).verified is True

    missing = deepcopy(disclosure)
    missing["membership_proof"].pop("schema")
    missing_decision = verify_selective_lineage_disclosure(missing)
    assert missing_decision.verified is False
    assert missing_decision.reason == "membership_proof_shape_invalid"

    altered = deepcopy(disclosure)
    altered["membership_proof"]["schema"] = "ttrace-lineage-membership-proof/v9.9"
    altered_decision = verify_selective_lineage_disclosure(altered)
    assert altered_decision.verified is False
    assert altered_decision.reason == "membership_proof_schema_invalid"


def test_truncated_and_extended_paths_fail_closed() -> None:
    _, _, disclosure = _disclosure(5, 3)
    truncated = deepcopy(disclosure)
    truncated["membership_proof"]["sibling_path"].pop()
    assert verify_selective_lineage_disclosure(truncated).reason == (
        "membership_path_invalid"
    )

    extended = deepcopy(disclosure)
    extended["membership_proof"]["sibling_path"].append(
        {"side": "right", "sha256": _sha("extra")}
    )
    assert verify_selective_lineage_disclosure(extended).reason == (
        "membership_path_invalid"
    )


def test_odd_duplicate_sibling_cannot_be_replaced() -> None:
    _, _, disclosure = _disclosure(5, 5)
    tampered = deepcopy(disclosure)
    tampered["membership_proof"]["sibling_path"][0]["sha256"] = _sha(
        "not-the-duplicated-leaf"
    )
    decision = verify_selective_lineage_disclosure(tampered)
    assert decision.verified is False
    assert decision.reason == "membership_path_invalid"


def test_current_accumulator_is_bound_into_anchor() -> None:
    _, _, disclosure = _disclosure(5, 3)
    tampered = deepcopy(disclosure)
    tampered["current_accumulator"]["lineage_root_sha256"] = _sha("other-root")
    decision = verify_selective_lineage_disclosure(tampered)
    assert decision.verified is False
    assert decision.reason == "membership_anchor_invalid"


def test_deeply_nested_disclosure_fails_closed() -> None:
    _, _, disclosure = _disclosure(5, 3)
    nested = []
    cursor = nested
    for _ in range(sys.getrecursionlimit() + 10):
        child = []
        cursor.append(child)
        cursor = child
    disclosure["anchor"]["nested"] = nested

    decision = verify_selective_lineage_disclosure(disclosure)
    assert decision.verified is False


def test_disclosed_accumulator_must_bind_selected_cycle() -> None:
    _, _, disclosure = _disclosure(5, 3)
    tampered = deepcopy(disclosure)
    tampered["disclosed_cycle"]["lineage_accumulator"][
        "cycle_commitment_sha256"
    ] = _sha("other-cycle")
    decision = verify_selective_lineage_disclosure(tampered)
    assert decision.verified is False
    assert decision.reason == "disclosed_accumulator_invalid"


def test_builder_rejects_reordered_or_incomplete_history() -> None:
    records, accumulator = _history(5)
    reordered = list(records)
    reordered[1], reordered[2] = reordered[2], reordered[1]
    with pytest.raises(ValueError, match="cycle_index_not_contiguous"):
        build_lineage_membership_anchor(
            reordered,
            accumulator,
            membership_contract_sha256=MEMBERSHIP_CONTRACT,
            authorization_contract_sha256=MEMBERSHIP_AUTHORIZATION,
        )

    with pytest.raises(ValueError, match="cycle_count_accumulator_mismatch"):
        build_lineage_membership_anchor(
            records[:-1],
            accumulator,
            membership_contract_sha256=MEMBERSHIP_CONTRACT,
            authorization_contract_sha256=MEMBERSHIP_AUTHORIZATION,
        )


def test_builder_rejects_a_non_tip_accumulator() -> None:
    records, accumulator = _history(5)
    old_accumulator = records[-2]["lineage_accumulator"]
    with pytest.raises(ValueError, match="cycle_count_accumulator_mismatch"):
        build_lineage_membership_anchor(
            records,
            old_accumulator,
            membership_contract_sha256=MEMBERSHIP_CONTRACT,
            authorization_contract_sha256=MEMBERSHIP_AUTHORIZATION,
        )
    assert accumulator != old_accumulator


def test_builder_rejects_zero_contracts_and_bad_selected_index() -> None:
    records, accumulator = _history(3)
    with pytest.raises(ValueError, match="membership_contract_invalid"):
        build_lineage_membership_anchor(
            records,
            accumulator,
            membership_contract_sha256=ZERO_SHA256,
            authorization_contract_sha256=MEMBERSHIP_AUTHORIZATION,
        )
    with pytest.raises(ValueError, match="selected_cycle_index_invalid"):
        build_selective_lineage_disclosure(
            records,
            accumulator,
            selected_cycle_index=4,
            membership_contract_sha256=MEMBERSHIP_CONTRACT,
            authorization_contract_sha256=MEMBERSHIP_AUTHORIZATION,
        )
