from __future__ import annotations

import sys
from copy import deepcopy

import pytest
import ttrace

from scripts.verify_witness_policy_handoff_chain import (
    CHAIN_AUTHORIZATION,
    CHAIN_CONTRACT,
    CHAIN_ID,
    build_canonical_handoff_chain_fixture,
)
from ttrace.lineage_compaction import ZERO_SHA256
from ttrace.lineage_witness_handoff import (
    LINEAGE_WITNESS_POLICY_HANDOFF_PACKAGE_SCHEMA,
)
from ttrace.lineage_witness_handoff_chain import (
    advance_witness_policy_handoff_chain,
    build_seed_witness_policy_handoff_chain,
)
from ttrace.lineage_witness_handoff_chain_membership import (
    HANDOFF_CHAIN_MEMBERSHIP_ANCHOR_SCHEMA,
    HANDOFF_CHAIN_MEMBERSHIP_PROOF_SCHEMA,
    HANDOFF_CHAIN_MEMBERSHIP_REASON,
    HANDOFF_CHAIN_MEMBERSHIP_TREE_ALGORITHM,
    HANDOFF_CHAIN_SELECTIVE_DISCLOSURE_SCHEMA,
    _leaf_hash,
    _merkle_path,
    _merkle_root,
    _node_hash,
    _verify_merkle_path,
    build_selective_witness_policy_handoff_chain_disclosure,
    build_witness_policy_handoff_chain_membership_anchor,
    validate_witness_policy_handoff_chain_membership_anchor,
    verify_selective_witness_policy_handoff_chain_disclosure,
)
from ttrace.portable_causality import digest_json

MEMBERSHIP_CONTRACT = digest_json({"contract": "handoff-membership/v0.1"})
MEMBERSHIP_AUTHORIZATION = digest_json(
    {"contract": "handoff-membership-authorization/v0.1"}
)

ANCHOR_KEYS = {
    "schema",
    "chain_id",
    "policy_id",
    "genesis_policy_epoch",
    "genesis_policy_sha256",
    "completed_handoffs",
    "current_policy_epoch",
    "current_policy_sha256",
    "current_chain_ref_sha256",
    "current_chain_root_sha256",
    "current_step_commitment_sha256",
    "tree_size",
    "tree_algorithm",
    "step_commitment_merkle_root_sha256",
    "chain_contract_sha256",
    "chain_authorization_contract_sha256",
    "membership_contract_sha256",
    "authorization_contract_sha256",
}
DISCLOSED_HANDOFF_KEYS = {
    "handoff_index",
    "previous_chain_ref",
    "handoff_package",
    "chain_step",
    "chain_ref",
    "step_commitment_sha256",
}


def _chain(
    *,
    chain_id: str = CHAIN_ID,
    chain_contract: str = CHAIN_CONTRACT,
    chain_authorization: str = CHAIN_AUTHORIZATION,
):
    fixture = build_canonical_handoff_chain_fixture()
    packages = fixture["packages"]
    seed = build_seed_witness_policy_handoff_chain(
        packages[0],
        chain_id=chain_id,
        expected_genesis_policy_epoch=1,
        expected_genesis_policy_sha256=digest_json(fixture["policies"][0]),
        chain_contract_sha256=chain_contract,
        authorization_contract_sha256=chain_authorization,
    )
    assert seed.verified and seed.chain_ref is not None
    second = advance_witness_policy_handoff_chain(seed.chain_ref, packages[1])
    assert second.verified and second.chain_ref is not None
    third = advance_witness_policy_handoff_chain(second.chain_ref, packages[2])
    assert third.verified and third.chain_ref is not None
    return fixture, seed.chain_ref, second.chain_ref, third.chain_ref


def _disclosure(selected: int = 2):
    fixture, seed_ref, second_ref, current_ref = _chain()
    disclosure = build_selective_witness_policy_handoff_chain_disclosure(
        fixture["packages"],
        current_ref,
        selected_handoff_index=selected,
        membership_contract_sha256=MEMBERSHIP_CONTRACT,
        authorization_contract_sha256=MEMBERSHIP_AUTHORIZATION,
    )
    return fixture, (seed_ref, second_ref, current_ref), disclosure


def _count_schema(value, schema: str) -> int:
    if isinstance(value, dict):
        own = 1 if value.get("schema") == schema else 0
        return own + sum(_count_schema(item, schema) for item in value.values())
    if isinstance(value, (list, tuple)):
        return sum(_count_schema(item, schema) for item in value)
    return 0


def _all_keys(value) -> set[str]:
    if isinstance(value, dict):
        return set(value).union(*(_all_keys(item) for item in value.values()))
    if isinstance(value, (list, tuple)):
        return set().union(*(_all_keys(item) for item in value))
    return set()


def test_selected_handoff_verifies_with_two_logarithmic_paths() -> None:
    _, _, disclosure = _disclosure(2)
    decision = verify_selective_witness_policy_handoff_chain_disclosure(
        disclosure
    )
    assert decision.verified is True
    assert decision.reason == HANDOFF_CHAIN_MEMBERSHIP_REASON
    assert decision.disclosed_handoff_index == 2
    assert decision.anchor_sha256 == digest_json(disclosure["anchor"])
    assert decision.step_commitment_sha256 == disclosure["disclosed_handoff"][
        "step_commitment_sha256"
    ]
    assert decision.selected_sibling_hash_count == 2
    assert decision.current_sibling_hash_count == 2
    assert decision.sibling_hash_count == 4
    assert decision.membership_anchor_authorization_status == "not-evaluated"
    assert decision.current_tip_freshness_status == "not-evaluated"
    assert decision.global_non_equivocation_status == "unproven"


def test_first_and_current_handoffs_verify_with_bounded_predecessor_context() -> None:
    _, refs, first = _disclosure(1)
    _, _, current = _disclosure(3)
    assert first["disclosed_handoff"]["previous_chain_ref"] is None
    assert verify_selective_witness_policy_handoff_chain_disclosure(first).verified
    assert current["disclosed_handoff"]["previous_chain_ref"] == refs[1]
    assert current["disclosed_handoff"]["chain_ref"] == refs[2]
    assert verify_selective_witness_policy_handoff_chain_disclosure(current).verified


@pytest.mark.parametrize(
    "handoff_count,selected,expected_path_length",
    [(1, 1, 0), (2, 1, 1), (2, 2, 1), (3, 2, 2)],
)
def test_singleton_power_of_two_and_odd_trees_verify(
    handoff_count: int, selected: int, expected_path_length: int
) -> None:
    fixture, refs, _ = _disclosure()
    disclosure = build_selective_witness_policy_handoff_chain_disclosure(
        fixture["packages"][:handoff_count],
        refs[handoff_count - 1],
        selected_handoff_index=selected,
        membership_contract_sha256=MEMBERSHIP_CONTRACT,
        authorization_contract_sha256=MEMBERSHIP_AUTHORIZATION,
    )
    proof = disclosure["membership_proof"]
    assert len(proof["sibling_path"]) == expected_path_length
    assert len(proof["current_step_sibling_path"]) == expected_path_length
    assert verify_selective_witness_policy_handoff_chain_disclosure(
        disclosure
    ).verified


def test_merkle_encoding_matches_independent_golden_vectors() -> None:
    commitments = ["11" * 32, "22" * 32, "33" * 32, "44" * 32]
    leaves = [_leaf_hash(index, value) for index, value in enumerate(commitments, 1)]
    assert leaves == [
        "a2a12ce09f7208dedc1d07ef06ab72074634fecca847ff6b1875d5b0e722a700",
        "bd6245183dd40e273f285806139057b12e1aa30d13c29909de4ce712d7a5641d",
        "0c8983e58d2cb3e7b09af7f7866b4b1ecccbda02023fa1591b5a98dcc0eae821",
        "9e96a5ad656e529dc009a5f611028162b51f32a9c516e43fbe4c7650ce24558c",
    ]

    three_leaf_root = _merkle_root(leaves[:3])
    assert three_leaf_root == (
        "bac898aaf90e58bf262dcb56fb32f8a22d0769c2bbfc88484e569cd679a1cb93"
    )
    assert _merkle_path(leaves[:3], 1) == [
        {"side": "left", "sha256": leaves[0]},
        {
            "side": "right",
            "sha256": (
                "60b8c41ca2e5aaabf3ed00c0bee0e4519c18142cf835685cfdb15c9ee9db1e39"
            ),
        },
    ]
    assert _verify_merkle_path(
        leaf_sha256=leaves[1],
        leaf_index=1,
        tree_size=3,
        sibling_path=_merkle_path(leaves[:3], 1),
        expected_root_sha256=three_leaf_root,
    )

    assert _node_hash(leaves[0], leaves[1]) == (
        "329993b3b05c37852a5c725184691e6949edea1fe76ac87e1b47216d0f162fdc"
    )
    assert _merkle_root(leaves) == (
        "98c56ef7ca18cf3512654f546f5a2175f6b1db3914fdc337c400e08ed5e1c70f"
    )
    for leaf_index, leaf_sha256 in enumerate(leaves):
        assert _verify_merkle_path(
            leaf_sha256=leaf_sha256,
            leaf_index=leaf_index,
            tree_size=4,
            sibling_path=_merkle_path(leaves, leaf_index),
            expected_root_sha256=_merkle_root(leaves),
        )


def test_anchor_is_fixed_shape_and_bound_to_current_tip_and_both_contract_planes() -> None:
    fixture, refs, _ = _disclosure()
    current_ref = refs[2]
    anchor = build_witness_policy_handoff_chain_membership_anchor(
        fixture["packages"],
        current_ref,
        membership_contract_sha256=MEMBERSHIP_CONTRACT,
        authorization_contract_sha256=MEMBERSHIP_AUTHORIZATION,
    )
    assert set(anchor) == ANCHOR_KEYS
    assert len(anchor) == 18
    assert all(not isinstance(value, (dict, list, tuple)) for value in anchor.values())
    assert anchor["schema"] == HANDOFF_CHAIN_MEMBERSHIP_ANCHOR_SCHEMA
    assert anchor["tree_algorithm"] == HANDOFF_CHAIN_MEMBERSHIP_TREE_ALGORITHM
    assert anchor["current_chain_ref_sha256"] == digest_json(current_ref)
    assert anchor["chain_contract_sha256"] == CHAIN_CONTRACT
    assert anchor["chain_authorization_contract_sha256"] == CHAIN_AUTHORIZATION
    assert anchor["membership_contract_sha256"] == MEMBERSHIP_CONTRACT
    assert anchor["authorization_contract_sha256"] == MEMBERSHIP_AUTHORIZATION
    assert validate_witness_policy_handoff_chain_membership_anchor(
        anchor, current_ref
    )


@pytest.mark.parametrize(
    "field,replacement",
    [
        ("genesis_policy_epoch", True),
        ("genesis_policy_epoch", 1.0),
        ("completed_handoffs", True),
        ("completed_handoffs", 1.0),
        ("current_policy_epoch", 2.0),
    ],
)
def test_anchor_rejects_equal_but_noncanonical_numeric_scalars(
    field: str, replacement
) -> None:
    fixture, refs, _ = _disclosure()
    current_ref = refs[0]
    anchor = build_witness_policy_handoff_chain_membership_anchor(
        fixture["packages"][:1],
        current_ref,
        membership_contract_sha256=MEMBERSHIP_CONTRACT,
        authorization_contract_sha256=MEMBERSHIP_AUTHORIZATION,
    )
    assert anchor[field] == replacement
    anchor[field] = replacement
    assert not validate_witness_policy_handoff_chain_membership_anchor(
        anchor, current_ref
    )


def test_disclosure_contains_exactly_one_complete_handoff_package() -> None:
    _, _, disclosure = _disclosure(2)
    assert set(disclosure) == {
        "schema",
        "anchor",
        "current_chain_ref",
        "disclosed_handoff",
        "membership_proof",
    }
    assert disclosure["schema"] == HANDOFF_CHAIN_SELECTIVE_DISCLOSURE_SCHEMA
    assert set(disclosure["disclosed_handoff"]) == DISCLOSED_HANDOFF_KEYS
    assert _count_schema(
        disclosure, LINEAGE_WITNESS_POLICY_HANDOFF_PACKAGE_SCHEMA
    ) == 1
    serialized_keys = _all_keys(disclosure)
    assert not {
        "handoff_packages",
        "handoff_records",
        "all_handoffs",
        "intermediate_handoffs",
    } & serialized_keys


def test_odd_last_leaf_requires_the_canonical_duplicate_sibling() -> None:
    _, _, disclosure = _disclosure(3)
    proof = disclosure["membership_proof"]
    assert proof["current_step_sibling_path"][0] == {
        "side": "right",
        "sha256": proof["leaf_sha256"],
    }
    proof["current_step_sibling_path"][0]["sha256"] = digest_json(
        {"tampered": "duplicate"}
    )
    decision = verify_selective_witness_policy_handoff_chain_disclosure(
        disclosure
    )
    assert decision.verified is False
    assert decision.reason == "current_handoff_membership_path_invalid"


def test_same_size_tree_that_omits_the_current_step_fails_closed() -> None:
    _, _, first = _disclosure(1)
    _, _, selected = _disclosure(2)
    _, _, current = _disclosure(3)
    commitments = (
        first["disclosed_handoff"]["step_commitment_sha256"],
        selected["disclosed_handoff"]["step_commitment_sha256"],
        current["disclosed_handoff"]["step_commitment_sha256"],
    )
    fake_leaves = [
        _leaf_hash(1, commitments[0]),
        _leaf_hash(2, commitments[1]),
        _leaf_hash(3, commitments[1]),
    ]
    proof = selected["membership_proof"]
    selected["anchor"]["step_commitment_merkle_root_sha256"] = _merkle_root(
        fake_leaves
    )
    proof["anchor_sha256"] = digest_json(selected["anchor"])
    proof["sibling_path"] = _merkle_path(fake_leaves, 1)
    proof["current_step_sibling_path"] = _merkle_path(fake_leaves, 2)
    decision = verify_selective_witness_policy_handoff_chain_disclosure(selected)
    assert decision.verified is False
    assert decision.reason == "current_handoff_membership_path_invalid"


@pytest.mark.parametrize(
    "mutation",
    [
        lambda value: value.update({"all_handoffs": []}),
        lambda value: value.__setitem__(
            "schema", "ttrace-wrong-selective-disclosure/v0.1"
        ),
        lambda value: value["anchor"].update({"unknown": "field"}),
        lambda value: value["anchor"].__setitem__(
            "schema", "ttrace-wrong-membership-anchor/v0.1"
        ),
        lambda value: value["anchor"].__setitem__(
            "tree_algorithm", "wrong-merkle/v0.1"
        ),
        lambda value: value["membership_proof"].update({"unknown": "field"}),
        lambda value: value["disclosed_handoff"].update({"unknown": "field"}),
        lambda value: value["membership_proof"].__setitem__(
            "schema", "ttrace-wrong-proof/v0.1"
        ),
        lambda value: value["membership_proof"].__setitem__(
            "handoff_index", True
        ),
        lambda value: value["membership_proof"].__setitem__("leaf_index", True),
        lambda value: value["membership_proof"].__setitem__("tree_size", True),
        lambda value: value["membership_proof"].__setitem__(
            "tree_algorithm", "wrong-merkle/v0.1"
        ),
        lambda value: value["anchor"].__setitem__("tree_size", True),
        lambda value: value["anchor"].__setitem__(
            "membership_contract_sha256", ZERO_SHA256
        ),
        lambda value: value["membership_proof"].__setitem__(
            "anchor_sha256", digest_json({"other": "anchor"})
        ),
        lambda value: value["disclosed_handoff"].__setitem__(
            "step_commitment_sha256", digest_json({"other": "step"})
        ),
        lambda value: value["membership_proof"].__setitem__(
            "leaf_sha256", digest_json({"other": "leaf"})
        ),
        lambda value: value["membership_proof"]["sibling_path"][0].__setitem__(
            "side", "right"
        ),
        lambda value: value["membership_proof"]["sibling_path"][0].update(
            {"unknown": "field"}
        ),
        lambda value: value["membership_proof"]["sibling_path"].pop(),
        lambda value: value["membership_proof"]["sibling_path"].append(
            {"side": "right", "sha256": digest_json({"extra": "sibling"})}
        ),
        lambda value: value["membership_proof"].__setitem__(
            "current_step_sibling_path",
            deepcopy(value["membership_proof"]["sibling_path"]),
        ),
        lambda value: value["disclosed_handoff"]["handoff_package"].update(
            {"unknown": "field"}
        ),
        lambda value: value["disclosed_handoff"]["chain_step"].__setitem__(
            "new_policy_sha256", digest_json({"other": "policy"})
        ),
        lambda value: value["disclosed_handoff"]["chain_ref"].__setitem__(
            "step_commitment_sha256", digest_json({"other": "step"})
        ),
        lambda value: value["disclosed_handoff"]["previous_chain_ref"].__setitem__(
            "completed_handoffs", True
        ),
    ],
)
def test_tampering_and_schema_extensions_fail_closed(mutation) -> None:
    _, _, disclosure = _disclosure(2)
    mutation(disclosure)
    assert not verify_selective_witness_policy_handoff_chain_disclosure(
        disclosure
    ).verified


@pytest.mark.parametrize(
    "foreign_context",
    [
        {"chain_id": "example.foreign.witness-policy-chain"},
        {"chain_contract": digest_json({"contract": "foreign-chain/v0.1"})},
    ],
)
def test_valid_foreign_current_tip_cannot_replace_disclosed_tip(
    foreign_context,
) -> None:
    _, _, disclosure = _disclosure(2)
    _, _, _, foreign_tip = _chain(**foreign_context)
    disclosure["current_chain_ref"] = foreign_tip
    decision = verify_selective_witness_policy_handoff_chain_disclosure(disclosure)
    assert decision.verified is False
    assert decision.reason == "handoff_chain_membership_anchor_invalid"


@pytest.mark.parametrize(
    "foreign_context",
    [
        {"chain_id": "example.foreign.witness-policy-chain"},
        {"chain_contract": digest_json({"contract": "foreign-chain/v0.1"})},
    ],
)
def test_valid_foreign_predecessor_cannot_rebind_selected_handoff(
    foreign_context,
) -> None:
    _, _, disclosure = _disclosure(2)
    _, foreign_seed, _, _ = _chain(**foreign_context)
    disclosure["disclosed_handoff"]["previous_chain_ref"] = foreign_seed
    decision = verify_selective_witness_policy_handoff_chain_disclosure(disclosure)
    assert decision.verified is False
    assert decision.reason == "disclosed_predecessor_context_mismatch"


def test_seed_disclosure_requires_null_predecessor() -> None:
    _, refs, disclosure = _disclosure(1)
    disclosure["disclosed_handoff"]["previous_chain_ref"] = refs[0]
    decision = verify_selective_witness_policy_handoff_chain_disclosure(disclosure)
    assert decision.verified is False
    assert decision.reason == "disclosed_seed_predecessor_invalid"


def test_deeply_nested_disclosure_fails_closed() -> None:
    _, _, disclosure = _disclosure(2)
    nested = []
    cursor = nested
    for _ in range(sys.getrecursionlimit() + 10):
        child = []
        cursor.append(child)
        cursor = child
    disclosure["disclosed_handoff"]["chain_step"] = nested
    decision = verify_selective_witness_policy_handoff_chain_disclosure(disclosure)
    assert decision.verified is False
    assert decision.reason == "handoff_chain_selective_disclosure_too_deep"


def test_all_membership_symbols_are_exported_from_public_api() -> None:
    expected = {
        "HANDOFF_CHAIN_MEMBERSHIP_ANCHOR_AUTHORIZATION_STATUS",
        "HANDOFF_CHAIN_MEMBERSHIP_ANCHOR_SCHEMA",
        "HANDOFF_CHAIN_MEMBERSHIP_CURRENT_TIP_FRESHNESS_STATUS",
        "HANDOFF_CHAIN_MEMBERSHIP_LEAF_SCHEMA",
        "HANDOFF_CHAIN_MEMBERSHIP_NODE_SCHEMA",
        "HANDOFF_CHAIN_MEMBERSHIP_PROOF_SCHEMA",
        "HANDOFF_CHAIN_MEMBERSHIP_REASON",
        "HANDOFF_CHAIN_MEMBERSHIP_TREE_ALGORITHM",
        "HANDOFF_CHAIN_SELECTIVE_DISCLOSURE_SCHEMA",
        "WitnessPolicyHandoffChainMembershipDecision",
        "build_selective_witness_policy_handoff_chain_disclosure",
        "build_witness_policy_handoff_chain_membership_anchor",
        "validate_witness_policy_handoff_chain_membership_anchor",
        "verify_selective_witness_policy_handoff_chain_disclosure",
    }
    assert expected <= set(ttrace.__all__)
    assert all(hasattr(ttrace, name) for name in expected)


def test_proof_cannot_be_rebound_to_another_membership_anchor() -> None:
    _, _, disclosure = _disclosure(2)
    fixture, refs, _ = _disclosure(2)
    other = build_selective_witness_policy_handoff_chain_disclosure(
        fixture["packages"],
        refs[2],
        selected_handoff_index=2,
        membership_contract_sha256=digest_json({"contract": "other"}),
        authorization_contract_sha256=MEMBERSHIP_AUTHORIZATION,
    )
    disclosure["anchor"] = other["anchor"]
    decision = verify_selective_witness_policy_handoff_chain_disclosure(
        disclosure
    )
    assert decision.verified is False
    assert decision.reason == "proof_anchor_mismatch"


@pytest.mark.parametrize("selected", [True, 0, -1, 4, 1.0])
def test_builder_rejects_noncanonical_or_out_of_range_indexes(selected) -> None:
    fixture, refs, _ = _disclosure()
    with pytest.raises(ValueError, match="selected_handoff_index_invalid"):
        build_selective_witness_policy_handoff_chain_disclosure(
            fixture["packages"],
            refs[2],
            selected_handoff_index=selected,
            membership_contract_sha256=MEMBERSHIP_CONTRACT,
            authorization_contract_sha256=MEMBERSHIP_AUTHORIZATION,
        )


@pytest.mark.parametrize(
    "membership_contract,authorization_contract",
    [
        (ZERO_SHA256, MEMBERSHIP_AUTHORIZATION),
        (MEMBERSHIP_CONTRACT, ZERO_SHA256),
        ("not-a-digest", MEMBERSHIP_AUTHORIZATION),
        (MEMBERSHIP_CONTRACT, "not-a-digest"),
    ],
)
def test_builder_rejects_invalid_membership_contracts(
    membership_contract, authorization_contract
) -> None:
    fixture, refs, _ = _disclosure()
    with pytest.raises(ValueError):
        build_witness_policy_handoff_chain_membership_anchor(
            fixture["packages"],
            refs[2],
            membership_contract_sha256=membership_contract,
            authorization_contract_sha256=authorization_contract,
        )


def test_anchor_builder_rejects_reordered_truncated_and_non_tip_histories() -> None:
    fixture, refs, _ = _disclosure()
    packages = fixture["packages"]
    for invalid_packages, invalid_tip in (
        (tuple(reversed(packages)), refs[2]),
        (packages[:2], refs[2]),
        (packages, refs[1]),
    ):
        with pytest.raises(ValueError):
            build_witness_policy_handoff_chain_membership_anchor(
                invalid_packages,
                invalid_tip,
                membership_contract_sha256=MEMBERSHIP_CONTRACT,
                authorization_contract_sha256=MEMBERSHIP_AUTHORIZATION,
            )
