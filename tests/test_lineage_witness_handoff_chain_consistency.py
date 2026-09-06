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
from ttrace.lineage_witness_handoff_chain import (
    advance_witness_policy_handoff_chain,
    build_seed_witness_policy_handoff_chain,
)
from ttrace.lineage_witness_handoff_chain_consistency import (
    HANDOFF_CHAIN_MEMBERSHIP_ANCHOR_STATEMENT_SCHEMA,
    HANDOFF_CHAIN_MEMBERSHIP_AUTHORIZED_CONSISTENCY_REASON,
    HANDOFF_CHAIN_MEMBERSHIP_EQUIVOCATION_DETECTED_REASON,
    HANDOFF_CHAIN_MEMBERSHIP_EQUIVOCATION_EVIDENCE_SCHEMA,
    HANDOFF_CHAIN_MEMBERSHIP_EQUIVOCATION_NOT_PROVEN_REASON,
    HANDOFF_CHAIN_MEMBERSHIP_ROOT_CONSISTENCY_PACKAGE_SCHEMA,
    HANDOFF_CHAIN_MEMBERSHIP_ROOT_CONSISTENCY_PROOF_SCHEMA,
    HANDOFF_CHAIN_MEMBERSHIP_ROOT_CONSISTENCY_REASON,
    _append_block,
    _bag_frontier_to_membership_root,
    _build_blocks,
    _prefix_block_shapes,
    _suffix_block_shapes,
    build_witness_policy_handoff_chain_membership_anchor_statement,
    build_witness_policy_handoff_chain_membership_root_consistency_package,
    detect_witness_policy_handoff_chain_membership_anchor_equivocation,
    validate_witness_policy_handoff_chain_membership_anchor_statement,
    validate_witness_policy_handoff_chain_membership_equivocation_evidence,
    verify_authorized_witness_policy_handoff_chain_membership_root_consistency,
    verify_witness_policy_handoff_chain_membership_root_consistency,
)
from ttrace.lineage_witness_handoff_chain_membership import (
    _leaf_hash,
    _merkle_root,
    _node_hash,
    build_witness_policy_handoff_chain_membership_anchor,
)
from ttrace.portable_causality import digest_json


MEMBERSHIP_CONTRACT = digest_json(
    {"contract": "handoff-membership-consistency/v0.1"}
)
MEMBERSHIP_AUTHORIZATION = digest_json(
    {"contract": "handoff-membership-consistency-authorization/v0.1"}
)

PACKAGE_KEYS = {
    "schema",
    "old_endpoint",
    "new_endpoint",
    "consistency_proof",
}
ENDPOINT_KEYS = {"membership_anchor", "current_chain_ref"}
PROOF_KEYS = {
    "schema",
    "old_anchor_sha256",
    "new_anchor_sha256",
    "old_tree_size",
    "new_tree_size",
    "membership_tree_algorithm",
    "consistency_algorithm",
    "old_frontier",
    "append_blocks",
    "old_current_step_sibling_path",
    "new_current_step_sibling_path",
}
STATEMENT_KEYS = {
    "schema",
    "verified",
    "authority_id",
    "statement_sequence",
    "previous_statement_sha256",
    "statement_provenance_sha256",
    "chain_id",
    "policy_id",
    "genesis_policy_epoch",
    "genesis_policy_sha256",
    "tree_size",
    "anchor_sha256",
    "membership_root_sha256",
    "current_chain_ref_sha256",
    "current_chain_root_sha256",
    "current_step_commitment_sha256",
    "current_policy_epoch",
    "current_policy_sha256",
    "tree_algorithm",
    "chain_contract_sha256",
    "chain_authorization_contract_sha256",
    "membership_contract_sha256",
    "authorization_contract_sha256",
}
EVIDENCE_KEYS = {
    "schema",
    "verified",
    "reason",
    "equivocation_detected",
    "authority_id",
    "chain_id",
    "policy_id",
    "genesis_policy_epoch",
    "genesis_policy_sha256",
    "detection_mode",
    "statement_a_sha256",
    "statement_b_sha256",
    "anchor_a_sha256",
    "anchor_b_sha256",
    "current_chain_ref_a_sha256",
    "current_chain_ref_b_sha256",
    "tree_size_a",
    "tree_size_b",
    "membership_root_a_sha256",
    "membership_root_b_sha256",
    "tree_algorithm",
    "chain_contract_sha256",
    "chain_authorization_contract_sha256",
    "membership_contract_sha256",
    "authorization_contract_sha256",
    "global_non_equivocation_status",
}


def _refs(
    packages,
    *,
    chain_id: str = CHAIN_ID,
    chain_contract: str = CHAIN_CONTRACT,
    chain_authorization: str = CHAIN_AUTHORIZATION,
):
    fixture = build_canonical_handoff_chain_fixture()
    seed = build_seed_witness_policy_handoff_chain(
        packages[0],
        chain_id=chain_id,
        expected_genesis_policy_epoch=1,
        expected_genesis_policy_sha256=digest_json(fixture["policies"][0]),
        chain_contract_sha256=chain_contract,
        authorization_contract_sha256=chain_authorization,
    )
    assert seed.verified and seed.chain_ref is not None
    refs = [seed.chain_ref]
    for package in packages[1:]:
        result = advance_witness_policy_handoff_chain(refs[-1], package)
        assert result.verified and result.chain_ref is not None
        refs.append(result.chain_ref)
    return tuple(refs)


def _case(old_size: int = 1, new_size: int = 3):
    fixture = build_canonical_handoff_chain_fixture()
    packages = fixture["packages"]
    refs = _refs(packages)
    package = (
        build_witness_policy_handoff_chain_membership_root_consistency_package(
            packages[:old_size],
            refs[old_size - 1],
            packages[:new_size],
            refs[new_size - 1],
            membership_contract_sha256=MEMBERSHIP_CONTRACT,
            authorization_contract_sha256=MEMBERSHIP_AUTHORIZATION,
        )
    )
    return fixture, packages, refs, package


def _statements(package, *, authority: str = "anchor-authority"):
    old_endpoint = package["old_endpoint"]
    new_endpoint = package["new_endpoint"]
    old = build_witness_policy_handoff_chain_membership_anchor_statement(
        old_endpoint["membership_anchor"],
        old_endpoint["current_chain_ref"],
        verified=True,
        authority_id=authority,
        statement_sequence=1,
        previous_statement_sha256=ZERO_SHA256,
        statement_provenance_sha256=digest_json({"statement": "old"}),
    )
    new = build_witness_policy_handoff_chain_membership_anchor_statement(
        new_endpoint["membership_anchor"],
        new_endpoint["current_chain_ref"],
        verified=True,
        authority_id=authority,
        statement_sequence=2,
        previous_statement_sha256=digest_json(old),
        statement_provenance_sha256=digest_json({"statement": "new"}),
    )
    return old, new


@pytest.mark.parametrize(
    "old_size,new_size,frontier_count,append_count,old_path,new_path",
    [(1, 2, 1, 1, 0, 1), (1, 3, 1, 2, 0, 2), (2, 3, 1, 1, 1, 2)],
)
def test_append_only_consistency_verifies_with_compact_proof(
    old_size: int,
    new_size: int,
    frontier_count: int,
    append_count: int,
    old_path: int,
    new_path: int,
) -> None:
    _, _, _, package = _case(old_size, new_size)
    decision = (
        verify_witness_policy_handoff_chain_membership_root_consistency(package)
    )
    assert decision.verified is True
    assert decision.reason == HANDOFF_CHAIN_MEMBERSHIP_ROOT_CONSISTENCY_REASON
    assert decision.old_tree_size == old_size
    assert decision.new_tree_size == new_size
    assert decision.old_frontier_node_count == frontier_count
    assert decision.append_block_count == append_count
    assert decision.old_current_path_hash_count == old_path
    assert decision.new_current_path_hash_count == new_path
    assert decision.append_only_consistent is True
    assert decision.current_steps_membership_bound is True
    assert decision.raw_handoff_packages_disclosed is False
    assert decision.membership_anchor_authorization_status == "not-evaluated"
    assert decision.current_tip_freshness_status == "not-evaluated"
    assert decision.rolling_chain_descendance_status == "not-independently-proven"
    assert decision.global_non_equivocation_status == "unproven"


def test_package_is_exact_shape_private_and_reuses_canonical_anchors() -> None:
    _, packages, refs, package = _case()
    assert set(package) == PACKAGE_KEYS
    assert package["schema"] == HANDOFF_CHAIN_MEMBERSHIP_ROOT_CONSISTENCY_PACKAGE_SCHEMA
    assert set(package["old_endpoint"]) == ENDPOINT_KEYS
    assert set(package["new_endpoint"]) == ENDPOINT_KEYS
    proof = package["consistency_proof"]
    assert set(proof) == PROOF_KEYS
    assert proof["schema"] == HANDOFF_CHAIN_MEMBERSHIP_ROOT_CONSISTENCY_PROOF_SCHEMA
    assert "handoff_packages" not in repr(proof)
    assert package["old_endpoint"]["membership_anchor"] == (
        build_witness_policy_handoff_chain_membership_anchor(
            packages[:1],
            refs[0],
            membership_contract_sha256=MEMBERSHIP_CONTRACT,
            authorization_contract_sha256=MEMBERSHIP_AUTHORIZATION,
        )
    )
    assert package["new_endpoint"]["membership_anchor"] == (
        build_witness_policy_handoff_chain_membership_anchor(
            packages,
            refs[2],
            membership_contract_sha256=MEMBERSHIP_CONTRACT,
            authorization_contract_sha256=MEMBERSHIP_AUTHORIZATION,
        )
    )


def test_compact_frontier_matches_independent_golden_vector() -> None:
    commitments = ["11" * 32, "22" * 32, "33" * 32, "44" * 32]
    leaves = [_leaf_hash(index, value) for index, value in enumerate(commitments, 1)]
    node_12 = _node_hash(leaves[0], leaves[1])
    node_34 = _node_hash(leaves[2], leaves[3])
    assert node_12 == "329993b3b05c37852a5c725184691e6949edea1fe76ac87e1b47216d0f162fdc"
    assert node_34 == "66e84a3a04ab1bf47c10c5dc633b9ea7095798f474eccf0ca492999280d3be28"
    assert _build_blocks(leaves[:3], _prefix_block_shapes(3)) == [
        {"start": 0, "size": 2, "sha256": node_12},
        {"start": 2, "size": 1, "sha256": leaves[2]},
    ]
    assert _build_blocks(leaves, _suffix_block_shapes(3, 4)) == [
        {"start": 3, "size": 1, "sha256": leaves[3]}
    ]
    assert _node_hash(node_12, node_34) == (
        "98c56ef7ca18cf3512654f546f5a2175f6b1db3914fdc337c400e08ed5e1c70f"
    )


def test_frontier_append_reconstructs_duplicate_last_roots_across_sizes() -> None:
    commitments = [f"{index:064x}" for index in range(1, 34)]
    leaves = [_leaf_hash(index, value) for index, value in enumerate(commitments, 1)]
    for old_size in range(1, 17):
        old_frontier = _build_blocks(
            leaves, _prefix_block_shapes(old_size)
        )
        assert _bag_frontier_to_membership_root(old_frontier) == _merkle_root(
            leaves[:old_size]
        )
        for new_size in range(old_size + 1, 34):
            frontier = [dict(block) for block in old_frontier]
            for block in _build_blocks(
                leaves, _suffix_block_shapes(old_size, new_size)
            ):
                frontier = _append_block(frontier, block)
            assert frontier == _build_blocks(
                leaves, _prefix_block_shapes(new_size)
            )
            assert _bag_frontier_to_membership_root(frontier) == _merkle_root(
                leaves[:new_size]
            )


@pytest.mark.parametrize(
    "field,value",
    [
        ("old_tree_size", True),
        ("old_tree_size", 1.0),
        ("old_tree_size", 0),
        ("old_tree_size", -1),
        ("new_tree_size", True),
        ("new_tree_size", 3.0),
        ("new_tree_size", 0),
    ],
)
def test_proof_sizes_require_strict_positive_json_integers(field, value) -> None:
    _, _, _, package = _case()
    package["consistency_proof"][field] = value
    assert not verify_witness_policy_handoff_chain_membership_root_consistency(
        package
    ).verified


@pytest.mark.parametrize("section", ["old_frontier", "append_blocks"])
@pytest.mark.parametrize(
    "field,value",
    [("start", True), ("start", 0.0), ("size", True), ("size", 1.0)],
)
def test_blocks_reject_bool_and_float_coordinates(section, field, value) -> None:
    _, _, _, package = _case()
    package["consistency_proof"][section][0][field] = value
    assert not verify_witness_policy_handoff_chain_membership_root_consistency(
        package
    ).verified


@pytest.mark.parametrize(
    "mutation",
    [
        lambda value: value.update({"unknown": True}),
        lambda value: value.__setitem__("schema", "wrong/v0.1"),
        lambda value: value["consistency_proof"].update({"unknown": True}),
        lambda value: value["consistency_proof"].__setitem__("schema", "wrong/v0.1"),
        lambda value: value["consistency_proof"]["old_frontier"].pop(),
        lambda value: value["consistency_proof"]["old_frontier"][0].update(
            {"unknown": True}
        ),
        lambda value: value["consistency_proof"]["append_blocks"].reverse(),
        lambda value: value["consistency_proof"]["append_blocks"][0].__setitem__(
            "start", 2
        ),
        lambda value: value["consistency_proof"]["append_blocks"][0].__setitem__(
            "sha256", digest_json({"tampered": "append"})
        ),
        lambda value: value["consistency_proof"].__setitem__(
            "old_anchor_sha256", digest_json({"wrong": "old"})
        ),
        lambda value: value["consistency_proof"].__setitem__(
            "new_anchor_sha256", digest_json({"wrong": "new"})
        ),
        lambda value: value["consistency_proof"][
            "old_current_step_sibling_path"
        ].append({"side": "right", "sha256": "11" * 32}),
        lambda value: value["consistency_proof"][
            "new_current_step_sibling_path"
        ][0].__setitem__("side", "left"),
        lambda value: value["consistency_proof"][
            "new_current_step_sibling_path"
        ][0].update({"unknown": True}),
        lambda value: value["consistency_proof"]["new_current_step_sibling_path"].pop(),
    ],
)
def test_schema_frontier_append_and_path_tampering_fail_closed(mutation) -> None:
    _, _, _, package = _case()
    mutation(package)
    assert not verify_witness_policy_handoff_chain_membership_root_consistency(
        package
    ).verified


def test_odd_current_step_requires_canonical_duplicate_sibling() -> None:
    _, _, _, package = _case()
    path = package["consistency_proof"]["new_current_step_sibling_path"]
    expected_leaf = _leaf_hash(
        3,
        package["new_endpoint"]["membership_anchor"][
            "current_step_commitment_sha256"
        ],
    )
    assert path[0] == {"side": "right", "sha256": expected_leaf}
    path[0]["sha256"] = digest_json({"not": "duplicate"})
    assert not verify_witness_policy_handoff_chain_membership_root_consistency(
        package
    ).verified


def test_builder_rejects_same_size_rollback_non_tip_and_different_prefix() -> None:
    fixture, packages, refs, _ = _case()
    kwargs = {
        "membership_contract_sha256": MEMBERSHIP_CONTRACT,
        "authorization_contract_sha256": MEMBERSHIP_AUTHORIZATION,
    }
    with pytest.raises(ValueError, match="tree_not_extended"):
        build_witness_policy_handoff_chain_membership_root_consistency_package(
            packages[:2], refs[1], packages[:2], refs[1], **kwargs
        )
    with pytest.raises(ValueError, match="tree_not_extended"):
        build_witness_policy_handoff_chain_membership_root_consistency_package(
            packages, refs[2], packages[:2], refs[1], **kwargs
        )
    with pytest.raises(ValueError, match="count_tip_mismatch"):
        build_witness_policy_handoff_chain_membership_root_consistency_package(
            packages[:1], refs[0], packages, refs[1], **kwargs
        )
    alternate = (packages[0], fixture["alternate_second_package"])
    alternate_refs = _refs(alternate)
    with pytest.raises(ValueError, match="prefix_mismatch"):
        build_witness_policy_handoff_chain_membership_root_consistency_package(
            alternate, alternate_refs[1], packages, refs[2], **kwargs
        )


def test_builder_requires_exact_boundary_rolling_reference() -> None:
    _, packages, refs, _ = _case()
    foreign_refs = _refs(packages[:1], chain_id="example.foreign.chain")
    with pytest.raises(ValueError, match="prefix_mismatch|boundary_ref_mismatch"):
        build_witness_policy_handoff_chain_membership_root_consistency_package(
            packages[:1],
            foreign_refs[0],
            packages,
            refs[2],
            membership_contract_sha256=MEMBERSHIP_CONTRACT,
            authorization_contract_sha256=MEMBERSHIP_AUTHORIZATION,
        )


@pytest.mark.parametrize(
    "context,reason",
    [
        ("chain_id", "chain_id_mismatch"),
        ("chain_contract", "chain_contract_mismatch"),
        ("chain_authorization", "chain_authorization_contract_mismatch"),
        ("membership_contract", "membership_contract_mismatch"),
        ("membership_authorization", "authorization_contract_mismatch"),
    ],
)
def test_all_four_contract_planes_and_chain_context_must_match(
    context: str, reason: str
) -> None:
    _, packages, _, package = _case()
    alternate = digest_json({"alternate": context})
    ref_kwargs = {}
    membership_contract = MEMBERSHIP_CONTRACT
    membership_authorization = MEMBERSHIP_AUTHORIZATION
    if context == "chain_id":
        ref_kwargs["chain_id"] = "example.foreign.chain"
    elif context == "chain_contract":
        ref_kwargs["chain_contract"] = alternate
    elif context == "chain_authorization":
        ref_kwargs["chain_authorization"] = alternate
    elif context == "membership_contract":
        membership_contract = alternate
    else:
        membership_authorization = alternate
    other_refs = _refs(packages, **ref_kwargs)
    other = (
        build_witness_policy_handoff_chain_membership_root_consistency_package(
            packages[:1],
            other_refs[0],
            packages,
            other_refs[2],
            membership_contract_sha256=membership_contract,
            authorization_contract_sha256=membership_authorization,
        )
    )
    other_anchor = other["new_endpoint"]["membership_anchor"]
    package["new_endpoint"] = other["new_endpoint"]
    package["consistency_proof"]["new_anchor_sha256"] = digest_json(other_anchor)
    decision = verify_witness_policy_handoff_chain_membership_root_consistency(package)
    assert decision.verified is False
    assert decision.reason == f"handoff_chain_consistency_{reason}"


def test_anchor_statements_are_exact_and_authorized_transition_verifies() -> None:
    _, _, _, package = _case()
    old, new = _statements(package)
    assert set(old) == STATEMENT_KEYS
    assert old["schema"] == HANDOFF_CHAIN_MEMBERSHIP_ANCHOR_STATEMENT_SCHEMA
    assert old["previous_statement_sha256"] == ZERO_SHA256
    assert new["previous_statement_sha256"] == digest_json(old)
    decision = (
        verify_authorized_witness_policy_handoff_chain_membership_root_consistency(
            package, old, new
        )
    )
    assert decision.verified is True
    assert decision.reason == HANDOFF_CHAIN_MEMBERSHIP_AUTHORIZED_CONSISTENCY_REASON
    assert decision.authority_chain_continuous is True
    assert decision.append_only_consistent is True
    assert decision.presented_equivocation_detected is False
    assert decision.global_non_equivocation_status == "unproven"


@pytest.mark.parametrize("value", [True, 1.0, 0, -1])
def test_statement_sequence_requires_strict_positive_integer(value) -> None:
    _, _, _, package = _case()
    endpoint = package["old_endpoint"]
    with pytest.raises(ValueError, match="sequence_invalid"):
        build_witness_policy_handoff_chain_membership_anchor_statement(
            endpoint["membership_anchor"],
            endpoint["current_chain_ref"],
            verified=True,
            authority_id="authority",
            statement_sequence=value,
            previous_statement_sha256=ZERO_SHA256,
            statement_provenance_sha256=digest_json({"proof": 1}),
        )


@pytest.mark.parametrize(
    "mutation,reason",
    [
        (
            lambda old, new: new.__setitem__("authority_id", "other"),
            "authority_mismatch",
        ),
        (
            lambda old, new: new.__setitem__("statement_sequence", 3),
            "sequence_discontinuity",
        ),
        (
            lambda old, new: new.__setitem__(
                "previous_statement_sha256", digest_json({"wrong": 1})
            ),
            "predecessor_mismatch",
        ),
        (lambda old, new: old.update({"unknown": True}), "statement_invalid"),
    ],
)
def test_authorized_transition_rejects_mismatches(mutation, reason) -> None:
    _, _, _, package = _case()
    old, new = _statements(package)
    mutation(old, new)
    decision = (
        verify_authorized_witness_policy_handoff_chain_membership_root_consistency(
            package, old, new
        )
    )
    assert decision.verified is False
    assert reason in decision.reason


def _fork_statements():
    fixture, packages, refs, package = _case()
    old, _ = _statements(package)
    canonical_anchor = build_witness_policy_handoff_chain_membership_anchor(
        packages[:2],
        refs[1],
        membership_contract_sha256=MEMBERSHIP_CONTRACT,
        authorization_contract_sha256=MEMBERSHIP_AUTHORIZATION,
    )
    alternate_packages = (packages[0], fixture["alternate_second_package"])
    alternate_refs = _refs(alternate_packages)
    alternate_anchor = build_witness_policy_handoff_chain_membership_anchor(
        alternate_packages,
        alternate_refs[1],
        membership_contract_sha256=MEMBERSHIP_CONTRACT,
        authorization_contract_sha256=MEMBERSHIP_AUTHORIZATION,
    )
    common = digest_json(old)
    statement_a = build_witness_policy_handoff_chain_membership_anchor_statement(
        canonical_anchor,
        refs[1],
        verified=True,
        authority_id="anchor-authority",
        statement_sequence=2,
        previous_statement_sha256=common,
        statement_provenance_sha256=digest_json({"fork": "a"}),
    )
    statement_b = build_witness_policy_handoff_chain_membership_anchor_statement(
        alternate_anchor,
        alternate_refs[1],
        verified=True,
        authority_id="anchor-authority",
        statement_sequence=2,
        previous_statement_sha256=common,
        statement_provenance_sha256=digest_json({"fork": "b"}),
    )
    return (
        canonical_anchor,
        refs[1],
        statement_a,
        alternate_anchor,
        alternate_refs[1],
        statement_b,
    )


def test_same_sequence_and_same_size_root_conflict_produce_exact_evidence() -> None:
    inputs = _fork_statements()
    decision = detect_witness_policy_handoff_chain_membership_anchor_equivocation(
        *inputs
    )
    assert decision.verified is True
    assert decision.reason == HANDOFF_CHAIN_MEMBERSHIP_EQUIVOCATION_DETECTED_REASON
    assert decision.equivocation_detected is True
    assert decision.evidence is not None
    assert set(decision.evidence) == EVIDENCE_KEYS
    assert decision.evidence["schema"] == (
        HANDOFF_CHAIN_MEMBERSHIP_EQUIVOCATION_EVIDENCE_SCHEMA
    )
    assert decision.evidence["detection_mode"] == "same-sequence-conflict"
    assert validate_witness_policy_handoff_chain_membership_equivocation_evidence(
        decision.evidence, *inputs
    )


def test_same_size_root_conflict_does_not_require_same_sequence() -> None:
    inputs = list(_fork_statements())
    statement_b = inputs[5]
    statement_b["statement_sequence"] = 3
    statement_b["previous_statement_sha256"] = digest_json({"statement": 2})
    decision = detect_witness_policy_handoff_chain_membership_anchor_equivocation(
        *inputs
    )
    assert decision.equivocation_detected is True
    assert decision.evidence["detection_mode"] == "same-size-root-conflict"


def test_different_authority_is_not_comparable_or_standalone_evidence() -> None:
    inputs = list(_fork_statements())
    inputs[5]["authority_id"] = "other-authority"
    decision = detect_witness_policy_handoff_chain_membership_anchor_equivocation(
        *inputs
    )
    assert decision.verified is True
    assert decision.equivocation_detected is False
    assert decision.reason == HANDOFF_CHAIN_MEMBERSHIP_EQUIVOCATION_NOT_PROVEN_REASON
    assert decision.evidence["authority_id"] is None
    assert decision.evidence["chain_id"] is None
    assert not validate_witness_policy_handoff_chain_membership_equivocation_evidence(
        decision.evidence, *inputs
    )


@pytest.mark.parametrize(
    "mutation",
    [
        lambda value: value.update({"unknown": True}),
        lambda value: value.__setitem__("verified", False),
        lambda value: value.__setitem__("equivocation_detected", False),
        lambda value: value.__setitem__("tree_size_a", True),
        lambda value: value.__setitem__(
            "statement_a_sha256", digest_json({"wrong": "statement"})
        ),
        lambda value: value.__setitem__(
            "anchor_b_sha256", digest_json({"wrong": "anchor"})
        ),
        lambda value: value.__setitem__(
            "current_chain_ref_a_sha256", digest_json({"wrong": "ref"})
        ),
    ],
)
def test_serialized_equivocation_evidence_recomputes_and_rejects_tampering(
    mutation,
) -> None:
    inputs = _fork_statements()
    decision = detect_witness_policy_handoff_chain_membership_anchor_equivocation(
        *inputs
    )
    evidence = deepcopy(decision.evidence)
    mutation(evidence)
    assert not validate_witness_policy_handoff_chain_membership_equivocation_evidence(
        evidence, *inputs
    )


def test_identical_statement_never_validates_as_equivocation_evidence() -> None:
    inputs = _fork_statements()
    same = inputs[:3] + inputs[:3]
    decision = detect_witness_policy_handoff_chain_membership_anchor_equivocation(
        *same
    )
    assert decision.verified is True
    assert decision.equivocation_detected is False
    assert not validate_witness_policy_handoff_chain_membership_equivocation_evidence(
        decision.evidence, *same
    )


def test_deeply_nested_proof_and_evidence_fail_closed() -> None:
    _, _, _, package = _case()
    nested = []
    cursor = nested
    for _ in range(sys.getrecursionlimit() + 10):
        child = []
        cursor.append(child)
        cursor = child
    package["old_endpoint"]["membership_anchor"] = nested
    assert not verify_witness_policy_handoff_chain_membership_root_consistency(
        package
    ).verified
    inputs = _fork_statements()
    decision = detect_witness_policy_handoff_chain_membership_anchor_equivocation(
        *inputs
    )
    evidence = deepcopy(decision.evidence)
    evidence["statement_a_sha256"] = nested
    assert not validate_witness_policy_handoff_chain_membership_equivocation_evidence(
        evidence, *inputs
    )


def test_all_consistency_symbols_are_exported_from_root_api() -> None:
    expected = {
        "HANDOFF_CHAIN_MEMBERSHIP_ANCHOR_STATEMENT_SCHEMA",
        "HANDOFF_CHAIN_MEMBERSHIP_AUTHORIZED_CONSISTENCY_REASON",
        "HANDOFF_CHAIN_MEMBERSHIP_EQUIVOCATION_DETECTED_REASON",
        "HANDOFF_CHAIN_MEMBERSHIP_EQUIVOCATION_EVIDENCE_SCHEMA",
        "HANDOFF_CHAIN_MEMBERSHIP_EQUIVOCATION_NOT_PROVEN_REASON",
        "HANDOFF_CHAIN_MEMBERSHIP_ROLLING_DESCENDANCE_STATUS",
        "HANDOFF_CHAIN_MEMBERSHIP_ROOT_CONSISTENCY_ALGORITHM",
        "HANDOFF_CHAIN_MEMBERSHIP_ROOT_CONSISTENCY_PACKAGE_SCHEMA",
        "HANDOFF_CHAIN_MEMBERSHIP_ROOT_CONSISTENCY_PROOF_SCHEMA",
        "HANDOFF_CHAIN_MEMBERSHIP_ROOT_CONSISTENCY_REASON",
        "AuthorizedWitnessPolicyHandoffChainMembershipRootConsistencyDecision",
        "WitnessPolicyHandoffChainMembershipEquivocationDecision",
        "WitnessPolicyHandoffChainMembershipRootConsistencyDecision",
        "build_witness_policy_handoff_chain_membership_anchor_statement",
        "build_witness_policy_handoff_chain_membership_root_consistency_package",
        "detect_witness_policy_handoff_chain_membership_anchor_equivocation",
        "validate_witness_policy_handoff_chain_membership_anchor_statement",
        "validate_witness_policy_handoff_chain_membership_equivocation_evidence",
        "verify_authorized_witness_policy_handoff_chain_membership_root_consistency",
        "verify_witness_policy_handoff_chain_membership_root_consistency",
    }
    assert expected <= set(ttrace.__all__)
    assert all(hasattr(ttrace, name) for name in expected)
