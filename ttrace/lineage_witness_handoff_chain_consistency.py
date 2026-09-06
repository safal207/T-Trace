"""Append-only consistency for witness-policy handoff membership roots.

The handoff-chain membership profile binds validated step commitments to a
duplicate-last Merkle tree.  This companion profile proves that a later root is
an append-only extension of an earlier root with a compact frontier.  It also
defines context-bound authority statements and bounded, independently
recomputable equivocation evidence.

The standalone consistency verifier deliberately does not claim that hidden
handoff packages were semantically revalidated, that either presented tip is
fresh, or that the later rolling chain reference descends from the earlier one.
The builder checks the retained histories and the exact boundary reference; the
serialized proof only establishes the root and current-step relationships that
it carries.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

from .lineage_compaction import ZERO_SHA256
from .lineage_consistency import GLOBAL_NON_EQUIVOCATION_STATUS
from .lineage_witness_handoff_chain_membership import (
    HANDOFF_CHAIN_MEMBERSHIP_ANCHOR_AUTHORIZATION_STATUS,
    HANDOFF_CHAIN_MEMBERSHIP_CURRENT_TIP_FRESHNESS_STATUS,
    HANDOFF_CHAIN_MEMBERSHIP_TREE_ALGORITHM,
    _build_anchor,
    _leaf_hash,
    _merkle_path,
    _node_hash,
    _validate_handoff_history,
    _verify_merkle_path,
    validate_witness_policy_handoff_chain_membership_anchor,
)
from .portable_causality import canonical_json_bytes, digest_json, is_sha256


HANDOFF_CHAIN_MEMBERSHIP_ROOT_CONSISTENCY_PROOF_SCHEMA = (
    "ttrace-witness-policy-handoff-chain-membership-root-consistency-proof/v0.1"
)
HANDOFF_CHAIN_MEMBERSHIP_ROOT_CONSISTENCY_PACKAGE_SCHEMA = (
    "ttrace-witness-policy-handoff-chain-membership-root-consistency-package/v0.1"
)
HANDOFF_CHAIN_MEMBERSHIP_ANCHOR_STATEMENT_SCHEMA = (
    "ttrace-witness-policy-handoff-chain-membership-anchor-statement/v0.1"
)
HANDOFF_CHAIN_MEMBERSHIP_EQUIVOCATION_EVIDENCE_SCHEMA = (
    "ttrace-witness-policy-handoff-chain-membership-anchor-equivocation-evidence/v0.1"
)
HANDOFF_CHAIN_MEMBERSHIP_ROOT_CONSISTENCY_ALGORITHM = (
    "compact-frontier-over-pairwise-duplicate-last-sha256/v0.1"
)
HANDOFF_CHAIN_MEMBERSHIP_ROOT_CONSISTENCY_REASON = (
    "witness_policy_handoff_chain_membership_root_consistency_verified"
)
HANDOFF_CHAIN_MEMBERSHIP_AUTHORIZED_CONSISTENCY_REASON = (
    "authorized_witness_policy_handoff_chain_membership_root_consistency_verified"
)
HANDOFF_CHAIN_MEMBERSHIP_EQUIVOCATION_DETECTED_REASON = (
    "witness_policy_handoff_chain_membership_anchor_equivocation_detected"
)
HANDOFF_CHAIN_MEMBERSHIP_EQUIVOCATION_NOT_PROVEN_REASON = (
    "witness_policy_handoff_chain_membership_anchor_equivocation_not_proven"
)
HANDOFF_CHAIN_MEMBERSHIP_ROLLING_DESCENDANCE_STATUS = (
    "not-independently-proven"
)

_BLOCK_KEYS = {"start", "size", "sha256"}
_ENDPOINT_KEYS = {"membership_anchor", "current_chain_ref"}
_PROOF_KEYS = {
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
_PACKAGE_KEYS = {
    "schema",
    "old_endpoint",
    "new_endpoint",
    "consistency_proof",
}
_STATEMENT_KEYS = {
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
_EQUIVOCATION_EVIDENCE_KEYS = {
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
_PATH_ENTRY_KEYS = {"side", "sha256"}
_SHARED_CONTEXT_FIELDS = (
    "chain_id",
    "policy_id",
    "genesis_policy_epoch",
    "genesis_policy_sha256",
    "tree_algorithm",
    "chain_contract_sha256",
    "chain_authorization_contract_sha256",
    "membership_contract_sha256",
    "authorization_contract_sha256",
)


@dataclass(frozen=True)
class WitnessPolicyHandoffChainMembershipRootConsistencyDecision:
    """Machine-readable result for one compact append-only root proof."""

    verified: bool
    reason: str
    old_tree_size: Optional[int] = None
    new_tree_size: Optional[int] = None
    old_anchor_sha256: Optional[str] = None
    new_anchor_sha256: Optional[str] = None
    old_frontier_node_count: Optional[int] = None
    append_block_count: Optional[int] = None
    old_current_path_hash_count: Optional[int] = None
    new_current_path_hash_count: Optional[int] = None
    append_only_consistent: bool = False
    current_steps_membership_bound: bool = False
    raw_handoff_packages_disclosed: bool = False
    membership_anchor_authorization_status: str = (
        HANDOFF_CHAIN_MEMBERSHIP_ANCHOR_AUTHORIZATION_STATUS
    )
    current_tip_freshness_status: str = (
        HANDOFF_CHAIN_MEMBERSHIP_CURRENT_TIP_FRESHNESS_STATUS
    )
    rolling_chain_descendance_status: str = (
        HANDOFF_CHAIN_MEMBERSHIP_ROLLING_DESCENDANCE_STATUS
    )
    global_non_equivocation_status: str = GLOBAL_NON_EQUIVOCATION_STATUS


@dataclass(frozen=True)
class AuthorizedWitnessPolicyHandoffChainMembershipRootConsistencyDecision:
    """Root consistency bound to a direct authority-statement transition."""

    verified: bool
    reason: str
    authority_id: Optional[str] = None
    old_statement_sha256: Optional[str] = None
    new_statement_sha256: Optional[str] = None
    append_only_consistent: bool = False
    authority_chain_continuous: bool = False
    presented_equivocation_detected: bool = False
    rolling_chain_descendance_status: str = (
        HANDOFF_CHAIN_MEMBERSHIP_ROLLING_DESCENDANCE_STATUS
    )
    global_non_equivocation_status: str = GLOBAL_NON_EQUIVOCATION_STATUS


@dataclass(frozen=True)
class WitnessPolicyHandoffChainMembershipEquivocationDecision:
    """Conflict verdict for two externally verified membership statements."""

    verified: bool
    reason: str
    equivocation_detected: bool = False
    evidence: Optional[Dict[str, Any]] = None
    global_non_equivocation_status: str = GLOBAL_NON_EQUIVOCATION_STATUS


def _text(value: Any) -> bool:
    return isinstance(value, str) and bool(value)


def _positive_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value > 0


def _zero_based_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def _power_of_two(value: Any) -> bool:
    return _positive_int(value) and value & (value - 1) == 0


def _nonzero_sha(value: Any) -> bool:
    return is_sha256(value) and value != ZERO_SHA256


def _subtree_root(
    leaf_hashes: Sequence[str], start: int, size: int
) -> str:
    if (
        not _power_of_two(size)
        or not _zero_based_int(start)
        or start % size != 0
        or start + size > len(leaf_hashes)
    ):
        raise ValueError("handoff_chain_consistency_subtree_range_invalid")
    if size == 1:
        leaf = leaf_hashes[start]
        if not _nonzero_sha(leaf):
            raise ValueError("handoff_chain_consistency_leaf_invalid")
        return leaf
    half = size // 2
    return _node_hash(
        _subtree_root(leaf_hashes, start, half),
        _subtree_root(leaf_hashes, start + half, half),
    )


def _prefix_block_shapes(tree_size: int) -> Tuple[Tuple[int, int], ...]:
    if not _positive_int(tree_size):
        raise ValueError("handoff_chain_consistency_tree_size_invalid")
    blocks: List[Tuple[int, int]] = []
    start = 0
    remaining = tree_size
    while remaining:
        size = 1 << (remaining.bit_length() - 1)
        blocks.append((start, size))
        start += size
        remaining -= size
    return tuple(blocks)


def _suffix_block_shapes(
    start: int, end: int
) -> Tuple[Tuple[int, int], ...]:
    if not _zero_based_int(start) or not _positive_int(end) or end <= start:
        raise ValueError("handoff_chain_consistency_append_range_invalid")
    blocks: List[Tuple[int, int]] = []
    cursor = start
    while cursor < end:
        remaining = end - cursor
        size = (
            1 << (remaining.bit_length() - 1)
            if cursor == 0
            else cursor & -cursor
        )
        while size > remaining:
            size //= 2
        blocks.append((cursor, size))
        cursor += size
    return tuple(blocks)


def _build_blocks(
    leaf_hashes: Sequence[str], shapes: Sequence[Tuple[int, int]]
) -> List[Dict[str, Any]]:
    return [
        {
            "start": start,
            "size": size,
            "sha256": _subtree_root(leaf_hashes, start, size),
        }
        for start, size in shapes
    ]


def _valid_block(value: Any) -> bool:
    return (
        isinstance(value, Mapping)
        and set(value) == _BLOCK_KEYS
        and _zero_based_int(value.get("start"))
        and _power_of_two(value.get("size"))
        and _nonzero_sha(value.get("sha256"))
    )


def _validate_block_shapes(
    values: Any, expected_shapes: Sequence[Tuple[int, int]]
) -> bool:
    if not isinstance(values, list) or len(values) != len(expected_shapes):
        return False
    return all(
        _valid_block(value)
        and value.get("start") == start
        and value.get("size") == size
        for value, (start, size) in zip(values, expected_shapes)
    )


def _bag_frontier_to_membership_root(
    frontier: Sequence[Mapping[str, Any]],
) -> str:
    """Reconstruct the duplicate-last membership root from compact peaks."""

    if not frontier:
        raise ValueError("handoff_chain_consistency_frontier_empty")
    accumulator_sha256 = str(frontier[-1]["sha256"])
    accumulator_size = frontier[-1]["size"]
    if not _positive_int(accumulator_size):
        raise ValueError("handoff_chain_consistency_frontier_shape_invalid")
    for block in reversed(frontier[:-1]):
        block_size = block["size"]
        if not _positive_int(block_size):
            raise ValueError("handoff_chain_consistency_frontier_shape_invalid")
        while accumulator_size < block_size:
            accumulator_sha256 = _node_hash(
                accumulator_sha256, accumulator_sha256
            )
            accumulator_size *= 2
        if accumulator_size != block_size:
            raise ValueError("handoff_chain_consistency_frontier_shape_invalid")
        accumulator_sha256 = _node_hash(
            str(block["sha256"]), accumulator_sha256
        )
        accumulator_size *= 2
    return accumulator_sha256


def _append_block(
    frontier: Sequence[Mapping[str, Any]], block: Mapping[str, Any]
) -> List[Dict[str, Any]]:
    if not _valid_block(block):
        raise ValueError("handoff_chain_consistency_append_block_invalid")
    result = [dict(item) for item in frontier]
    covered = sum(item["size"] for item in result)
    if block.get("start") != covered:
        raise ValueError("handoff_chain_consistency_append_block_start_invalid")
    result.append(dict(block))
    while len(result) >= 2:
        left = result[-2]
        right = result[-1]
        if (
            left["size"] != right["size"]
            or left["start"] + left["size"] != right["start"]
        ):
            break
        parent_size = left["size"] * 2
        if left["start"] % parent_size != 0:
            raise ValueError("handoff_chain_consistency_append_alignment_invalid")
        result[-2:] = [
            {
                "start": left["start"],
                "size": parent_size,
                "sha256": _node_hash(left["sha256"], right["sha256"]),
            }
        ]
    return result


def _validated_endpoint(
    value: Any,
) -> Tuple[Mapping[str, Any], Mapping[str, Any]]:
    if not isinstance(value, Mapping) or set(value) != _ENDPOINT_KEYS:
        raise ValueError("handoff_chain_consistency_endpoint_shape_invalid")
    anchor = value.get("membership_anchor")
    current_chain_ref = value.get("current_chain_ref")
    if not validate_witness_policy_handoff_chain_membership_anchor(
        anchor, current_chain_ref
    ):
        raise ValueError("handoff_chain_consistency_membership_anchor_invalid")
    assert isinstance(anchor, Mapping)
    assert isinstance(current_chain_ref, Mapping)
    return anchor, current_chain_ref


def _same_membership_context(
    old_anchor: Mapping[str, Any], new_anchor: Mapping[str, Any]
) -> None:
    reasons = {
        "chain_id": "handoff_chain_consistency_chain_id_mismatch",
        "policy_id": "handoff_chain_consistency_policy_id_mismatch",
        "genesis_policy_epoch": (
            "handoff_chain_consistency_genesis_policy_epoch_mismatch"
        ),
        "genesis_policy_sha256": (
            "handoff_chain_consistency_genesis_policy_mismatch"
        ),
        "tree_algorithm": "handoff_chain_consistency_tree_algorithm_mismatch",
        "chain_contract_sha256": (
            "handoff_chain_consistency_chain_contract_mismatch"
        ),
        "chain_authorization_contract_sha256": (
            "handoff_chain_consistency_chain_authorization_contract_mismatch"
        ),
        "membership_contract_sha256": (
            "handoff_chain_consistency_membership_contract_mismatch"
        ),
        "authorization_contract_sha256": (
            "handoff_chain_consistency_authorization_contract_mismatch"
        ),
    }
    for field in _SHARED_CONTEXT_FIELDS:
        if old_anchor.get(field) != new_anchor.get(field):
            raise ValueError(reasons[field])


def build_witness_policy_handoff_chain_membership_root_consistency_package(
    old_handoff_packages: Sequence[Mapping[str, Any]],
    old_current_chain_ref: Mapping[str, Any],
    new_handoff_packages: Sequence[Mapping[str, Any]],
    new_current_chain_ref: Mapping[str, Any],
    *,
    membership_contract_sha256: str,
    authorization_contract_sha256: str,
) -> Dict[str, Any]:
    """Build a compact proof after validating both retained histories."""

    if not _nonzero_sha(membership_contract_sha256):
        raise ValueError("handoff_chain_consistency_membership_contract_invalid")
    if not _nonzero_sha(authorization_contract_sha256):
        raise ValueError("handoff_chain_consistency_authorization_contract_invalid")
    old_handoffs = _validate_handoff_history(
        old_handoff_packages, old_current_chain_ref
    )
    new_handoffs = _validate_handoff_history(
        new_handoff_packages, new_current_chain_ref
    )
    old_size = len(old_handoffs)
    new_size = len(new_handoffs)
    if old_size >= new_size:
        raise ValueError("handoff_chain_consistency_tree_not_extended")
    old_commitments = tuple(
        item.step_commitment_sha256 for item in old_handoffs
    )
    new_commitments = tuple(
        item.step_commitment_sha256 for item in new_handoffs
    )
    if tuple(new_commitments[:old_size]) != old_commitments:
        raise ValueError("handoff_chain_consistency_prefix_mismatch")
    if canonical_json_bytes(new_handoffs[old_size - 1].chain_ref) != (
        canonical_json_bytes(old_current_chain_ref)
    ):
        raise ValueError("handoff_chain_consistency_boundary_ref_mismatch")

    old_anchor = _build_anchor(
        old_handoffs,
        old_current_chain_ref,
        membership_contract_sha256=membership_contract_sha256,
        authorization_contract_sha256=authorization_contract_sha256,
    )
    new_anchor = _build_anchor(
        new_handoffs,
        new_current_chain_ref,
        membership_contract_sha256=membership_contract_sha256,
        authorization_contract_sha256=authorization_contract_sha256,
    )
    old_leaf_hashes = [
        _leaf_hash(index, commitment)
        for index, commitment in enumerate(old_commitments, start=1)
    ]
    new_leaf_hashes = [
        _leaf_hash(index, commitment)
        for index, commitment in enumerate(new_commitments, start=1)
    ]
    proof = {
        "schema": HANDOFF_CHAIN_MEMBERSHIP_ROOT_CONSISTENCY_PROOF_SCHEMA,
        "old_anchor_sha256": digest_json(old_anchor),
        "new_anchor_sha256": digest_json(new_anchor),
        "old_tree_size": old_size,
        "new_tree_size": new_size,
        "membership_tree_algorithm": HANDOFF_CHAIN_MEMBERSHIP_TREE_ALGORITHM,
        "consistency_algorithm": (
            HANDOFF_CHAIN_MEMBERSHIP_ROOT_CONSISTENCY_ALGORITHM
        ),
        "old_frontier": _build_blocks(
            old_leaf_hashes, _prefix_block_shapes(old_size)
        ),
        "append_blocks": _build_blocks(
            new_leaf_hashes, _suffix_block_shapes(old_size, new_size)
        ),
        "old_current_step_sibling_path": _merkle_path(
            old_leaf_hashes, old_size - 1
        ),
        "new_current_step_sibling_path": _merkle_path(
            new_leaf_hashes, new_size - 1
        ),
    }
    package = {
        "schema": HANDOFF_CHAIN_MEMBERSHIP_ROOT_CONSISTENCY_PACKAGE_SCHEMA,
        "old_endpoint": {
            "membership_anchor": old_anchor,
            "current_chain_ref": dict(old_current_chain_ref),
        },
        "new_endpoint": {
            "membership_anchor": new_anchor,
            "current_chain_ref": dict(new_current_chain_ref),
        },
        "consistency_proof": proof,
    }
    decision = (
        verify_witness_policy_handoff_chain_membership_root_consistency(package)
    )
    if not decision.verified:
        raise ValueError(
            f"handoff_chain_consistency_package_invalid:{decision.reason}"
        )
    return package


def verify_witness_policy_handoff_chain_membership_root_consistency(
    value: Any,
) -> WitnessPolicyHandoffChainMembershipRootConsistencyDecision:
    """Verify compact append-only root consistency and both current-step paths."""

    try:
        if not isinstance(value, Mapping) or set(value) != _PACKAGE_KEYS:
            raise ValueError("handoff_chain_consistency_package_shape_invalid")
        if (
            value.get("schema")
            != HANDOFF_CHAIN_MEMBERSHIP_ROOT_CONSISTENCY_PACKAGE_SCHEMA
        ):
            raise ValueError("handoff_chain_consistency_package_schema_invalid")
        old_anchor, _ = _validated_endpoint(value.get("old_endpoint"))
        new_anchor, _ = _validated_endpoint(value.get("new_endpoint"))
        proof = value.get("consistency_proof")
        if not isinstance(proof, Mapping) or set(proof) != _PROOF_KEYS:
            raise ValueError("handoff_chain_consistency_proof_shape_invalid")
        if (
            proof.get("schema")
            != HANDOFF_CHAIN_MEMBERSHIP_ROOT_CONSISTENCY_PROOF_SCHEMA
        ):
            raise ValueError("handoff_chain_consistency_proof_schema_invalid")

        old_size = old_anchor.get("tree_size")
        new_size = new_anchor.get("tree_size")
        if not _positive_int(old_size) or not _positive_int(new_size):
            raise ValueError("handoff_chain_consistency_tree_size_invalid")
        assert isinstance(old_size, int)
        assert isinstance(new_size, int)
        if old_size >= new_size:
            raise ValueError("handoff_chain_consistency_tree_not_extended")
        if not _positive_int(proof.get("old_tree_size")):
            raise ValueError("handoff_chain_consistency_old_tree_size_invalid")
        if not _positive_int(proof.get("new_tree_size")):
            raise ValueError("handoff_chain_consistency_new_tree_size_invalid")
        if proof.get("old_tree_size") != old_size:
            raise ValueError("handoff_chain_consistency_old_tree_size_mismatch")
        if proof.get("new_tree_size") != new_size:
            raise ValueError("handoff_chain_consistency_new_tree_size_mismatch")
        if proof.get("old_anchor_sha256") != digest_json(old_anchor):
            raise ValueError("handoff_chain_consistency_old_anchor_mismatch")
        if proof.get("new_anchor_sha256") != digest_json(new_anchor):
            raise ValueError("handoff_chain_consistency_new_anchor_mismatch")
        if (
            proof.get("membership_tree_algorithm")
            != HANDOFF_CHAIN_MEMBERSHIP_TREE_ALGORITHM
            or old_anchor.get("tree_algorithm")
            != HANDOFF_CHAIN_MEMBERSHIP_TREE_ALGORITHM
            or new_anchor.get("tree_algorithm")
            != HANDOFF_CHAIN_MEMBERSHIP_TREE_ALGORITHM
        ):
            raise ValueError(
                "handoff_chain_consistency_membership_algorithm_invalid"
            )
        if (
            proof.get("consistency_algorithm")
            != HANDOFF_CHAIN_MEMBERSHIP_ROOT_CONSISTENCY_ALGORITHM
        ):
            raise ValueError("handoff_chain_consistency_algorithm_invalid")

        _same_membership_context(old_anchor, new_anchor)
        if (
            old_anchor.get("completed_handoffs") != old_size
            or new_anchor.get("completed_handoffs") != new_size
        ):
            raise ValueError("handoff_chain_consistency_handoff_count_mismatch")
        if not _positive_int(old_anchor.get("current_policy_epoch")) or not (
            _positive_int(new_anchor.get("current_policy_epoch"))
        ):
            raise ValueError("handoff_chain_consistency_policy_epoch_invalid")
        if new_anchor["current_policy_epoch"] <= old_anchor["current_policy_epoch"]:
            raise ValueError("handoff_chain_consistency_policy_epoch_not_advanced")

        old_frontier = proof.get("old_frontier")
        if not _validate_block_shapes(
            old_frontier, _prefix_block_shapes(old_size)
        ):
            raise ValueError("handoff_chain_consistency_old_frontier_invalid")
        assert isinstance(old_frontier, list)
        old_root = _bag_frontier_to_membership_root(old_frontier)
        if old_root != old_anchor.get("step_commitment_merkle_root_sha256"):
            raise ValueError("handoff_chain_consistency_old_root_mismatch")

        append_blocks = proof.get("append_blocks")
        if not _validate_block_shapes(
            append_blocks, _suffix_block_shapes(old_size, new_size)
        ):
            raise ValueError("handoff_chain_consistency_append_blocks_invalid")
        assert isinstance(append_blocks, list)
        new_frontier: List[Dict[str, Any]] = [
            dict(item) for item in old_frontier
        ]
        for block in append_blocks:
            assert isinstance(block, Mapping)
            new_frontier = _append_block(new_frontier, block)
        if not _validate_block_shapes(
            new_frontier, _prefix_block_shapes(new_size)
        ):
            raise ValueError("handoff_chain_consistency_new_frontier_invalid")
        new_root = _bag_frontier_to_membership_root(new_frontier)
        if new_root != new_anchor.get("step_commitment_merkle_root_sha256"):
            raise ValueError("handoff_chain_consistency_new_root_mismatch")

        old_current_leaf = _leaf_hash(
            old_size, str(old_anchor["current_step_commitment_sha256"])
        )
        if not _verify_merkle_path(
            leaf_sha256=old_current_leaf,
            leaf_index=old_size - 1,
            tree_size=old_size,
            sibling_path=proof.get("old_current_step_sibling_path"),
            expected_root_sha256=str(
                old_anchor["step_commitment_merkle_root_sha256"]
            ),
        ):
            raise ValueError("handoff_chain_consistency_old_current_step_not_bound")
        new_current_leaf = _leaf_hash(
            new_size, str(new_anchor["current_step_commitment_sha256"])
        )
        if not _verify_merkle_path(
            leaf_sha256=new_current_leaf,
            leaf_index=new_size - 1,
            tree_size=new_size,
            sibling_path=proof.get("new_current_step_sibling_path"),
            expected_root_sha256=str(
                new_anchor["step_commitment_merkle_root_sha256"]
            ),
        ):
            raise ValueError("handoff_chain_consistency_new_current_step_not_bound")

        return WitnessPolicyHandoffChainMembershipRootConsistencyDecision(
            True,
            HANDOFF_CHAIN_MEMBERSHIP_ROOT_CONSISTENCY_REASON,
            old_tree_size=old_size,
            new_tree_size=new_size,
            old_anchor_sha256=digest_json(old_anchor),
            new_anchor_sha256=digest_json(new_anchor),
            old_frontier_node_count=len(old_frontier),
            append_block_count=len(append_blocks),
            old_current_path_hash_count=len(
                proof["old_current_step_sibling_path"]
            ),
            new_current_path_hash_count=len(
                proof["new_current_step_sibling_path"]
            ),
            append_only_consistent=True,
            current_steps_membership_bound=True,
            raw_handoff_packages_disclosed=False,
        )
    except RecursionError:
        return WitnessPolicyHandoffChainMembershipRootConsistencyDecision(
            False, "handoff_chain_consistency_proof_too_deep"
        )
    except (KeyError, TypeError, ValueError) as error:
        return WitnessPolicyHandoffChainMembershipRootConsistencyDecision(
            False, str(error)
        )


def build_witness_policy_handoff_chain_membership_anchor_statement(
    membership_anchor: Mapping[str, Any],
    current_chain_ref: Mapping[str, Any],
    *,
    verified: bool,
    authority_id: str,
    statement_sequence: int,
    previous_statement_sha256: str,
    statement_provenance_sha256: str,
) -> Dict[str, Any]:
    """Normalize one externally verified statement in its full context."""

    if not validate_witness_policy_handoff_chain_membership_anchor(
        membership_anchor, current_chain_ref
    ):
        raise ValueError("handoff_chain_anchor_statement_membership_anchor_invalid")
    if verified is not True:
        raise ValueError("handoff_chain_anchor_statement_unverified")
    if not _text(authority_id):
        raise ValueError("handoff_chain_anchor_statement_authority_invalid")
    if not _positive_int(statement_sequence):
        raise ValueError("handoff_chain_anchor_statement_sequence_invalid")
    if not _nonzero_sha(statement_provenance_sha256):
        raise ValueError("handoff_chain_anchor_statement_provenance_invalid")
    if statement_sequence == 1:
        if previous_statement_sha256 != ZERO_SHA256:
            raise ValueError(
                "handoff_chain_anchor_statement_seed_predecessor_invalid"
            )
    elif not _nonzero_sha(previous_statement_sha256):
        raise ValueError("handoff_chain_anchor_statement_predecessor_invalid")

    statement = {
        "schema": HANDOFF_CHAIN_MEMBERSHIP_ANCHOR_STATEMENT_SCHEMA,
        "verified": True,
        "authority_id": authority_id,
        "statement_sequence": statement_sequence,
        "previous_statement_sha256": previous_statement_sha256,
        "statement_provenance_sha256": statement_provenance_sha256,
        "chain_id": membership_anchor["chain_id"],
        "policy_id": membership_anchor["policy_id"],
        "genesis_policy_epoch": membership_anchor["genesis_policy_epoch"],
        "genesis_policy_sha256": membership_anchor["genesis_policy_sha256"],
        "tree_size": membership_anchor["tree_size"],
        "anchor_sha256": digest_json(membership_anchor),
        "membership_root_sha256": membership_anchor[
            "step_commitment_merkle_root_sha256"
        ],
        "current_chain_ref_sha256": digest_json(current_chain_ref),
        "current_chain_root_sha256": membership_anchor[
            "current_chain_root_sha256"
        ],
        "current_step_commitment_sha256": membership_anchor[
            "current_step_commitment_sha256"
        ],
        "current_policy_epoch": membership_anchor["current_policy_epoch"],
        "current_policy_sha256": membership_anchor["current_policy_sha256"],
        "tree_algorithm": membership_anchor["tree_algorithm"],
        "chain_contract_sha256": membership_anchor["chain_contract_sha256"],
        "chain_authorization_contract_sha256": membership_anchor[
            "chain_authorization_contract_sha256"
        ],
        "membership_contract_sha256": membership_anchor[
            "membership_contract_sha256"
        ],
        "authorization_contract_sha256": membership_anchor[
            "authorization_contract_sha256"
        ],
    }
    if not validate_witness_policy_handoff_chain_membership_anchor_statement(
        statement, membership_anchor, current_chain_ref
    ):
        raise ValueError("handoff_chain_anchor_statement_invalid")
    return statement


def validate_witness_policy_handoff_chain_membership_anchor_statement(
    statement: Any, membership_anchor: Any, current_chain_ref: Any
) -> bool:
    """Validate exact statement shape and bind every endpoint context field."""

    try:
        if (
            not isinstance(statement, Mapping)
            or set(statement) != _STATEMENT_KEYS
            or not validate_witness_policy_handoff_chain_membership_anchor(
                membership_anchor, current_chain_ref
            )
        ):
            return False
        assert isinstance(membership_anchor, Mapping)
        assert isinstance(current_chain_ref, Mapping)
        sequence = statement.get("statement_sequence")
        previous = statement.get("previous_statement_sha256")
        expected = {
            "chain_id": membership_anchor.get("chain_id"),
            "policy_id": membership_anchor.get("policy_id"),
            "genesis_policy_epoch": membership_anchor.get(
                "genesis_policy_epoch"
            ),
            "genesis_policy_sha256": membership_anchor.get(
                "genesis_policy_sha256"
            ),
            "tree_size": membership_anchor.get("tree_size"),
            "anchor_sha256": digest_json(membership_anchor),
            "membership_root_sha256": membership_anchor.get(
                "step_commitment_merkle_root_sha256"
            ),
            "current_chain_ref_sha256": digest_json(current_chain_ref),
            "current_chain_root_sha256": membership_anchor.get(
                "current_chain_root_sha256"
            ),
            "current_step_commitment_sha256": membership_anchor.get(
                "current_step_commitment_sha256"
            ),
            "current_policy_epoch": membership_anchor.get(
                "current_policy_epoch"
            ),
            "current_policy_sha256": membership_anchor.get(
                "current_policy_sha256"
            ),
            "tree_algorithm": membership_anchor.get("tree_algorithm"),
            "chain_contract_sha256": membership_anchor.get(
                "chain_contract_sha256"
            ),
            "chain_authorization_contract_sha256": membership_anchor.get(
                "chain_authorization_contract_sha256"
            ),
            "membership_contract_sha256": membership_anchor.get(
                "membership_contract_sha256"
            ),
            "authorization_contract_sha256": membership_anchor.get(
                "authorization_contract_sha256"
            ),
        }
        return (
            statement.get("schema")
            == HANDOFF_CHAIN_MEMBERSHIP_ANCHOR_STATEMENT_SCHEMA
            and statement.get("verified") is True
            and _text(statement.get("authority_id"))
            and _positive_int(sequence)
            and (
                previous == ZERO_SHA256
                if sequence == 1
                else _nonzero_sha(previous)
            )
            and _nonzero_sha(statement.get("statement_provenance_sha256"))
            and all(statement.get(field) == value for field, value in expected.items())
        )
    except RecursionError:
        return False
    except (KeyError, TypeError, ValueError):
        return False


def verify_authorized_witness_policy_handoff_chain_membership_root_consistency(
    package: Any, old_statement: Any, new_statement: Any
) -> AuthorizedWitnessPolicyHandoffChainMembershipRootConsistencyDecision:
    """Verify root consistency plus direct authority-statement continuity."""

    consistency = (
        verify_witness_policy_handoff_chain_membership_root_consistency(package)
    )
    if not consistency.verified:
        return AuthorizedWitnessPolicyHandoffChainMembershipRootConsistencyDecision(
            False, consistency.reason
        )
    assert isinstance(package, Mapping)
    old_endpoint = package["old_endpoint"]
    new_endpoint = package["new_endpoint"]
    if not validate_witness_policy_handoff_chain_membership_anchor_statement(
        old_statement,
        old_endpoint["membership_anchor"],
        old_endpoint["current_chain_ref"],
    ):
        return AuthorizedWitnessPolicyHandoffChainMembershipRootConsistencyDecision(
            False, "old_handoff_chain_anchor_statement_invalid"
        )
    if not validate_witness_policy_handoff_chain_membership_anchor_statement(
        new_statement,
        new_endpoint["membership_anchor"],
        new_endpoint["current_chain_ref"],
    ):
        return AuthorizedWitnessPolicyHandoffChainMembershipRootConsistencyDecision(
            False, "new_handoff_chain_anchor_statement_invalid"
        )
    assert isinstance(old_statement, Mapping)
    assert isinstance(new_statement, Mapping)
    if old_statement.get("authority_id") != new_statement.get("authority_id"):
        return AuthorizedWitnessPolicyHandoffChainMembershipRootConsistencyDecision(
            False, "handoff_chain_anchor_statement_authority_mismatch"
        )
    if new_statement["statement_sequence"] != (
        old_statement["statement_sequence"] + 1
    ):
        return AuthorizedWitnessPolicyHandoffChainMembershipRootConsistencyDecision(
            False, "handoff_chain_anchor_statement_sequence_discontinuity"
        )
    if new_statement.get("previous_statement_sha256") != digest_json(
        old_statement
    ):
        return AuthorizedWitnessPolicyHandoffChainMembershipRootConsistencyDecision(
            False, "handoff_chain_anchor_statement_predecessor_mismatch"
        )
    return AuthorizedWitnessPolicyHandoffChainMembershipRootConsistencyDecision(
        True,
        HANDOFF_CHAIN_MEMBERSHIP_AUTHORIZED_CONSISTENCY_REASON,
        authority_id=str(old_statement["authority_id"]),
        old_statement_sha256=digest_json(old_statement),
        new_statement_sha256=digest_json(new_statement),
        append_only_consistent=True,
        authority_chain_continuous=True,
        presented_equivocation_detected=False,
    )


def _statements_comparable(
    statement_a: Mapping[str, Any], statement_b: Mapping[str, Any]
) -> bool:
    return statement_a.get("authority_id") == statement_b.get(
        "authority_id"
    ) and all(
        statement_a.get(field) == statement_b.get(field)
        for field in _SHARED_CONTEXT_FIELDS
    )


def detect_witness_policy_handoff_chain_membership_anchor_equivocation(
    anchor_a: Any,
    current_chain_ref_a: Any,
    statement_a: Any,
    anchor_b: Any,
    current_chain_ref_b: Any,
    statement_b: Any,
) -> WitnessPolicyHandoffChainMembershipEquivocationDecision:
    """Compare two presented, endpoint-bound statements for a direct conflict."""

    try:
        if not validate_witness_policy_handoff_chain_membership_anchor_statement(
            statement_a, anchor_a, current_chain_ref_a
        ) or not validate_witness_policy_handoff_chain_membership_anchor_statement(
            statement_b, anchor_b, current_chain_ref_b
        ):
            return WitnessPolicyHandoffChainMembershipEquivocationDecision(
                False, "handoff_chain_anchor_statement_invalid"
            )
        assert isinstance(anchor_a, Mapping)
        assert isinstance(anchor_b, Mapping)
        assert isinstance(current_chain_ref_a, Mapping)
        assert isinstance(current_chain_ref_b, Mapping)
        assert isinstance(statement_a, Mapping)
        assert isinstance(statement_b, Mapping)

        comparable = _statements_comparable(statement_a, statement_b)
        mode: Optional[str] = None
        if comparable:
            if (
                statement_a.get("statement_sequence")
                == statement_b.get("statement_sequence")
                and statement_a.get("previous_statement_sha256")
                == statement_b.get("previous_statement_sha256")
                and statement_a.get("anchor_sha256")
                != statement_b.get("anchor_sha256")
            ):
                mode = "same-sequence-conflict"
            elif (
                statement_a.get("tree_size") == statement_b.get("tree_size")
                and statement_a.get("membership_root_sha256")
                != statement_b.get("membership_root_sha256")
            ):
                mode = "same-size-root-conflict"

        detected = mode is not None
        shared = (
            {field: statement_a[field] for field in _SHARED_CONTEXT_FIELDS}
            if comparable
            else {field: None for field in _SHARED_CONTEXT_FIELDS}
        )
        evidence = {
            "schema": HANDOFF_CHAIN_MEMBERSHIP_EQUIVOCATION_EVIDENCE_SCHEMA,
            "verified": True,
            "reason": (
                HANDOFF_CHAIN_MEMBERSHIP_EQUIVOCATION_DETECTED_REASON
                if detected
                else HANDOFF_CHAIN_MEMBERSHIP_EQUIVOCATION_NOT_PROVEN_REASON
            ),
            "equivocation_detected": detected,
            "authority_id": statement_a["authority_id"] if comparable else None,
            "chain_id": shared["chain_id"],
            "policy_id": shared["policy_id"],
            "genesis_policy_epoch": shared["genesis_policy_epoch"],
            "genesis_policy_sha256": shared["genesis_policy_sha256"],
            "detection_mode": mode,
            "statement_a_sha256": digest_json(statement_a),
            "statement_b_sha256": digest_json(statement_b),
            "anchor_a_sha256": digest_json(anchor_a),
            "anchor_b_sha256": digest_json(anchor_b),
            "current_chain_ref_a_sha256": digest_json(current_chain_ref_a),
            "current_chain_ref_b_sha256": digest_json(current_chain_ref_b),
            "tree_size_a": anchor_a["tree_size"],
            "tree_size_b": anchor_b["tree_size"],
            "membership_root_a_sha256": anchor_a[
                "step_commitment_merkle_root_sha256"
            ],
            "membership_root_b_sha256": anchor_b[
                "step_commitment_merkle_root_sha256"
            ],
            "tree_algorithm": shared["tree_algorithm"],
            "chain_contract_sha256": shared["chain_contract_sha256"],
            "chain_authorization_contract_sha256": shared[
                "chain_authorization_contract_sha256"
            ],
            "membership_contract_sha256": shared[
                "membership_contract_sha256"
            ],
            "authorization_contract_sha256": shared[
                "authorization_contract_sha256"
            ],
            "global_non_equivocation_status": GLOBAL_NON_EQUIVOCATION_STATUS,
        }
        if set(evidence) != _EQUIVOCATION_EVIDENCE_KEYS:
            return WitnessPolicyHandoffChainMembershipEquivocationDecision(
                False, "handoff_chain_membership_equivocation_evidence_shape_invalid"
            )
        return WitnessPolicyHandoffChainMembershipEquivocationDecision(
            True,
            evidence["reason"],
            equivocation_detected=detected,
            evidence=evidence,
        )
    except RecursionError:
        return WitnessPolicyHandoffChainMembershipEquivocationDecision(
            False, "handoff_chain_membership_equivocation_evidence_too_deep"
        )
    except (KeyError, TypeError, ValueError) as error:
        return WitnessPolicyHandoffChainMembershipEquivocationDecision(
            False, str(error)
        )


def validate_witness_policy_handoff_chain_membership_equivocation_evidence(
    evidence: Any,
    anchor_a: Any,
    current_chain_ref_a: Any,
    statement_a: Any,
    anchor_b: Any,
    current_chain_ref_b: Any,
    statement_b: Any,
) -> bool:
    """Recompute exact serialized evidence from all pinned inputs."""

    try:
        if (
            not isinstance(evidence, Mapping)
            or set(evidence) != _EQUIVOCATION_EVIDENCE_KEYS
            or evidence.get("schema")
            != HANDOFF_CHAIN_MEMBERSHIP_EQUIVOCATION_EVIDENCE_SCHEMA
            or evidence.get("verified") is not True
            or evidence.get("reason")
            != HANDOFF_CHAIN_MEMBERSHIP_EQUIVOCATION_DETECTED_REASON
            or evidence.get("equivocation_detected") is not True
            or evidence.get("detection_mode")
            not in {"same-sequence-conflict", "same-size-root-conflict"}
            or evidence.get("global_non_equivocation_status")
            != GLOBAL_NON_EQUIVOCATION_STATUS
        ):
            return False
        decision = (
            detect_witness_policy_handoff_chain_membership_anchor_equivocation(
                anchor_a,
                current_chain_ref_a,
                statement_a,
                anchor_b,
                current_chain_ref_b,
                statement_b,
            )
        )
        return (
            decision.verified
            and decision.equivocation_detected
            and isinstance(decision.evidence, Mapping)
            and canonical_json_bytes(dict(evidence))
            == canonical_json_bytes(decision.evidence)
        )
    except RecursionError:
        return False
    except (KeyError, TypeError, ValueError):
        return False
