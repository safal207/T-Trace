"""Append-only consistency proofs and bounded equivocation evidence for lineage roots.

The membership profile proves inclusion in one supplied root. This companion profile
proves that a later membership root is an append-only extension of an earlier root
without replaying every reconciliation cycle. It also normalizes externally verified
anchor statements so conflicting statements from one authority can be compared
without claiming global non-equivocation.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

from .lineage_compaction import ZERO_SHA256
from .lineage_membership import (
    LINEAGE_MEMBERSHIP_LEAF_SCHEMA,
    LINEAGE_MEMBERSHIP_NODE_SCHEMA,
    LINEAGE_MEMBERSHIP_TREE_ALGORITHM,
    build_lineage_cycle_summary,
    build_lineage_membership_anchor,
    validate_lineage_membership_anchor,
)
from .portable_causality import (
    ReconciliationAgreement,
    digest_json,
    is_sha256,
    validate_reconciliation_agreement,
    validate_state_ref,
)


LINEAGE_ROOT_CONSISTENCY_PROOF_SCHEMA = (
    "ttrace-lineage-root-consistency-proof/v0.1"
)
LINEAGE_ROOT_CONSISTENCY_PACKAGE_SCHEMA = (
    "ttrace-lineage-root-consistency-package/v0.1"
)
LINEAGE_ANCHOR_STATEMENT_SCHEMA = "ttrace-lineage-anchor-statement/v0.1"
LINEAGE_EQUIVOCATION_EVIDENCE_SCHEMA = (
    "ttrace-lineage-anchor-equivocation-evidence/v0.1"
)
LINEAGE_ROOT_CONSISTENCY_REASON = "lineage_root_append_only_consistency_verified"
LINEAGE_AUTHORIZED_CONSISTENCY_REASON = (
    "authorized_lineage_root_consistency_verified"
)
LINEAGE_EQUIVOCATION_DETECTED_REASON = "lineage_anchor_equivocation_detected"
LINEAGE_EQUIVOCATION_NOT_PROVEN_REASON = (
    "lineage_anchor_equivocation_not_proven"
)
LINEAGE_ROOT_CONSISTENCY_ALGORITHM = (
    "compact-frontier-over-pairwise-duplicate-last-sha256/v0.1"
)
GLOBAL_NON_EQUIVOCATION_STATUS = "unproven"

_BLOCK_KEYS = {"start", "size", "sha256"}
_ENDPOINT_KEYS = {"membership_anchor", "current_accumulator"}
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
    "old_current_cycle_sibling_path",
    "new_current_cycle_sibling_path",
}
_PACKAGE_KEYS = {"schema", "old_endpoint", "new_endpoint", "consistency_proof"}
_PATH_ENTRY_KEYS = {"side", "sha256"}
_STATEMENT_KEYS = {
    "schema",
    "verified",
    "authority_id",
    "statement_sequence",
    "previous_statement_sha256",
    "statement_provenance_sha256",
    "trust_domain",
    "logical_state_id",
    "tree_size",
    "anchor_sha256",
    "membership_root_sha256",
    "authorization_contract_sha256",
}
_EQUIVOCATION_EVIDENCE_KEYS = {
    "schema",
    "verified",
    "reason",
    "equivocation_detected",
    "authority_id",
    "trust_domain",
    "logical_state_id",
    "detection_mode",
    "statement_a_sha256",
    "statement_b_sha256",
    "anchor_a_sha256",
    "anchor_b_sha256",
    "tree_size_a",
    "tree_size_b",
    "membership_root_a_sha256",
    "membership_root_b_sha256",
    "global_non_equivocation_status",
}
_RECONCILIATION_KEYS = {
    "verified",
    "reason",
    "branch_tips",
    "parent_set",
    "reconciled_state_ref",
    "reconciliation_ref",
    "receipt",
}


@dataclass(frozen=True)
class LineageConsistencyDecision:
    """Machine-readable result for one append-only membership-root proof."""

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
    current_tips_membership_bound: bool = False
    raw_cycle_records_disclosed: bool = False


@dataclass(frozen=True)
class AuthorizedLineageConsistencyDecision:
    """Consistency result bound to two externally verified authority statements."""

    verified: bool
    reason: str
    authority_id: Optional[str] = None
    old_statement_sha256: Optional[str] = None
    new_statement_sha256: Optional[str] = None
    append_only_consistent: bool = False
    authority_chain_continuous: bool = False
    presented_equivocation_detected: bool = False
    global_non_equivocation_status: str = GLOBAL_NON_EQUIVOCATION_STATUS


@dataclass(frozen=True)
class LineageEquivocationDecision:
    """Conflict verdict for two externally verified anchor statements."""

    verified: bool
    reason: str
    equivocation_detected: bool = False
    evidence: Optional[Dict[str, Any]] = None
    global_non_equivocation_status: str = GLOBAL_NON_EQUIVOCATION_STATUS


def _text(value: Any) -> bool:
    return isinstance(value, str) and bool(value)


def _positive_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value > 0


def _power_of_two(value: Any) -> bool:
    return _positive_int(value) and value & (value - 1) == 0


def _reconciliation_from_mapping(value: Any) -> ReconciliationAgreement:
    if not isinstance(value, Mapping) or set(value) != _RECONCILIATION_KEYS:
        raise ValueError("reconciliation_object_invalid")
    branch_tips = value.get("branch_tips")
    if not isinstance(branch_tips, (list, tuple)):
        raise ValueError("reconciliation_branch_tips_invalid")
    if not all(isinstance(item, Mapping) for item in branch_tips):
        raise ValueError("reconciliation_branch_tips_invalid")
    optional_objects = (
        value.get("parent_set"),
        value.get("reconciled_state_ref"),
        value.get("reconciliation_ref"),
        value.get("receipt"),
    )
    if any(
        item is not None and not isinstance(item, Mapping)
        for item in optional_objects
    ):
        raise ValueError("reconciliation_sections_invalid")
    return ReconciliationAgreement(
        verified=value.get("verified") is True,
        reason=str(value.get("reason", "")),
        branch_tips=tuple(dict(item) for item in branch_tips),
        parent_set=(
            dict(value["parent_set"])
            if value.get("parent_set") is not None
            else None
        ),
        reconciled_state_ref=(
            dict(value["reconciled_state_ref"])
            if value.get("reconciled_state_ref") is not None
            else None
        ),
        reconciliation_ref=(
            dict(value["reconciliation_ref"])
            if value.get("reconciliation_ref") is not None
            else None
        ),
        receipt=(
            dict(value["receipt"])
            if value.get("receipt") is not None
            else None
        ),
    )


def _validated_cycle_commitments(
    cycle_records: Sequence[Mapping[str, Any]],
    current_accumulator: Mapping[str, Any],
    *,
    membership_contract_sha256: str,
    authorization_contract_sha256: str,
) -> Tuple[Dict[str, Any], Tuple[str, ...]]:
    """Validate the retained cycle chain and return its exact commitments."""

    anchor = build_lineage_membership_anchor(
        cycle_records,
        current_accumulator,
        membership_contract_sha256=membership_contract_sha256,
        authorization_contract_sha256=authorization_contract_sha256,
    )
    commitments: List[str] = []
    for cycle_index, record in enumerate(cycle_records, start=1):
        if not isinstance(record, Mapping):
            raise ValueError("cycle_record_invalid")
        common_state_ref = record.get("common_state_ref")
        if not validate_state_ref(common_state_ref):
            raise ValueError("cycle_common_state_invalid")
        assert isinstance(common_state_ref, Mapping)
        reconciliation = _reconciliation_from_mapping(record.get("reconciliation"))
        if not validate_reconciliation_agreement(
            reconciliation, common_state_ref
        ):
            raise ValueError("cycle_reconciliation_invalid")
        summary = build_lineage_cycle_summary(
            cycle_index, common_state_ref, reconciliation
        )
        commitment = digest_json(summary)
        accumulator = record.get("lineage_accumulator")
        if not isinstance(accumulator, Mapping):
            raise ValueError("cycle_accumulator_invalid")
        if accumulator.get("cycle_commitment_sha256") != commitment:
            raise ValueError("cycle_commitment_mismatch")
        commitments.append(commitment)

    if len(commitments) != anchor["tree_size"]:
        raise ValueError("cycle_count_anchor_mismatch")
    if commitments[-1] != anchor["current_cycle_commitment_sha256"]:
        raise ValueError("current_cycle_commitment_mismatch")
    return anchor, tuple(commitments)


def _membership_leaf_hash(
    cycle_index: int, cycle_commitment_sha256: str
) -> str:
    if not _positive_int(cycle_index) or not is_sha256(
        cycle_commitment_sha256
    ):
        raise ValueError("consistency_leaf_invalid")
    return digest_json(
        {
            "schema": LINEAGE_MEMBERSHIP_LEAF_SCHEMA,
            "cycle_index": cycle_index,
            "cycle_commitment_sha256": cycle_commitment_sha256,
        }
    )


def _membership_node_hash(left_sha256: str, right_sha256: str) -> str:
    if not is_sha256(left_sha256) or not is_sha256(right_sha256):
        raise ValueError("consistency_node_invalid")
    return digest_json(
        {
            "schema": LINEAGE_MEMBERSHIP_NODE_SCHEMA,
            "left_sha256": left_sha256,
            "right_sha256": right_sha256,
        }
    )


def _subtree_root(
    leaf_hashes: Sequence[str], start: int, size: int
) -> str:
    if (
        not _power_of_two(size)
        or not isinstance(start, int)
        or isinstance(start, bool)
        or start < 0
        or start % size != 0
        or start + size > len(leaf_hashes)
    ):
        raise ValueError("consistency_subtree_range_invalid")
    if size == 1:
        leaf = leaf_hashes[start]
        if not is_sha256(leaf):
            raise ValueError("consistency_leaf_invalid")
        return leaf
    half = size // 2
    return _membership_node_hash(
        _subtree_root(leaf_hashes, start, half),
        _subtree_root(leaf_hashes, start + half, half),
    )


def _prefix_block_shapes(tree_size: int) -> Tuple[Tuple[int, int], ...]:
    if not _positive_int(tree_size):
        raise ValueError("consistency_tree_size_invalid")
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
    if (
        not isinstance(start, int)
        or isinstance(start, bool)
        or not isinstance(end, int)
        or isinstance(end, bool)
        or start < 0
        or end <= start
    ):
        raise ValueError("consistency_append_range_invalid")
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
    leaf_hashes: Sequence[str],
    shapes: Sequence[Tuple[int, int]],
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
        and isinstance(value.get("start"), int)
        and not isinstance(value.get("start"), bool)
        and value.get("start") >= 0
        and _power_of_two(value.get("size"))
        and is_sha256(value.get("sha256"))
    )


def _validate_block_shapes(
    values: Any,
    expected_shapes: Sequence[Tuple[int, int]],
) -> bool:
    if not isinstance(values, list) or len(values) != len(expected_shapes):
        return False
    return all(
        _valid_block(value)
        and value.get("start") == start
        and value.get("size") == size
        for value, (start, size) in zip(values, expected_shapes)
    )


def _bag_frontier_to_membership_root(frontier: Sequence[Mapping[str, Any]]) -> str:
    """Reconstruct the duplicate-last membership root from compact peaks."""

    if not frontier:
        raise ValueError("consistency_frontier_empty")
    accumulator_sha256 = str(frontier[-1]["sha256"])
    accumulator_size = int(frontier[-1]["size"])
    for block in reversed(frontier[:-1]):
        block_size = int(block["size"])
        while accumulator_size < block_size:
            accumulator_sha256 = _membership_node_hash(
                accumulator_sha256, accumulator_sha256
            )
            accumulator_size *= 2
        if accumulator_size != block_size:
            raise ValueError("consistency_frontier_shape_invalid")
        accumulator_sha256 = _membership_node_hash(
            str(block["sha256"]), accumulator_sha256
        )
        accumulator_size *= 2
    return accumulator_sha256


def _append_block(
    frontier: Sequence[Mapping[str, Any]],
    block: Mapping[str, Any],
) -> List[Dict[str, Any]]:
    if not _valid_block(block):
        raise ValueError("consistency_append_block_invalid")
    result = [dict(item) for item in frontier]
    covered = sum(int(item["size"]) for item in result)
    if block.get("start") != covered:
        raise ValueError("consistency_append_block_start_invalid")
    result.append(dict(block))
    while len(result) >= 2:
        left = result[-2]
        right = result[-1]
        if (
            left["size"] != right["size"]
            or left["start"] + left["size"] != right["start"]
        ):
            break
        parent_size = int(left["size"]) * 2
        if int(left["start"]) % parent_size != 0:
            raise ValueError("consistency_append_alignment_invalid")
        result[-2:] = [
            {
                "start": int(left["start"]),
                "size": parent_size,
                "sha256": _membership_node_hash(
                    str(left["sha256"]), str(right["sha256"])
                ),
            }
        ]
    return result


def _next_membership_level(level: Sequence[str]) -> List[str]:
    result: List[str] = []
    for index in range(0, len(level), 2):
        left = level[index]
        right = level[index + 1] if index + 1 < len(level) else left
        result.append(_membership_node_hash(left, right))
    return result


def _membership_path(
    leaf_hashes: Sequence[str], leaf_index: int
) -> List[Dict[str, Any]]:
    if (
        not leaf_hashes
        or not isinstance(leaf_index, int)
        or isinstance(leaf_index, bool)
        or leaf_index < 0
        or leaf_index >= len(leaf_hashes)
    ):
        raise ValueError("consistency_membership_index_invalid")
    level = list(leaf_hashes)
    index = leaf_index
    path: List[Dict[str, Any]] = []
    while len(level) > 1:
        if index % 2 == 0:
            sibling_index = index + 1 if index + 1 < len(level) else index
            side = "right"
        else:
            sibling_index = index - 1
            side = "left"
        path.append({"side": side, "sha256": level[sibling_index]})
        index //= 2
        level = _next_membership_level(level)
    return path


def _expected_membership_path_length(tree_size: int) -> int:
    if not _positive_int(tree_size):
        raise ValueError("consistency_tree_size_invalid")
    length = 0
    width = tree_size
    while width > 1:
        width = (width + 1) // 2
        length += 1
    return length


def _verify_membership_path(
    *,
    leaf_sha256: str,
    leaf_index: int,
    tree_size: int,
    sibling_path: Any,
    expected_root_sha256: str,
) -> bool:
    if (
        not is_sha256(leaf_sha256)
        or not is_sha256(expected_root_sha256)
        or not _positive_int(tree_size)
        or not isinstance(leaf_index, int)
        or isinstance(leaf_index, bool)
        or leaf_index < 0
        or leaf_index >= tree_size
        or not isinstance(sibling_path, list)
        or len(sibling_path)
        != _expected_membership_path_length(tree_size)
    ):
        return False
    current = leaf_sha256
    index = leaf_index
    width = tree_size
    for entry in sibling_path:
        if not isinstance(entry, Mapping) or set(entry) != _PATH_ENTRY_KEYS:
            return False
        side = entry.get("side")
        sibling = entry.get("sha256")
        if side not in {"left", "right"} or not is_sha256(sibling):
            return False
        expected_side = "left" if index % 2 else "right"
        if side != expected_side:
            return False
        if index % 2 == 0 and index + 1 >= width and sibling != current:
            return False
        current = (
            _membership_node_hash(str(sibling), current)
            if side == "left"
            else _membership_node_hash(current, str(sibling))
        )
        index //= 2
        width = (width + 1) // 2
    return width == 1 and index == 0 and current == expected_root_sha256


def build_lineage_root_consistency_package(
    old_cycle_records: Sequence[Mapping[str, Any]],
    old_current_accumulator: Mapping[str, Any],
    new_cycle_records: Sequence[Mapping[str, Any]],
    new_current_accumulator: Mapping[str, Any],
    *,
    membership_contract_sha256: str,
    authorization_contract_sha256: str,
) -> Dict[str, Any]:
    """Build a compact append-only proof between two membership anchors."""

    old_anchor, old_commitments = _validated_cycle_commitments(
        old_cycle_records,
        old_current_accumulator,
        membership_contract_sha256=membership_contract_sha256,
        authorization_contract_sha256=authorization_contract_sha256,
    )
    new_anchor, new_commitments = _validated_cycle_commitments(
        new_cycle_records,
        new_current_accumulator,
        membership_contract_sha256=membership_contract_sha256,
        authorization_contract_sha256=authorization_contract_sha256,
    )
    old_size = len(old_commitments)
    new_size = len(new_commitments)
    if old_size >= new_size:
        raise ValueError("consistency_tree_not_extended")
    if tuple(new_commitments[:old_size]) != old_commitments:
        raise ValueError("consistency_prefix_mismatch")

    old_leaf_hashes = [
        _membership_leaf_hash(index, commitment)
        for index, commitment in enumerate(old_commitments, start=1)
    ]
    new_leaf_hashes = [
        _membership_leaf_hash(index, commitment)
        for index, commitment in enumerate(new_commitments, start=1)
    ]
    old_frontier = _build_blocks(
        old_leaf_hashes, _prefix_block_shapes(old_size)
    )
    append_blocks = _build_blocks(
        new_leaf_hashes, _suffix_block_shapes(old_size, new_size)
    )
    proof = {
        "schema": LINEAGE_ROOT_CONSISTENCY_PROOF_SCHEMA,
        "old_anchor_sha256": digest_json(old_anchor),
        "new_anchor_sha256": digest_json(new_anchor),
        "old_tree_size": old_size,
        "new_tree_size": new_size,
        "membership_tree_algorithm": LINEAGE_MEMBERSHIP_TREE_ALGORITHM,
        "consistency_algorithm": LINEAGE_ROOT_CONSISTENCY_ALGORITHM,
        "old_frontier": old_frontier,
        "append_blocks": append_blocks,
        "old_current_cycle_sibling_path": _membership_path(
            old_leaf_hashes, old_size - 1
        ),
        "new_current_cycle_sibling_path": _membership_path(
            new_leaf_hashes, new_size - 1
        ),
    }
    package = {
        "schema": LINEAGE_ROOT_CONSISTENCY_PACKAGE_SCHEMA,
        "old_endpoint": {
            "membership_anchor": old_anchor,
            "current_accumulator": dict(old_current_accumulator),
        },
        "new_endpoint": {
            "membership_anchor": new_anchor,
            "current_accumulator": dict(new_current_accumulator),
        },
        "consistency_proof": proof,
    }
    decision = verify_lineage_root_consistency(package)
    if not decision.verified:
        raise ValueError(f"consistency_package_invalid:{decision.reason}")
    return package


def _validate_endpoint(value: Any) -> Tuple[Mapping[str, Any], Mapping[str, Any]]:
    if not isinstance(value, Mapping) or set(value) != _ENDPOINT_KEYS:
        raise ValueError("consistency_endpoint_shape_invalid")
    anchor = value.get("membership_anchor")
    accumulator = value.get("current_accumulator")
    if not validate_lineage_membership_anchor(anchor, accumulator):
        raise ValueError("consistency_membership_anchor_invalid")
    assert isinstance(anchor, Mapping)
    assert isinstance(accumulator, Mapping)
    return anchor, accumulator


def verify_lineage_root_consistency(
    value: Any,
) -> LineageConsistencyDecision:
    """Verify direct append-only consistency between two membership roots."""

    try:
        if not isinstance(value, Mapping) or set(value) != _PACKAGE_KEYS:
            raise ValueError("consistency_package_shape_invalid")
        if value.get("schema") != LINEAGE_ROOT_CONSISTENCY_PACKAGE_SCHEMA:
            raise ValueError("consistency_package_schema_invalid")
        old_anchor, _ = _validate_endpoint(value.get("old_endpoint"))
        new_anchor, _ = _validate_endpoint(value.get("new_endpoint"))
        proof = value.get("consistency_proof")
        if not isinstance(proof, Mapping) or set(proof) != _PROOF_KEYS:
            raise ValueError("consistency_proof_shape_invalid")
        if proof.get("schema") != LINEAGE_ROOT_CONSISTENCY_PROOF_SCHEMA:
            raise ValueError("consistency_proof_schema_invalid")

        old_size = old_anchor.get("tree_size")
        new_size = new_anchor.get("tree_size")
        if not _positive_int(old_size) or not _positive_int(new_size):
            raise ValueError("consistency_tree_size_invalid")
        assert isinstance(old_size, int)
        assert isinstance(new_size, int)
        if old_size >= new_size:
            raise ValueError("consistency_tree_not_extended")
        if proof.get("old_tree_size") != old_size:
            raise ValueError("consistency_old_tree_size_mismatch")
        if proof.get("new_tree_size") != new_size:
            raise ValueError("consistency_new_tree_size_mismatch")
        if proof.get("old_anchor_sha256") != digest_json(old_anchor):
            raise ValueError("consistency_old_anchor_mismatch")
        if proof.get("new_anchor_sha256") != digest_json(new_anchor):
            raise ValueError("consistency_new_anchor_mismatch")
        if (
            proof.get("membership_tree_algorithm")
            != LINEAGE_MEMBERSHIP_TREE_ALGORITHM
            or old_anchor.get("tree_algorithm")
            != LINEAGE_MEMBERSHIP_TREE_ALGORITHM
            or new_anchor.get("tree_algorithm")
            != LINEAGE_MEMBERSHIP_TREE_ALGORITHM
        ):
            raise ValueError("consistency_membership_algorithm_invalid")
        if (
            proof.get("consistency_algorithm")
            != LINEAGE_ROOT_CONSISTENCY_ALGORITHM
        ):
            raise ValueError("consistency_algorithm_invalid")

        for field, reason in (
            ("trust_domain", "consistency_trust_domain_mismatch"),
            ("logical_state_id", "consistency_logical_state_mismatch"),
            (
                "membership_contract_sha256",
                "consistency_membership_contract_mismatch",
            ),
            (
                "authorization_contract_sha256",
                "consistency_authorization_contract_mismatch",
            ),
        ):
            if old_anchor.get(field) != new_anchor.get(field):
                raise ValueError(reason)
        if (
            old_anchor.get("completed_reconciliation_cycles") != old_size
            or new_anchor.get("completed_reconciliation_cycles") != new_size
        ):
            raise ValueError("consistency_cycle_count_mismatch")
        if int(new_anchor["current_causal_epoch"]) <= int(
            old_anchor["current_causal_epoch"]
        ):
            raise ValueError("consistency_causal_epoch_not_advanced")

        old_frontier = proof.get("old_frontier")
        if not _validate_block_shapes(
            old_frontier, _prefix_block_shapes(old_size)
        ):
            raise ValueError("consistency_old_frontier_invalid")
        assert isinstance(old_frontier, list)
        old_root = _bag_frontier_to_membership_root(old_frontier)
        if old_root != old_anchor.get(
            "cycle_commitment_merkle_root_sha256"
        ):
            raise ValueError("consistency_old_root_mismatch")

        append_blocks = proof.get("append_blocks")
        if not _validate_block_shapes(
            append_blocks, _suffix_block_shapes(old_size, new_size)
        ):
            raise ValueError("consistency_append_blocks_invalid")
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
            raise ValueError("consistency_new_frontier_invalid")
        new_root = _bag_frontier_to_membership_root(new_frontier)
        if new_root != new_anchor.get(
            "cycle_commitment_merkle_root_sha256"
        ):
            raise ValueError("consistency_new_root_mismatch")

        old_current_leaf = _membership_leaf_hash(
            old_size, str(old_anchor["current_cycle_commitment_sha256"])
        )
        if not _verify_membership_path(
            leaf_sha256=old_current_leaf,
            leaf_index=old_size - 1,
            tree_size=old_size,
            sibling_path=proof.get("old_current_cycle_sibling_path"),
            expected_root_sha256=str(
                old_anchor["cycle_commitment_merkle_root_sha256"]
            ),
        ):
            raise ValueError("consistency_old_current_tip_not_bound")
        new_current_leaf = _membership_leaf_hash(
            new_size, str(new_anchor["current_cycle_commitment_sha256"])
        )
        if not _verify_membership_path(
            leaf_sha256=new_current_leaf,
            leaf_index=new_size - 1,
            tree_size=new_size,
            sibling_path=proof.get("new_current_cycle_sibling_path"),
            expected_root_sha256=str(
                new_anchor["cycle_commitment_merkle_root_sha256"]
            ),
        ):
            raise ValueError("consistency_new_current_tip_not_bound")

        return LineageConsistencyDecision(
            True,
            LINEAGE_ROOT_CONSISTENCY_REASON,
            old_tree_size=old_size,
            new_tree_size=new_size,
            old_anchor_sha256=digest_json(old_anchor),
            new_anchor_sha256=digest_json(new_anchor),
            old_frontier_node_count=len(old_frontier),
            append_block_count=len(append_blocks),
            old_current_path_hash_count=len(
                proof["old_current_cycle_sibling_path"]
            ),
            new_current_path_hash_count=len(
                proof["new_current_cycle_sibling_path"]
            ),
            append_only_consistent=True,
            current_tips_membership_bound=True,
            raw_cycle_records_disclosed=False,
        )
    except RecursionError:
        return LineageConsistencyDecision(
            False, "consistency_proof_too_deep"
        )
    except (KeyError, TypeError, ValueError) as error:
        return LineageConsistencyDecision(False, str(error))


def build_lineage_anchor_statement(
    membership_anchor: Mapping[str, Any],
    current_accumulator: Mapping[str, Any],
    *,
    verified: bool,
    authority_id: str,
    statement_sequence: int,
    previous_statement_sha256: str,
    statement_provenance_sha256: str,
) -> Dict[str, Any]:
    """Normalize an externally verified statement about one membership anchor."""

    if not validate_lineage_membership_anchor(
        membership_anchor, current_accumulator
    ):
        raise ValueError("anchor_statement_membership_anchor_invalid")
    if verified is not True:
        raise ValueError("anchor_statement_unverified")
    if not _text(authority_id):
        raise ValueError("anchor_statement_authority_invalid")
    if not _positive_int(statement_sequence):
        raise ValueError("anchor_statement_sequence_invalid")
    if not is_sha256(statement_provenance_sha256):
        raise ValueError("anchor_statement_provenance_invalid")
    if statement_provenance_sha256 == ZERO_SHA256:
        raise ValueError("anchor_statement_provenance_invalid")
    if statement_sequence == 1:
        if previous_statement_sha256 != ZERO_SHA256:
            raise ValueError("anchor_statement_seed_predecessor_invalid")
    elif (
        not is_sha256(previous_statement_sha256)
        or previous_statement_sha256 == ZERO_SHA256
    ):
        raise ValueError("anchor_statement_predecessor_invalid")
    statement = {
        "schema": LINEAGE_ANCHOR_STATEMENT_SCHEMA,
        "verified": True,
        "authority_id": authority_id,
        "statement_sequence": statement_sequence,
        "previous_statement_sha256": previous_statement_sha256,
        "statement_provenance_sha256": statement_provenance_sha256,
        "trust_domain": membership_anchor["trust_domain"],
        "logical_state_id": membership_anchor["logical_state_id"],
        "tree_size": membership_anchor["tree_size"],
        "anchor_sha256": digest_json(membership_anchor),
        "membership_root_sha256": membership_anchor[
            "cycle_commitment_merkle_root_sha256"
        ],
        "authorization_contract_sha256": membership_anchor[
            "authorization_contract_sha256"
        ],
    }
    if not validate_lineage_anchor_statement(
        statement, membership_anchor, current_accumulator
    ):
        raise ValueError("anchor_statement_invalid")
    return statement


def validate_lineage_anchor_statement(
    statement: Any,
    membership_anchor: Any,
    current_accumulator: Any,
) -> bool:
    if (
        not isinstance(statement, Mapping)
        or set(statement) != _STATEMENT_KEYS
        or not validate_lineage_membership_anchor(
            membership_anchor, current_accumulator
        )
    ):
        return False
    assert isinstance(membership_anchor, Mapping)
    sequence = statement.get("statement_sequence")
    previous = statement.get("previous_statement_sha256")
    return (
        statement.get("schema") == LINEAGE_ANCHOR_STATEMENT_SCHEMA
        and statement.get("verified") is True
        and _text(statement.get("authority_id"))
        and _positive_int(sequence)
        and (
            previous == ZERO_SHA256
            if sequence == 1
            else (
                is_sha256(previous)
                and previous != ZERO_SHA256
            )
        )
        and is_sha256(statement.get("statement_provenance_sha256"))
        and statement.get("statement_provenance_sha256") != ZERO_SHA256
        and statement.get("trust_domain")
        == membership_anchor.get("trust_domain")
        and statement.get("logical_state_id")
        == membership_anchor.get("logical_state_id")
        and statement.get("tree_size")
        == membership_anchor.get("tree_size")
        and statement.get("anchor_sha256")
        == digest_json(membership_anchor)
        and statement.get("membership_root_sha256")
        == membership_anchor.get("cycle_commitment_merkle_root_sha256")
        and statement.get("authorization_contract_sha256")
        == membership_anchor.get("authorization_contract_sha256")
    )


def verify_authorized_lineage_root_consistency(
    package: Any,
    old_statement: Any,
    new_statement: Any,
) -> AuthorizedLineageConsistencyDecision:
    """Verify append-only consistency plus direct authority-statement continuity."""

    consistency = verify_lineage_root_consistency(package)
    if not consistency.verified:
        return AuthorizedLineageConsistencyDecision(
            False, consistency.reason
        )
    assert isinstance(package, Mapping)
    old_endpoint = package["old_endpoint"]
    new_endpoint = package["new_endpoint"]
    old_anchor = old_endpoint["membership_anchor"]
    old_accumulator = old_endpoint["current_accumulator"]
    new_anchor = new_endpoint["membership_anchor"]
    new_accumulator = new_endpoint["current_accumulator"]
    if not validate_lineage_anchor_statement(
        old_statement, old_anchor, old_accumulator
    ):
        return AuthorizedLineageConsistencyDecision(
            False, "old_anchor_statement_invalid"
        )
    if not validate_lineage_anchor_statement(
        new_statement, new_anchor, new_accumulator
    ):
        return AuthorizedLineageConsistencyDecision(
            False, "new_anchor_statement_invalid"
        )
    assert isinstance(old_statement, Mapping)
    assert isinstance(new_statement, Mapping)
    if old_statement.get("authority_id") != new_statement.get(
        "authority_id"
    ):
        return AuthorizedLineageConsistencyDecision(
            False, "anchor_statement_authority_mismatch"
        )
    if int(new_statement["statement_sequence"]) != int(
        old_statement["statement_sequence"]
    ) + 1:
        return AuthorizedLineageConsistencyDecision(
            False, "anchor_statement_sequence_discontinuity"
        )
    if new_statement.get("previous_statement_sha256") != digest_json(
        old_statement
    ):
        return AuthorizedLineageConsistencyDecision(
            False, "anchor_statement_predecessor_mismatch"
        )
    return AuthorizedLineageConsistencyDecision(
        True,
        LINEAGE_AUTHORIZED_CONSISTENCY_REASON,
        authority_id=str(old_statement["authority_id"]),
        old_statement_sha256=digest_json(old_statement),
        new_statement_sha256=digest_json(new_statement),
        append_only_consistent=True,
        authority_chain_continuous=True,
        presented_equivocation_detected=False,
        global_non_equivocation_status=GLOBAL_NON_EQUIVOCATION_STATUS,
    )


def detect_lineage_anchor_equivocation(
    anchor_a: Any,
    accumulator_a: Any,
    statement_a: Any,
    anchor_b: Any,
    accumulator_b: Any,
    statement_b: Any,
) -> LineageEquivocationDecision:
    """Detect a conflict when both externally verified statements are presented."""

    if not validate_lineage_anchor_statement(
        statement_a, anchor_a, accumulator_a
    ) or not validate_lineage_anchor_statement(
        statement_b, anchor_b, accumulator_b
    ):
        return LineageEquivocationDecision(
            False, "anchor_statement_invalid"
        )
    assert isinstance(anchor_a, Mapping)
    assert isinstance(anchor_b, Mapping)
    assert isinstance(statement_a, Mapping)
    assert isinstance(statement_b, Mapping)

    comparable = (
        statement_a.get("authority_id") == statement_b.get("authority_id")
        and statement_a.get("trust_domain")
        == statement_b.get("trust_domain")
        and statement_a.get("logical_state_id")
        == statement_b.get("logical_state_id")
        and statement_a.get("authorization_contract_sha256")
        == statement_b.get("authorization_contract_sha256")
    )
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
    evidence = {
        "schema": LINEAGE_EQUIVOCATION_EVIDENCE_SCHEMA,
        "verified": True,
        "reason": (
            LINEAGE_EQUIVOCATION_DETECTED_REASON
            if detected
            else LINEAGE_EQUIVOCATION_NOT_PROVEN_REASON
        ),
        "equivocation_detected": detected,
        "authority_id": (
            statement_a["authority_id"] if comparable else None
        ),
        "trust_domain": statement_a["trust_domain"],
        "logical_state_id": statement_a["logical_state_id"],
        "detection_mode": mode,
        "statement_a_sha256": digest_json(statement_a),
        "statement_b_sha256": digest_json(statement_b),
        "anchor_a_sha256": digest_json(anchor_a),
        "anchor_b_sha256": digest_json(anchor_b),
        "tree_size_a": anchor_a["tree_size"],
        "tree_size_b": anchor_b["tree_size"],
        "membership_root_a_sha256": anchor_a[
            "cycle_commitment_merkle_root_sha256"
        ],
        "membership_root_b_sha256": anchor_b[
            "cycle_commitment_merkle_root_sha256"
        ],
        "global_non_equivocation_status": GLOBAL_NON_EQUIVOCATION_STATUS,
    }
    if set(evidence) != _EQUIVOCATION_EVIDENCE_KEYS:
        return LineageEquivocationDecision(
            False, "equivocation_evidence_shape_invalid"
        )
    return LineageEquivocationDecision(
        True,
        evidence["reason"],
        equivocation_detected=detected,
        evidence=evidence,
        global_non_equivocation_status=GLOBAL_NON_EQUIVOCATION_STATUS,
    )
