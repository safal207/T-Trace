"""Selective disclosure for repeated witness-policy handoff chains.

The rolling handoff-chain reference is fixed-shape and therefore efficient as an
active tip, but proving an older rotation directly from that hash chain would
require every later handoff package.  This companion profile commits the validated
step commitments to a domain-separated Merkle tree.  A disclosure carries one
complete handoff package, one fixed-shape predecessor reference, and two O(log n)
paths: one for the selected step and one for the current step.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

from .lineage_compaction import ZERO_SHA256
from .lineage_consistency import GLOBAL_NON_EQUIVOCATION_STATUS
from .lineage_witness_handoff_chain import (
    advance_witness_policy_handoff_chain,
    build_seed_witness_policy_handoff_chain,
    validate_witness_policy_handoff_chain_ref,
)
from .portable_causality import canonical_json_bytes, digest_json, is_sha256

HANDOFF_CHAIN_MEMBERSHIP_LEAF_SCHEMA = (
    "ttrace-witness-policy-handoff-chain-membership-leaf/v0.1"
)
HANDOFF_CHAIN_MEMBERSHIP_NODE_SCHEMA = (
    "ttrace-witness-policy-handoff-chain-membership-node/v0.1"
)
HANDOFF_CHAIN_MEMBERSHIP_ANCHOR_SCHEMA = (
    "ttrace-witness-policy-handoff-chain-membership-anchor/v0.1"
)
HANDOFF_CHAIN_MEMBERSHIP_PROOF_SCHEMA = (
    "ttrace-witness-policy-handoff-chain-membership-proof/v0.1"
)
HANDOFF_CHAIN_SELECTIVE_DISCLOSURE_SCHEMA = (
    "ttrace-witness-policy-handoff-chain-selective-disclosure/v0.1"
)
HANDOFF_CHAIN_MEMBERSHIP_REASON = (
    "witness_policy_handoff_chain_selective_disclosure_verified"
)
HANDOFF_CHAIN_MEMBERSHIP_TREE_ALGORITHM = (
    "pairwise-duplicate-last-sha256/v0.1"
)
HANDOFF_CHAIN_MEMBERSHIP_ANCHOR_AUTHORIZATION_STATUS = "not-evaluated"
HANDOFF_CHAIN_MEMBERSHIP_CURRENT_TIP_FRESHNESS_STATUS = "not-evaluated"

_ANCHOR_KEYS = {
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
_PROOF_KEYS = {
    "schema",
    "anchor_sha256",
    "handoff_index",
    "leaf_index",
    "tree_size",
    "tree_algorithm",
    "step_commitment_sha256",
    "leaf_sha256",
    "sibling_path",
    "current_step_sibling_path",
}
_DISCLOSED_HANDOFF_KEYS = {
    "handoff_index",
    "previous_chain_ref",
    "handoff_package",
    "chain_step",
    "chain_ref",
    "step_commitment_sha256",
}
_DISCLOSURE_KEYS = {
    "schema",
    "anchor",
    "current_chain_ref",
    "disclosed_handoff",
    "membership_proof",
}
_PATH_ENTRY_KEYS = {"side", "sha256"}


@dataclass(frozen=True)
class WitnessPolicyHandoffChainMembershipDecision:
    verified: bool
    reason: str
    disclosed_handoff_index: Optional[int] = None
    anchor_sha256: Optional[str] = None
    step_commitment_sha256: Optional[str] = None
    selected_sibling_hash_count: Optional[int] = None
    current_sibling_hash_count: Optional[int] = None
    sibling_hash_count: Optional[int] = None
    membership_anchor_authorization_status: str = (
        HANDOFF_CHAIN_MEMBERSHIP_ANCHOR_AUTHORIZATION_STATUS
    )
    current_tip_freshness_status: str = (
        HANDOFF_CHAIN_MEMBERSHIP_CURRENT_TIP_FRESHNESS_STATUS
    )
    global_non_equivocation_status: str = GLOBAL_NON_EQUIVOCATION_STATUS


@dataclass(frozen=True)
class _ValidatedHandoff:
    handoff_index: int
    previous_chain_ref: Optional[Dict[str, Any]]
    handoff_package: Dict[str, Any]
    chain_step: Dict[str, Any]
    chain_ref: Dict[str, Any]
    step_commitment_sha256: str


def _positive_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value > 0


def _zero_based_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def _nonzero_sha(value: Any) -> bool:
    return is_sha256(value) and value != ZERO_SHA256


def _validate_handoff_history(
    handoff_packages: Sequence[Mapping[str, Any]],
    current_chain_ref: Mapping[str, Any],
) -> Tuple[_ValidatedHandoff, ...]:
    if not isinstance(handoff_packages, Sequence) or isinstance(
        handoff_packages, (str, bytes)
    ):
        raise ValueError("handoff_packages_invalid")
    if not handoff_packages:
        raise ValueError("handoff_packages_empty")
    if not validate_witness_policy_handoff_chain_ref(current_chain_ref):
        raise ValueError("current_handoff_chain_ref_invalid")
    if len(handoff_packages) != current_chain_ref.get("completed_handoffs"):
        raise ValueError("handoff_package_count_tip_mismatch")

    validated: List[_ValidatedHandoff] = []
    previous: Optional[Dict[str, Any]] = None
    for handoff_index, package in enumerate(handoff_packages, start=1):
        if not isinstance(package, Mapping):
            raise ValueError("handoff_package_invalid")
        if previous is None:
            result = build_seed_witness_policy_handoff_chain(
                package,
                chain_id=str(current_chain_ref["chain_id"]),
                expected_genesis_policy_epoch=current_chain_ref[
                    "genesis_policy_epoch"
                ],
                expected_genesis_policy_sha256=str(
                    current_chain_ref["genesis_policy_sha256"]
                ),
                chain_contract_sha256=str(
                    current_chain_ref["chain_contract_sha256"]
                ),
                authorization_contract_sha256=str(
                    current_chain_ref["authorization_contract_sha256"]
                ),
            )
        else:
            result = advance_witness_policy_handoff_chain(previous, package)
        if (
            not result.verified
            or result.step_commitment is None
            or result.chain_ref is None
        ):
            raise ValueError(result.reason)
        if result.chain_ref.get("completed_handoffs") != handoff_index:
            raise ValueError("handoff_index_not_contiguous")
        step_sha256 = digest_json(result.step_commitment)
        if result.chain_ref.get("step_commitment_sha256") != step_sha256:
            raise ValueError("handoff_step_commitment_mismatch")
        record = _ValidatedHandoff(
            handoff_index=handoff_index,
            previous_chain_ref=(dict(previous) if previous is not None else None),
            handoff_package=dict(package),
            chain_step=dict(result.step_commitment),
            chain_ref=dict(result.chain_ref),
            step_commitment_sha256=step_sha256,
        )
        validated.append(record)
        previous = record.chain_ref

    if previous is None or canonical_json_bytes(previous) != canonical_json_bytes(
        current_chain_ref
    ):
        raise ValueError("current_handoff_chain_ref_not_history_tip")
    return tuple(validated)


def _leaf_payload(
    handoff_index: int, step_commitment_sha256: str
) -> Dict[str, Any]:
    if not _positive_int(handoff_index) or not _nonzero_sha(
        step_commitment_sha256
    ):
        raise ValueError("handoff_chain_membership_leaf_invalid")
    return {
        "schema": HANDOFF_CHAIN_MEMBERSHIP_LEAF_SCHEMA,
        "handoff_index": handoff_index,
        "step_commitment_sha256": step_commitment_sha256,
    }


def _leaf_hash(handoff_index: int, step_commitment_sha256: str) -> str:
    return digest_json(_leaf_payload(handoff_index, step_commitment_sha256))


def _node_hash(left_sha256: str, right_sha256: str) -> str:
    if not _nonzero_sha(left_sha256) or not _nonzero_sha(right_sha256):
        raise ValueError("handoff_chain_membership_node_invalid")
    return digest_json(
        {
            "schema": HANDOFF_CHAIN_MEMBERSHIP_NODE_SCHEMA,
            "left_sha256": left_sha256,
            "right_sha256": right_sha256,
        }
    )


def _next_level(level: Sequence[str]) -> List[str]:
    result: List[str] = []
    for index in range(0, len(level), 2):
        left = level[index]
        right = level[index + 1] if index + 1 < len(level) else left
        result.append(_node_hash(left, right))
    return result


def _merkle_root(leaf_hashes: Sequence[str]) -> str:
    if not leaf_hashes or not all(_nonzero_sha(item) for item in leaf_hashes):
        raise ValueError("handoff_chain_membership_leaf_set_invalid")
    level = list(leaf_hashes)
    while len(level) > 1:
        level = _next_level(level)
    return level[0]


def _merkle_path(
    leaf_hashes: Sequence[str], leaf_index: int
) -> List[Dict[str, Any]]:
    if (
        not leaf_hashes
        or not _zero_based_int(leaf_index)
        or leaf_index >= len(leaf_hashes)
    ):
        raise ValueError("handoff_chain_membership_leaf_index_invalid")
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
        level = _next_level(level)
    return path


def _expected_path_length(tree_size: int) -> int:
    if not _positive_int(tree_size):
        raise ValueError("handoff_chain_membership_tree_size_invalid")
    length = 0
    width = tree_size
    while width > 1:
        width = (width + 1) // 2
        length += 1
    return length


def _verify_merkle_path(
    *,
    leaf_sha256: str,
    leaf_index: int,
    tree_size: int,
    sibling_path: Any,
    expected_root_sha256: str,
) -> bool:
    if (
        not _nonzero_sha(leaf_sha256)
        or not _nonzero_sha(expected_root_sha256)
        or not _positive_int(tree_size)
        or not _zero_based_int(leaf_index)
        or leaf_index >= tree_size
        or not isinstance(sibling_path, list)
        or len(sibling_path) != _expected_path_length(tree_size)
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
        if side not in {"left", "right"} or not _nonzero_sha(sibling):
            return False
        expected_side = "left" if index % 2 else "right"
        if side != expected_side:
            return False
        if index % 2 == 0 and index + 1 >= width and sibling != current:
            return False
        current = (
            _node_hash(str(sibling), current)
            if side == "left"
            else _node_hash(current, str(sibling))
        )
        index //= 2
        width = (width + 1) // 2
    return width == 1 and index == 0 and current == expected_root_sha256


def validate_witness_policy_handoff_chain_membership_anchor(
    anchor: Any,
    current_chain_ref: Any,
) -> bool:
    if not isinstance(anchor, Mapping) or set(anchor) != _ANCHOR_KEYS:
        return False
    if not validate_witness_policy_handoff_chain_ref(current_chain_ref):
        return False
    completed = current_chain_ref.get("completed_handoffs")
    return (
        anchor.get("schema") == HANDOFF_CHAIN_MEMBERSHIP_ANCHOR_SCHEMA
        and anchor.get("chain_id") == current_chain_ref.get("chain_id")
        and anchor.get("policy_id") == current_chain_ref.get("policy_id")
        and _positive_int(anchor.get("genesis_policy_epoch"))
        and anchor.get("genesis_policy_epoch")
        == current_chain_ref.get("genesis_policy_epoch")
        and anchor.get("genesis_policy_sha256")
        == current_chain_ref.get("genesis_policy_sha256")
        and _positive_int(anchor.get("completed_handoffs"))
        and anchor.get("completed_handoffs") == completed
        and _positive_int(anchor.get("current_policy_epoch"))
        and anchor.get("current_policy_epoch")
        == current_chain_ref.get("current_policy_epoch")
        and anchor.get("current_policy_sha256")
        == current_chain_ref.get("current_policy_sha256")
        and anchor.get("current_chain_ref_sha256")
        == digest_json(current_chain_ref)
        and anchor.get("current_chain_root_sha256")
        == current_chain_ref.get("chain_root_sha256")
        and anchor.get("current_step_commitment_sha256")
        == current_chain_ref.get("step_commitment_sha256")
        and _positive_int(anchor.get("tree_size"))
        and anchor.get("tree_size") == completed
        and anchor.get("tree_algorithm")
        == HANDOFF_CHAIN_MEMBERSHIP_TREE_ALGORITHM
        and _nonzero_sha(anchor.get("step_commitment_merkle_root_sha256"))
        and anchor.get("chain_contract_sha256")
        == current_chain_ref.get("chain_contract_sha256")
        and anchor.get("chain_authorization_contract_sha256")
        == current_chain_ref.get("authorization_contract_sha256")
        and _nonzero_sha(anchor.get("membership_contract_sha256"))
        and _nonzero_sha(anchor.get("authorization_contract_sha256"))
    )


def _build_anchor(
    handoffs: Sequence[_ValidatedHandoff],
    current_chain_ref: Mapping[str, Any],
    *,
    membership_contract_sha256: str,
    authorization_contract_sha256: str,
) -> Dict[str, Any]:
    leaves = [
        _leaf_hash(item.handoff_index, item.step_commitment_sha256)
        for item in handoffs
    ]
    anchor = {
        "schema": HANDOFF_CHAIN_MEMBERSHIP_ANCHOR_SCHEMA,
        "chain_id": current_chain_ref["chain_id"],
        "policy_id": current_chain_ref["policy_id"],
        "genesis_policy_epoch": current_chain_ref["genesis_policy_epoch"],
        "genesis_policy_sha256": current_chain_ref["genesis_policy_sha256"],
        "completed_handoffs": current_chain_ref["completed_handoffs"],
        "current_policy_epoch": current_chain_ref["current_policy_epoch"],
        "current_policy_sha256": current_chain_ref["current_policy_sha256"],
        "current_chain_ref_sha256": digest_json(current_chain_ref),
        "current_chain_root_sha256": current_chain_ref["chain_root_sha256"],
        "current_step_commitment_sha256": current_chain_ref[
            "step_commitment_sha256"
        ],
        "tree_size": len(handoffs),
        "tree_algorithm": HANDOFF_CHAIN_MEMBERSHIP_TREE_ALGORITHM,
        "step_commitment_merkle_root_sha256": _merkle_root(leaves),
        "chain_contract_sha256": current_chain_ref["chain_contract_sha256"],
        "chain_authorization_contract_sha256": current_chain_ref[
            "authorization_contract_sha256"
        ],
        "membership_contract_sha256": membership_contract_sha256,
        "authorization_contract_sha256": authorization_contract_sha256,
    }
    if not validate_witness_policy_handoff_chain_membership_anchor(
        anchor, current_chain_ref
    ):
        raise ValueError("handoff_chain_membership_anchor_invalid")
    return anchor


def build_witness_policy_handoff_chain_membership_anchor(
    handoff_packages: Sequence[Mapping[str, Any]],
    current_chain_ref: Mapping[str, Any],
    *,
    membership_contract_sha256: str,
    authorization_contract_sha256: str,
) -> Dict[str, Any]:
    """Build a membership anchor only after rebuilding the complete chain."""

    if not _nonzero_sha(membership_contract_sha256):
        raise ValueError("handoff_chain_membership_contract_invalid")
    if not _nonzero_sha(authorization_contract_sha256):
        raise ValueError("handoff_chain_membership_authorization_invalid")
    handoffs = _validate_handoff_history(handoff_packages, current_chain_ref)
    return _build_anchor(
        handoffs,
        current_chain_ref,
        membership_contract_sha256=membership_contract_sha256,
        authorization_contract_sha256=authorization_contract_sha256,
    )


def build_selective_witness_policy_handoff_chain_disclosure(
    handoff_packages: Sequence[Mapping[str, Any]],
    current_chain_ref: Mapping[str, Any],
    *,
    selected_handoff_index: int,
    membership_contract_sha256: str,
    authorization_contract_sha256: str,
) -> Dict[str, Any]:
    """Build one selected handoff disclosure and two logarithmic Merkle paths."""

    if not _nonzero_sha(membership_contract_sha256):
        raise ValueError("handoff_chain_membership_contract_invalid")
    if not _nonzero_sha(authorization_contract_sha256):
        raise ValueError("handoff_chain_membership_authorization_invalid")
    handoffs = _validate_handoff_history(handoff_packages, current_chain_ref)
    if (
        not _positive_int(selected_handoff_index)
        or selected_handoff_index > len(handoffs)
    ):
        raise ValueError("selected_handoff_index_invalid")
    anchor = _build_anchor(
        handoffs,
        current_chain_ref,
        membership_contract_sha256=membership_contract_sha256,
        authorization_contract_sha256=authorization_contract_sha256,
    )
    leaf_hashes = [
        _leaf_hash(item.handoff_index, item.step_commitment_sha256)
        for item in handoffs
    ]
    selected = handoffs[selected_handoff_index - 1]
    proof = {
        "schema": HANDOFF_CHAIN_MEMBERSHIP_PROOF_SCHEMA,
        "anchor_sha256": digest_json(anchor),
        "handoff_index": selected_handoff_index,
        "leaf_index": selected_handoff_index - 1,
        "tree_size": len(handoffs),
        "tree_algorithm": HANDOFF_CHAIN_MEMBERSHIP_TREE_ALGORITHM,
        "step_commitment_sha256": selected.step_commitment_sha256,
        "leaf_sha256": leaf_hashes[selected_handoff_index - 1],
        "sibling_path": _merkle_path(
            leaf_hashes, selected_handoff_index - 1
        ),
        "current_step_sibling_path": _merkle_path(
            leaf_hashes, len(leaf_hashes) - 1
        ),
    }
    disclosure = {
        "schema": HANDOFF_CHAIN_SELECTIVE_DISCLOSURE_SCHEMA,
        "anchor": anchor,
        "current_chain_ref": dict(current_chain_ref),
        "disclosed_handoff": {
            "handoff_index": selected.handoff_index,
            "previous_chain_ref": selected.previous_chain_ref,
            "handoff_package": selected.handoff_package,
            "chain_step": selected.chain_step,
            "chain_ref": selected.chain_ref,
            "step_commitment_sha256": selected.step_commitment_sha256,
        },
        "membership_proof": proof,
    }
    decision = verify_selective_witness_policy_handoff_chain_disclosure(
        disclosure
    )
    if not decision.verified:
        raise ValueError(
            f"handoff_chain_selective_disclosure_invalid:{decision.reason}"
        )
    return disclosure


def _same_chain_context(
    ref: Mapping[str, Any], anchor: Mapping[str, Any]
) -> bool:
    return (
        ref.get("chain_id") == anchor.get("chain_id")
        and ref.get("policy_id") == anchor.get("policy_id")
        and ref.get("genesis_policy_epoch")
        == anchor.get("genesis_policy_epoch")
        and ref.get("genesis_policy_sha256")
        == anchor.get("genesis_policy_sha256")
        and ref.get("chain_contract_sha256")
        == anchor.get("chain_contract_sha256")
        and ref.get("authorization_contract_sha256")
        == anchor.get("chain_authorization_contract_sha256")
    )


def verify_selective_witness_policy_handoff_chain_disclosure(
    value: Any,
) -> WitnessPolicyHandoffChainMembershipDecision:
    """Independently revalidate one disclosed handoff and both Merkle paths."""

    try:
        if not isinstance(value, Mapping) or set(value) != _DISCLOSURE_KEYS:
            raise ValueError("handoff_chain_selective_disclosure_shape_invalid")
        if value.get("schema") != HANDOFF_CHAIN_SELECTIVE_DISCLOSURE_SCHEMA:
            raise ValueError("handoff_chain_selective_disclosure_schema_invalid")

        anchor = value.get("anchor")
        current_chain_ref = value.get("current_chain_ref")
        disclosed = value.get("disclosed_handoff")
        proof = value.get("membership_proof")
        if not validate_witness_policy_handoff_chain_membership_anchor(
            anchor, current_chain_ref
        ):
            raise ValueError("handoff_chain_membership_anchor_invalid")
        if (
            not isinstance(disclosed, Mapping)
            or set(disclosed) != _DISCLOSED_HANDOFF_KEYS
        ):
            raise ValueError("disclosed_handoff_shape_invalid")
        if not isinstance(proof, Mapping) or set(proof) != _PROOF_KEYS:
            raise ValueError("handoff_chain_membership_proof_shape_invalid")
        if proof.get("schema") != HANDOFF_CHAIN_MEMBERSHIP_PROOF_SCHEMA:
            raise ValueError("handoff_chain_membership_proof_schema_invalid")
        assert isinstance(anchor, Mapping)
        assert isinstance(current_chain_ref, Mapping)

        handoff_index = disclosed.get("handoff_index")
        if not _positive_int(handoff_index):
            raise ValueError("disclosed_handoff_index_invalid")
        if proof.get("handoff_index") != handoff_index or not _positive_int(
            proof.get("handoff_index")
        ):
            raise ValueError("proof_handoff_index_mismatch")
        leaf_index = proof.get("leaf_index")
        if not _zero_based_int(leaf_index) or leaf_index != handoff_index - 1:
            raise ValueError("proof_leaf_index_mismatch")
        tree_size = proof.get("tree_size")
        if not _positive_int(tree_size) or tree_size != anchor.get("tree_size"):
            raise ValueError("proof_tree_size_mismatch")
        if handoff_index > tree_size:
            raise ValueError("proof_handoff_index_out_of_range")
        if proof.get("tree_algorithm") != HANDOFF_CHAIN_MEMBERSHIP_TREE_ALGORITHM:
            raise ValueError("proof_tree_algorithm_invalid")
        if proof.get("anchor_sha256") != digest_json(anchor):
            raise ValueError("proof_anchor_mismatch")

        package = disclosed.get("handoff_package")
        if not isinstance(package, Mapping):
            raise ValueError("disclosed_handoff_package_invalid")
        previous = disclosed.get("previous_chain_ref")
        if handoff_index == 1:
            if previous is not None:
                raise ValueError("disclosed_seed_predecessor_invalid")
            result = build_seed_witness_policy_handoff_chain(
                package,
                chain_id=str(anchor["chain_id"]),
                expected_genesis_policy_epoch=anchor["genesis_policy_epoch"],
                expected_genesis_policy_sha256=str(
                    anchor["genesis_policy_sha256"]
                ),
                chain_contract_sha256=str(anchor["chain_contract_sha256"]),
                authorization_contract_sha256=str(
                    anchor["chain_authorization_contract_sha256"]
                ),
            )
        else:
            if not validate_witness_policy_handoff_chain_ref(previous):
                raise ValueError("disclosed_predecessor_invalid")
            assert isinstance(previous, Mapping)
            if previous.get("completed_handoffs") != handoff_index - 1:
                raise ValueError("disclosed_predecessor_index_mismatch")
            if not _same_chain_context(previous, anchor):
                raise ValueError("disclosed_predecessor_context_mismatch")
            result = advance_witness_policy_handoff_chain(previous, package)
        if (
            not result.verified
            or result.step_commitment is None
            or result.chain_ref is None
        ):
            raise ValueError(result.reason)

        supplied_step = disclosed.get("chain_step")
        supplied_ref = disclosed.get("chain_ref")
        if canonical_json_bytes(result.step_commitment) != canonical_json_bytes(
            supplied_step
        ):
            raise ValueError("disclosed_handoff_step_mismatch")
        if canonical_json_bytes(result.chain_ref) != canonical_json_bytes(
            supplied_ref
        ):
            raise ValueError("disclosed_handoff_chain_ref_mismatch")
        if not validate_witness_policy_handoff_chain_ref(supplied_ref):
            raise ValueError("disclosed_handoff_chain_ref_invalid")
        assert isinstance(supplied_ref, Mapping)
        if supplied_ref.get("completed_handoffs") != handoff_index:
            raise ValueError("disclosed_handoff_chain_ref_index_mismatch")
        if not _same_chain_context(supplied_ref, anchor):
            raise ValueError("disclosed_handoff_chain_context_mismatch")

        step_commitment = digest_json(result.step_commitment)
        if disclosed.get("step_commitment_sha256") != step_commitment:
            raise ValueError("disclosed_step_commitment_mismatch")
        if supplied_ref.get("step_commitment_sha256") != step_commitment:
            raise ValueError("disclosed_chain_ref_step_commitment_mismatch")
        if proof.get("step_commitment_sha256") != step_commitment:
            raise ValueError("proof_step_commitment_mismatch")
        if handoff_index == tree_size and canonical_json_bytes(
            supplied_ref
        ) != canonical_json_bytes(current_chain_ref):
            raise ValueError("selected_current_handoff_tip_mismatch")

        leaf_sha256 = _leaf_hash(handoff_index, step_commitment)
        if proof.get("leaf_sha256") != leaf_sha256:
            raise ValueError("proof_leaf_mismatch")
        merkle_root = str(anchor["step_commitment_merkle_root_sha256"])
        if not _verify_merkle_path(
            leaf_sha256=leaf_sha256,
            leaf_index=leaf_index,
            tree_size=tree_size,
            sibling_path=proof.get("sibling_path"),
            expected_root_sha256=merkle_root,
        ):
            raise ValueError("handoff_chain_membership_path_invalid")

        current_index = anchor["tree_size"]
        current_leaf_sha256 = _leaf_hash(
            current_index, str(anchor["current_step_commitment_sha256"])
        )
        if not _verify_merkle_path(
            leaf_sha256=current_leaf_sha256,
            leaf_index=current_index - 1,
            tree_size=current_index,
            sibling_path=proof.get("current_step_sibling_path"),
            expected_root_sha256=merkle_root,
        ):
            raise ValueError("current_handoff_membership_path_invalid")

        selected_count = len(proof["sibling_path"])
        current_count = len(proof["current_step_sibling_path"])
        return WitnessPolicyHandoffChainMembershipDecision(
            True,
            HANDOFF_CHAIN_MEMBERSHIP_REASON,
            disclosed_handoff_index=handoff_index,
            anchor_sha256=digest_json(anchor),
            step_commitment_sha256=step_commitment,
            selected_sibling_hash_count=selected_count,
            current_sibling_hash_count=current_count,
            sibling_hash_count=selected_count + current_count,
        )
    except RecursionError:
        return WitnessPolicyHandoffChainMembershipDecision(
            False, "handoff_chain_selective_disclosure_too_deep"
        )
    except (KeyError, TypeError, ValueError) as error:
        return WitnessPolicyHandoffChainMembershipDecision(False, str(error))
