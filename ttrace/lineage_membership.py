"""Selective disclosure proofs for compacted T-Trace reconciliation lineage.

The rolling lineage accumulator is intentionally fixed-shape, but its linear hash
chain is not membership-friendly: proving an old cycle directly from that chain
would require revealing every later accumulator. This profile adds a companion
Merkle commitment over validated cycle commitments. A verifier can then validate
one disclosed fork/reconciliation cycle with O(log n) sibling hashes while the
intervening cycles remain undisclosed.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

from .lineage_compaction import (
    LINEAGE_CYCLE_SUMMARY_SCHEMA,
    ZERO_SHA256,
    validate_lineage_accumulator,
)
from .portable_causality import (
    ReconciliationAgreement,
    canonical_json_bytes,
    digest_json,
    is_sha256,
    validate_reconciliation_agreement,
    validate_state_ref,
)

LINEAGE_MEMBERSHIP_LEAF_SCHEMA = "ttrace-lineage-membership-leaf/v0.1"
LINEAGE_MEMBERSHIP_NODE_SCHEMA = "ttrace-lineage-membership-node/v0.1"
LINEAGE_MEMBERSHIP_ANCHOR_SCHEMA = "ttrace-lineage-membership-anchor/v0.1"
LINEAGE_MEMBERSHIP_PROOF_SCHEMA = "ttrace-lineage-membership-proof/v0.1"
LINEAGE_SELECTIVE_DISCLOSURE_SCHEMA = "ttrace-lineage-selective-disclosure/v0.1"
LINEAGE_MEMBERSHIP_REASON = "lineage_selective_disclosure_verified"
LINEAGE_MEMBERSHIP_TREE_ALGORITHM = "pairwise-duplicate-last-sha256/v0.1"

_CYCLE_RECORD_KEYS = {
    "cycle_index",
    "common_state_ref",
    "reconciliation",
    "lineage_accumulator",
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
_ANCHOR_KEYS = {
    "schema",
    "trust_domain",
    "logical_state_id",
    "completed_reconciliation_cycles",
    "current_causal_epoch",
    "current_accumulator_sha256",
    "current_lineage_root_sha256",
    "current_cycle_commitment_sha256",
    "tree_size",
    "tree_algorithm",
    "cycle_commitment_merkle_root_sha256",
    "membership_contract_sha256",
    "authorization_contract_sha256",
}
_PROOF_KEYS = {
    "schema",
    "anchor_sha256",
    "cycle_index",
    "leaf_index",
    "tree_size",
    "tree_algorithm",
    "cycle_commitment_sha256",
    "leaf_sha256",
    "sibling_path",
    "current_cycle_sibling_path",
}
_DISCLOSED_CYCLE_KEYS = {
    "cycle_index",
    "common_state_ref",
    "reconciliation",
    "lineage_accumulator",
    "cycle_summary",
    "cycle_commitment_sha256",
}
_DISCLOSURE_KEYS = {
    "schema",
    "anchor",
    "current_accumulator",
    "disclosed_cycle",
    "membership_proof",
}
_PATH_ENTRY_KEYS = {"side", "sha256"}
_FORBIDDEN_DISCLOSURE_KEYS = {
    "provider_id",
    "authority_id",
    "provenance_sha256",
    "branch_evidence",
    "reconciliation_votes",
    "cycle_records",
    "all_cycles",
}


@dataclass(frozen=True)
class LineageMembershipDecision:
    verified: bool
    reason: str
    disclosed_cycle_index: Optional[int] = None
    anchor_sha256: Optional[str] = None
    cycle_commitment_sha256: Optional[str] = None
    sibling_hash_count: Optional[int] = None


@dataclass(frozen=True)
class _ValidatedCycle:
    cycle_index: int
    common_state_ref: Dict[str, Any]
    reconciliation: ReconciliationAgreement
    reconciliation_dict: Dict[str, Any]
    lineage_accumulator: Dict[str, Any]
    cycle_summary: Dict[str, Any]
    cycle_commitment_sha256: str


def _text(value: Any) -> bool:
    return isinstance(value, str) and bool(value)


def _positive_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value > 0


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
    if any(item is not None and not isinstance(item, Mapping) for item in optional_objects):
        raise ValueError("reconciliation_sections_invalid")
    return ReconciliationAgreement(
        verified=value.get("verified") is True,
        reason=str(value.get("reason", "")),
        branch_tips=tuple(dict(item) for item in branch_tips),
        parent_set=(dict(value["parent_set"]) if value.get("parent_set") is not None else None),
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
        receipt=(dict(value["receipt"]) if value.get("receipt") is not None else None),
    )


def build_lineage_cycle_summary(
    cycle_index: int,
    common_state_ref: Mapping[str, Any],
    reconciliation: ReconciliationAgreement,
) -> Dict[str, Any]:
    """Recompute the exact cycle commitment used by LineageAccumulatorRef."""

    if not _positive_int(cycle_index):
        raise ValueError("cycle_index_invalid")
    if not validate_reconciliation_agreement(reconciliation, common_state_ref):
        raise ValueError("reconciliation_agreement_invalid")
    assert reconciliation.parent_set is not None
    assert reconciliation.reconciled_state_ref is not None
    assert reconciliation.reconciliation_ref is not None
    assert reconciliation.receipt is not None
    return {
        "schema": LINEAGE_CYCLE_SUMMARY_SCHEMA,
        "cycle_index": cycle_index,
        "common_state_ref_sha256": digest_json(common_state_ref),
        "fork_causal_epoch": reconciliation.receipt["fork_causal_epoch"],
        "reconciled_causal_epoch": reconciliation.receipt[
            "reconciled_causal_epoch"
        ],
        "branch_tip_set_sha256": digest_json(
            [digest_json(tip) for tip in reconciliation.branch_tips]
        ),
        "parent_set_sha256": digest_json(reconciliation.parent_set),
        "reconciliation_ref_sha256": digest_json(
            reconciliation.reconciliation_ref
        ),
        "result_state_ref_sha256": digest_json(
            reconciliation.reconciled_state_ref
        ),
        "receipt_sha256": digest_json(reconciliation.receipt),
        "reconciliation_contract_sha256": reconciliation.reconciliation_ref[
            "reconciliation_contract_sha256"
        ],
        "authorization_contract_sha256": reconciliation.reconciliation_ref[
            "authorization_contract_sha256"
        ],
    }


def _validate_cycle_record(
    value: Any,
    expected_cycle_index: int,
    previous: Optional[_ValidatedCycle],
) -> _ValidatedCycle:
    if not isinstance(value, Mapping) or set(value) != _CYCLE_RECORD_KEYS:
        raise ValueError("cycle_record_invalid")
    cycle_index = value.get("cycle_index")
    if cycle_index != expected_cycle_index or not _positive_int(cycle_index):
        raise ValueError("cycle_index_not_contiguous")
    common_state_ref = value.get("common_state_ref")
    accumulator = value.get("lineage_accumulator")
    if not validate_state_ref(common_state_ref):
        raise ValueError("cycle_common_state_invalid")
    if not validate_lineage_accumulator(accumulator):
        raise ValueError("cycle_accumulator_invalid")
    assert isinstance(common_state_ref, Mapping)
    assert isinstance(accumulator, Mapping)
    reconciliation_dict = value.get("reconciliation")
    reconciliation = _reconciliation_from_mapping(reconciliation_dict)
    if not validate_reconciliation_agreement(reconciliation, common_state_ref):
        raise ValueError("cycle_reconciliation_invalid")
    assert reconciliation.reconciled_state_ref is not None

    summary = build_lineage_cycle_summary(
        cycle_index, common_state_ref, reconciliation
    )
    commitment = digest_json(summary)
    if accumulator.get("completed_reconciliation_cycles") != cycle_index:
        raise ValueError("cycle_accumulator_index_mismatch")
    if accumulator.get("trust_domain") != reconciliation.reconciled_state_ref.get(
        "trust_domain"
    ):
        raise ValueError("cycle_accumulator_domain_mismatch")
    if accumulator.get("logical_state_id") != reconciliation.reconciled_state_ref.get(
        "logical_state_id"
    ):
        raise ValueError("cycle_accumulator_state_id_mismatch")
    if accumulator.get("current_causal_epoch") != reconciliation.reconciled_state_ref.get(
        "causal_epoch"
    ):
        raise ValueError("cycle_accumulator_epoch_mismatch")
    if accumulator.get("current_state_ref_sha256") != digest_json(
        reconciliation.reconciled_state_ref
    ):
        raise ValueError("cycle_accumulator_state_mismatch")
    if accumulator.get("current_reconciliation_sha256") != digest_json(
        reconciliation.to_dict()
    ):
        raise ValueError("cycle_accumulator_reconciliation_mismatch")
    if accumulator.get("cycle_commitment_sha256") != commitment:
        raise ValueError("cycle_commitment_mismatch")

    if previous is None:
        if cycle_index != 1:
            raise ValueError("cycle_chain_must_start_at_one")
        if (
            accumulator.get("previous_accumulator_sha256") != ZERO_SHA256
            or accumulator.get("previous_lineage_root_sha256") != ZERO_SHA256
        ):
            raise ValueError("seed_cycle_predecessor_invalid")
    else:
        if previous.reconciliation.reconciled_state_ref is None:
            raise ValueError("previous_cycle_state_missing")
        if canonical_json_bytes(common_state_ref) != canonical_json_bytes(
            previous.reconciliation.reconciled_state_ref
        ):
            raise ValueError("cycle_common_state_discontinuity")
        if accumulator.get("previous_accumulator_sha256") != digest_json(
            previous.lineage_accumulator
        ):
            raise ValueError("cycle_previous_accumulator_mismatch")
        if accumulator.get("previous_lineage_root_sha256") != previous.lineage_accumulator.get(
            "lineage_root_sha256"
        ):
            raise ValueError("cycle_previous_root_mismatch")
        if accumulator.get("accumulator_contract_sha256") != previous.lineage_accumulator.get(
            "accumulator_contract_sha256"
        ):
            raise ValueError("cycle_accumulator_contract_drift")
        if accumulator.get("authorization_contract_sha256") != previous.lineage_accumulator.get(
            "authorization_contract_sha256"
        ):
            raise ValueError("cycle_accumulator_authorization_drift")

    return _ValidatedCycle(
        cycle_index=cycle_index,
        common_state_ref=dict(common_state_ref),
        reconciliation=reconciliation,
        reconciliation_dict=dict(reconciliation_dict),
        lineage_accumulator=dict(accumulator),
        cycle_summary=summary,
        cycle_commitment_sha256=commitment,
    )


def _validate_cycle_chain(
    cycle_records: Sequence[Mapping[str, Any]],
    current_accumulator: Mapping[str, Any],
) -> Tuple[_ValidatedCycle, ...]:
    if not isinstance(cycle_records, Sequence) or isinstance(
        cycle_records, (str, bytes)
    ):
        raise ValueError("cycle_records_invalid")
    if not cycle_records:
        raise ValueError("cycle_records_empty")
    if not validate_lineage_accumulator(current_accumulator):
        raise ValueError("current_accumulator_invalid")

    validated: List[_ValidatedCycle] = []
    previous: Optional[_ValidatedCycle] = None
    for expected_index, value in enumerate(cycle_records, start=1):
        cycle = _validate_cycle_record(value, expected_index, previous)
        validated.append(cycle)
        previous = cycle

    last = validated[-1]
    if len(validated) != current_accumulator.get("completed_reconciliation_cycles"):
        raise ValueError("cycle_count_accumulator_mismatch")
    if canonical_json_bytes(last.lineage_accumulator) != canonical_json_bytes(
        current_accumulator
    ):
        raise ValueError("current_accumulator_not_chain_tip")
    return tuple(validated)


def _leaf_payload(cycle_index: int, cycle_commitment_sha256: str) -> Dict[str, Any]:
    if not _positive_int(cycle_index) or not is_sha256(cycle_commitment_sha256):
        raise ValueError("membership_leaf_invalid")
    return {
        "schema": LINEAGE_MEMBERSHIP_LEAF_SCHEMA,
        "cycle_index": cycle_index,
        "cycle_commitment_sha256": cycle_commitment_sha256,
    }


def _leaf_hash(cycle_index: int, cycle_commitment_sha256: str) -> str:
    return digest_json(_leaf_payload(cycle_index, cycle_commitment_sha256))


def _node_hash(left_sha256: str, right_sha256: str) -> str:
    if not is_sha256(left_sha256) or not is_sha256(right_sha256):
        raise ValueError("membership_node_invalid")
    return digest_json(
        {
            "schema": LINEAGE_MEMBERSHIP_NODE_SCHEMA,
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
    if not leaf_hashes or not all(is_sha256(item) for item in leaf_hashes):
        raise ValueError("membership_leaf_set_invalid")
    level = list(leaf_hashes)
    while len(level) > 1:
        level = _next_level(level)
    return level[0]


def _merkle_path(leaf_hashes: Sequence[str], leaf_index: int) -> List[Dict[str, Any]]:
    if not leaf_hashes or not isinstance(leaf_index, int) or isinstance(leaf_index, bool):
        raise ValueError("membership_leaf_index_invalid")
    if leaf_index < 0 or leaf_index >= len(leaf_hashes):
        raise ValueError("membership_leaf_index_invalid")
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
        raise ValueError("membership_tree_size_invalid")
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
        not is_sha256(leaf_sha256)
        or not is_sha256(expected_root_sha256)
        or not _positive_int(tree_size)
        or not isinstance(leaf_index, int)
        or isinstance(leaf_index, bool)
        or leaf_index < 0
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
        if side not in {"left", "right"} or not is_sha256(sibling):
            return False
        expected_side = "left" if index % 2 else "right"
        if side != expected_side:
            return False
        if index % 2 == 0 and index + 1 >= width and sibling != current:
            return False
        current = (
            _node_hash(sibling, current)
            if side == "left"
            else _node_hash(current, sibling)
        )
        index //= 2
        width = (width + 1) // 2
    return width == 1 and index == 0 and current == expected_root_sha256


def validate_lineage_membership_anchor(
    anchor: Any,
    current_accumulator: Any,
) -> bool:
    if not isinstance(anchor, Mapping) or set(anchor) != _ANCHOR_KEYS:
        return False
    if not validate_lineage_accumulator(current_accumulator):
        return False
    cycles = current_accumulator.get("completed_reconciliation_cycles")
    epoch = current_accumulator.get("current_causal_epoch")
    return (
        anchor.get("schema") == LINEAGE_MEMBERSHIP_ANCHOR_SCHEMA
        and anchor.get("trust_domain") == current_accumulator.get("trust_domain")
        and anchor.get("logical_state_id")
        == current_accumulator.get("logical_state_id")
        and anchor.get("completed_reconciliation_cycles") == cycles
        and anchor.get("current_causal_epoch") == epoch
        and anchor.get("current_accumulator_sha256")
        == digest_json(current_accumulator)
        and anchor.get("current_lineage_root_sha256")
        == current_accumulator.get("lineage_root_sha256")
        and anchor.get("current_cycle_commitment_sha256")
        == current_accumulator.get("cycle_commitment_sha256")
        and anchor.get("tree_size") == cycles
        and anchor.get("tree_algorithm") == LINEAGE_MEMBERSHIP_TREE_ALGORITHM
        and is_sha256(anchor.get("cycle_commitment_merkle_root_sha256"))
        and anchor.get("cycle_commitment_merkle_root_sha256") != ZERO_SHA256
        and is_sha256(anchor.get("membership_contract_sha256"))
        and anchor.get("membership_contract_sha256") != ZERO_SHA256
        and is_sha256(anchor.get("authorization_contract_sha256"))
        and anchor.get("authorization_contract_sha256") != ZERO_SHA256
    )


def build_lineage_membership_anchor(
    cycle_records: Sequence[Mapping[str, Any]],
    current_accumulator: Mapping[str, Any],
    *,
    membership_contract_sha256: str,
    authorization_contract_sha256: str,
) -> Dict[str, Any]:
    if not is_sha256(membership_contract_sha256) or membership_contract_sha256 == ZERO_SHA256:
        raise ValueError("membership_contract_invalid")
    if not is_sha256(authorization_contract_sha256) or authorization_contract_sha256 == ZERO_SHA256:
        raise ValueError("membership_authorization_invalid")
    cycles = _validate_cycle_chain(cycle_records, current_accumulator)
    leaves = [
        _leaf_hash(item.cycle_index, item.cycle_commitment_sha256)
        for item in cycles
    ]
    anchor = {
        "schema": LINEAGE_MEMBERSHIP_ANCHOR_SCHEMA,
        "trust_domain": current_accumulator["trust_domain"],
        "logical_state_id": current_accumulator["logical_state_id"],
        "completed_reconciliation_cycles": current_accumulator[
            "completed_reconciliation_cycles"
        ],
        "current_causal_epoch": current_accumulator["current_causal_epoch"],
        "current_accumulator_sha256": digest_json(current_accumulator),
        "current_lineage_root_sha256": current_accumulator["lineage_root_sha256"],
        "current_cycle_commitment_sha256": current_accumulator[
            "cycle_commitment_sha256"
        ],
        "tree_size": len(cycles),
        "tree_algorithm": LINEAGE_MEMBERSHIP_TREE_ALGORITHM,
        "cycle_commitment_merkle_root_sha256": _merkle_root(leaves),
        "membership_contract_sha256": membership_contract_sha256,
        "authorization_contract_sha256": authorization_contract_sha256,
    }
    if not validate_lineage_membership_anchor(anchor, current_accumulator):
        raise ValueError("membership_anchor_invalid")
    return anchor


def _contains_forbidden_disclosure_key(value: Any) -> bool:
    if isinstance(value, Mapping):
        if _FORBIDDEN_DISCLOSURE_KEYS & set(value):
            return True
        return any(_contains_forbidden_disclosure_key(item) for item in value.values())
    if isinstance(value, (list, tuple)):
        return any(_contains_forbidden_disclosure_key(item) for item in value)
    return False


def build_selective_lineage_disclosure(
    cycle_records: Sequence[Mapping[str, Any]],
    current_accumulator: Mapping[str, Any],
    *,
    selected_cycle_index: int,
    membership_contract_sha256: str,
    authorization_contract_sha256: str,
) -> Dict[str, Any]:
    cycles = _validate_cycle_chain(cycle_records, current_accumulator)
    if not _positive_int(selected_cycle_index) or selected_cycle_index > len(cycles):
        raise ValueError("selected_cycle_index_invalid")
    anchor = build_lineage_membership_anchor(
        cycle_records,
        current_accumulator,
        membership_contract_sha256=membership_contract_sha256,
        authorization_contract_sha256=authorization_contract_sha256,
    )
    leaf_hashes = [
        _leaf_hash(item.cycle_index, item.cycle_commitment_sha256)
        for item in cycles
    ]
    selected = cycles[selected_cycle_index - 1]
    leaf_sha256 = leaf_hashes[selected_cycle_index - 1]
    proof = {
        "schema": LINEAGE_MEMBERSHIP_PROOF_SCHEMA,
        "anchor_sha256": digest_json(anchor),
        "cycle_index": selected_cycle_index,
        "leaf_index": selected_cycle_index - 1,
        "tree_size": len(cycles),
        "tree_algorithm": LINEAGE_MEMBERSHIP_TREE_ALGORITHM,
        "cycle_commitment_sha256": selected.cycle_commitment_sha256,
        "leaf_sha256": leaf_sha256,
        "sibling_path": _merkle_path(leaf_hashes, selected_cycle_index - 1),
        "current_cycle_sibling_path": _merkle_path(
            leaf_hashes, len(leaf_hashes) - 1
        ),
    }
    disclosure = {
        "schema": LINEAGE_SELECTIVE_DISCLOSURE_SCHEMA,
        "anchor": anchor,
        "current_accumulator": dict(current_accumulator),
        "disclosed_cycle": {
            "cycle_index": selected.cycle_index,
            "common_state_ref": selected.common_state_ref,
            "reconciliation": selected.reconciliation_dict,
            "lineage_accumulator": selected.lineage_accumulator,
            "cycle_summary": selected.cycle_summary,
            "cycle_commitment_sha256": selected.cycle_commitment_sha256,
        },
        "membership_proof": proof,
    }
    decision = verify_selective_lineage_disclosure(disclosure)
    if not decision.verified:
        raise ValueError(f"selective_disclosure_invalid:{decision.reason}")
    return disclosure


def verify_selective_lineage_disclosure(value: Any) -> LineageMembershipDecision:
    try:
        if not isinstance(value, Mapping) or set(value) != _DISCLOSURE_KEYS:
            raise ValueError("selective_disclosure_shape_invalid")
        if value.get("schema") != LINEAGE_SELECTIVE_DISCLOSURE_SCHEMA:
            raise ValueError("selective_disclosure_schema_invalid")
        if _contains_forbidden_disclosure_key(value):
            raise ValueError("raw_evidence_or_full_history_disclosed")

        anchor = value.get("anchor")
        current_accumulator = value.get("current_accumulator")
        disclosed = value.get("disclosed_cycle")
        proof = value.get("membership_proof")
        if not validate_lineage_membership_anchor(anchor, current_accumulator):
            raise ValueError("membership_anchor_invalid")
        if not isinstance(disclosed, Mapping) or set(disclosed) != _DISCLOSED_CYCLE_KEYS:
            raise ValueError("disclosed_cycle_shape_invalid")
        if not isinstance(proof, Mapping) or set(proof) != _PROOF_KEYS:
            raise ValueError("membership_proof_shape_invalid")
        if proof.get("schema") != LINEAGE_MEMBERSHIP_PROOF_SCHEMA:
            raise ValueError("membership_proof_schema_invalid")
        assert isinstance(anchor, Mapping)
        assert isinstance(current_accumulator, Mapping)

        cycle_index = disclosed.get("cycle_index")
        if not _positive_int(cycle_index):
            raise ValueError("disclosed_cycle_index_invalid")
        if cycle_index != proof.get("cycle_index"):
            raise ValueError("proof_cycle_index_mismatch")
        if proof.get("leaf_index") != cycle_index - 1:
            raise ValueError("proof_leaf_index_mismatch")
        if proof.get("tree_size") != anchor.get("tree_size"):
            raise ValueError("proof_tree_size_mismatch")
        if proof.get("tree_algorithm") != LINEAGE_MEMBERSHIP_TREE_ALGORITHM:
            raise ValueError("proof_tree_algorithm_invalid")
        if proof.get("anchor_sha256") != digest_json(anchor):
            raise ValueError("proof_anchor_mismatch")

        common_state_ref = disclosed.get("common_state_ref")
        if not validate_state_ref(common_state_ref):
            raise ValueError("disclosed_common_state_invalid")
        assert isinstance(common_state_ref, Mapping)
        reconciliation = _reconciliation_from_mapping(disclosed.get("reconciliation"))
        if not validate_reconciliation_agreement(reconciliation, common_state_ref):
            raise ValueError("disclosed_reconciliation_invalid")
        summary = build_lineage_cycle_summary(
            cycle_index, common_state_ref, reconciliation
        )
        if canonical_json_bytes(summary) != canonical_json_bytes(
            disclosed.get("cycle_summary")
        ):
            raise ValueError("disclosed_cycle_summary_mismatch")
        commitment = digest_json(summary)
        if disclosed.get("cycle_commitment_sha256") != commitment:
            raise ValueError("disclosed_cycle_commitment_mismatch")
        if proof.get("cycle_commitment_sha256") != commitment:
            raise ValueError("proof_cycle_commitment_mismatch")

        selected_accumulator = disclosed.get("lineage_accumulator")
        if not validate_lineage_accumulator(selected_accumulator):
            raise ValueError("disclosed_accumulator_invalid")
        assert isinstance(selected_accumulator, Mapping)
        assert reconciliation.reconciled_state_ref is not None
        if selected_accumulator.get("completed_reconciliation_cycles") != cycle_index:
            raise ValueError("disclosed_accumulator_index_mismatch")
        if selected_accumulator.get("current_state_ref_sha256") != digest_json(
            reconciliation.reconciled_state_ref
        ):
            raise ValueError("disclosed_accumulator_state_mismatch")
        if selected_accumulator.get("current_reconciliation_sha256") != digest_json(
            reconciliation.to_dict()
        ):
            raise ValueError("disclosed_accumulator_reconciliation_mismatch")
        if selected_accumulator.get("cycle_commitment_sha256") != commitment:
            raise ValueError("disclosed_accumulator_commitment_mismatch")
        if cycle_index == 1 and (
            selected_accumulator.get("previous_accumulator_sha256") != ZERO_SHA256
            or selected_accumulator.get("previous_lineage_root_sha256") != ZERO_SHA256
        ):
            raise ValueError("disclosed_seed_predecessor_invalid")
        if cycle_index > 1 and (
            selected_accumulator.get("previous_accumulator_sha256") == ZERO_SHA256
            or selected_accumulator.get("previous_lineage_root_sha256") == ZERO_SHA256
        ):
            raise ValueError("disclosed_predecessor_missing")

        leaf_sha256 = _leaf_hash(cycle_index, commitment)
        if proof.get("leaf_sha256") != leaf_sha256:
            raise ValueError("proof_leaf_mismatch")
        if not _verify_merkle_path(
            leaf_sha256=leaf_sha256,
            leaf_index=int(proof["leaf_index"]),
            tree_size=int(proof["tree_size"]),
            sibling_path=proof.get("sibling_path"),
            expected_root_sha256=str(
                anchor["cycle_commitment_merkle_root_sha256"]
            ),
        ):
            raise ValueError("membership_path_invalid")

        current_cycle_index = int(anchor["tree_size"])
        current_cycle_leaf_sha256 = _leaf_hash(
            current_cycle_index,
            str(anchor["current_cycle_commitment_sha256"]),
        )
        if not _verify_merkle_path(
            leaf_sha256=current_cycle_leaf_sha256,
            leaf_index=current_cycle_index - 1,
            tree_size=current_cycle_index,
            sibling_path=proof.get("current_cycle_sibling_path"),
            expected_root_sha256=str(
                anchor["cycle_commitment_merkle_root_sha256"]
            ),
        ):
            raise ValueError("current_cycle_membership_path_invalid")

        return LineageMembershipDecision(
            True,
            LINEAGE_MEMBERSHIP_REASON,
            disclosed_cycle_index=cycle_index,
            anchor_sha256=digest_json(anchor),
            cycle_commitment_sha256=commitment,
            sibling_hash_count=len(proof["sibling_path"]),
        )
    except (KeyError, RecursionError, TypeError, ValueError) as error:
        return LineageMembershipDecision(False, str(error))
