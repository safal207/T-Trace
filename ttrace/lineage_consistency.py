"""Hardened public surface for lineage membership-root consistency.

The original compact-frontier implementation is retained in the private
``lineage_consistency_core`` module so its construction logic and review history stay
stable. This module adds exact membership-context binding for authority statements
and closes Python's ``bool``-is-``int`` edge case for proof block offsets, then patches
those public entry points back into the core module so internally defined builders
also use the hardened validators.
"""

from __future__ import annotations

from typing import Any, Dict, Mapping, Optional

from . import lineage_consistency_core as _core
from .lineage_compaction import ZERO_SHA256
from .lineage_consistency_core import *  # noqa: F401,F403
from .lineage_membership import validate_lineage_membership_anchor
from .portable_causality import digest_json, is_sha256


_STATEMENT_CONTEXT_KEYS = {
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
    "tree_algorithm",
    "membership_contract_sha256",
    "authorization_contract_sha256",
}
_EQUIVOCATION_CONTEXT_EVIDENCE_KEYS = {
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
    "tree_algorithm",
    "membership_contract_sha256",
    "authorization_contract_sha256",
    "global_non_equivocation_status",
}

_core_verify_lineage_root_consistency = _core.verify_lineage_root_consistency


def _text(value: Any) -> bool:
    return isinstance(value, str) and bool(value)


def _positive_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value > 0


def verify_lineage_root_consistency(value: Any) -> LineageConsistencyDecision:
    """Verify root consistency with strict JSON integer semantics for block starts."""

    if isinstance(value, Mapping):
        proof = value.get("consistency_proof")
        if isinstance(proof, Mapping):
            for field, reason in (
                ("old_frontier", "consistency_old_frontier_invalid"),
                ("append_blocks", "consistency_append_blocks_invalid"),
            ):
                blocks = proof.get(field)
                if isinstance(blocks, list) and any(
                    isinstance(block, Mapping)
                    and isinstance(block.get("start"), bool)
                    for block in blocks
                ):
                    return LineageConsistencyDecision(False, reason)
    return _core_verify_lineage_root_consistency(value)


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
    """Normalize one externally verified statement in its full membership context."""

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
    if (
        not is_sha256(statement_provenance_sha256)
        or statement_provenance_sha256 == ZERO_SHA256
    ):
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
        "tree_algorithm": membership_anchor["tree_algorithm"],
        "membership_contract_sha256": membership_anchor[
            "membership_contract_sha256"
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
    """Validate exact statement shape and bind every membership-context field."""

    if (
        not isinstance(statement, Mapping)
        or set(statement) != _STATEMENT_CONTEXT_KEYS
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
            else is_sha256(previous) and previous != ZERO_SHA256
        )
        and is_sha256(statement.get("statement_provenance_sha256"))
        and statement.get("statement_provenance_sha256") != ZERO_SHA256
        and statement.get("trust_domain")
        == membership_anchor.get("trust_domain")
        and statement.get("logical_state_id")
        == membership_anchor.get("logical_state_id")
        and statement.get("tree_size") == membership_anchor.get("tree_size")
        and statement.get("anchor_sha256") == digest_json(membership_anchor)
        and statement.get("membership_root_sha256")
        == membership_anchor.get("cycle_commitment_merkle_root_sha256")
        and statement.get("tree_algorithm")
        == membership_anchor.get("tree_algorithm")
        and statement.get("membership_contract_sha256")
        == membership_anchor.get("membership_contract_sha256")
        and statement.get("authorization_contract_sha256")
        == membership_anchor.get("authorization_contract_sha256")
    )


def verify_authorized_lineage_root_consistency(
    package: Any,
    old_statement: Any,
    new_statement: Any,
) -> AuthorizedLineageConsistencyDecision:
    """Verify append-only roots plus direct context-bound statement continuity."""

    consistency = verify_lineage_root_consistency(package)
    if not consistency.verified:
        return AuthorizedLineageConsistencyDecision(False, consistency.reason)
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
    if old_statement.get("authority_id") != new_statement.get("authority_id"):
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
    """Compare two verified statements only inside one exact membership context."""

    if not validate_lineage_anchor_statement(
        statement_a, anchor_a, accumulator_a
    ) or not validate_lineage_anchor_statement(
        statement_b, anchor_b, accumulator_b
    ):
        return LineageEquivocationDecision(False, "anchor_statement_invalid")
    assert isinstance(anchor_a, Mapping)
    assert isinstance(anchor_b, Mapping)
    assert isinstance(statement_a, Mapping)
    assert isinstance(statement_b, Mapping)

    comparable = (
        statement_a.get("authority_id") == statement_b.get("authority_id")
        and statement_a.get("trust_domain") == statement_b.get("trust_domain")
        and statement_a.get("logical_state_id")
        == statement_b.get("logical_state_id")
        and statement_a.get("tree_algorithm")
        == statement_b.get("tree_algorithm")
        and statement_a.get("membership_contract_sha256")
        == statement_b.get("membership_contract_sha256")
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
        "authority_id": statement_a["authority_id"] if comparable else None,
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
        "tree_algorithm": (
            statement_a["tree_algorithm"] if comparable else None
        ),
        "membership_contract_sha256": (
            statement_a["membership_contract_sha256"]
            if comparable
            else None
        ),
        "authorization_contract_sha256": (
            statement_a["authorization_contract_sha256"]
            if comparable
            else None
        ),
        "global_non_equivocation_status": GLOBAL_NON_EQUIVOCATION_STATUS,
    }
    if set(evidence) != _EQUIVOCATION_CONTEXT_EVIDENCE_KEYS:
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


# Core builder functions resolve these names at runtime. Patching the private core
# keeps both direct submodule imports and internally defined builders on the hardened
# public validators without duplicating the compact-frontier implementation.
_core.verify_lineage_root_consistency = verify_lineage_root_consistency
_core.build_lineage_anchor_statement = build_lineage_anchor_statement
_core.validate_lineage_anchor_statement = validate_lineage_anchor_statement
_core.verify_authorized_lineage_root_consistency = (
    verify_authorized_lineage_root_consistency
)
_core.detect_lineage_anchor_equivocation = detect_lineage_anchor_equivocation
