"""Dual-quorum witness-policy handoff without an anti-equivocation gap.

The handoff is a separate acceptance primitive above witness quorum packages. It
binds one exact lineage-anchor statement and both exact witness policies. A valid
package requires:

* the current view accepted by an old-policy quorum;
* the same view accepted by a new-policy activation quorum;
* an exact handoff statement observed by an old-policy quorum and a new-policy
  quorum;
* direct predecessor continuity from the old active quorum into the handoff and
  from the handoff into the new activation quorum.

The module normalizes externally verified observations. It does not verify
signatures or attestations from a caller-provided boolean.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Mapping, Optional, Sequence, Tuple

from .lineage_compaction import ZERO_SHA256
from .lineage_consistency import (
    GLOBAL_NON_EQUIVOCATION_STATUS,
    validate_lineage_anchor_statement,
)
from .lineage_witness import (
    CONDITIONAL_NON_EQUIVOCATION_STATUS,
    minimum_quorum_intersection,
    validate_lineage_witness_policy,
    verify_lineage_witness_quorum_package,
)
from .portable_causality import digest_json, is_sha256

LINEAGE_WITNESS_POLICY_HANDOFF_STATEMENT_SCHEMA = (
    "ttrace-lineage-witness-policy-handoff-statement/v0.1"
)
LINEAGE_WITNESS_POLICY_HANDOFF_OBSERVATION_SCHEMA = (
    "ttrace-lineage-witness-policy-handoff-observation/v0.1"
)
LINEAGE_WITNESS_POLICY_HANDOFF_QUORUM_CERTIFICATE_SCHEMA = (
    "ttrace-lineage-witness-policy-handoff-quorum-certificate/v0.1"
)
LINEAGE_WITNESS_POLICY_HANDOFF_CERTIFICATE_SCHEMA = (
    "ttrace-lineage-witness-policy-handoff-certificate/v0.1"
)
LINEAGE_WITNESS_POLICY_HANDOFF_PACKAGE_SCHEMA = (
    "ttrace-lineage-witness-policy-handoff-package/v0.1"
)
LINEAGE_WITNESS_POLICY_HANDOFF_EQUIVOCATION_EVIDENCE_SCHEMA = (
    "ttrace-lineage-witness-policy-handoff-equivocation-evidence/v0.1"
)
LINEAGE_WITNESS_POLICY_HANDOFF_REASON = "lineage_witness_policy_handoff_verified"
LINEAGE_WITNESS_POLICY_HANDOFF_EQUIVOCATION_DETECTED_REASON = (
    "lineage_witness_policy_handoff_equivocation_detected"
)
LINEAGE_WITNESS_POLICY_HANDOFF_EQUIVOCATION_NOT_PROVEN_REASON = (
    "lineage_witness_policy_handoff_equivocation_not_proven"
)
CONDITIONAL_HANDOFF_STATUS = "dual-quorum-handoff-verified"

_HANDOFF_STATEMENT_KEYS = {
    "schema",
    "verified",
    "authority_id",
    "trust_domain",
    "logical_state_id",
    "tree_size",
    "anchor_sha256",
    "membership_root_sha256",
    "producer_statement_sha256",
    "policy_id",
    "old_policy_sha256",
    "new_policy_sha256",
    "old_policy_epoch",
    "new_policy_epoch",
    "handoff_contract_sha256",
    "authorization_contract_sha256",
    "handoff_provenance_sha256",
}
_HANDOFF_OBSERVATION_KEYS = {
    "schema",
    "verified",
    "witness_id",
    "witness_sequence",
    "previous_observation_sha256",
    "observation_provenance_sha256",
    "handoff_statement_sha256",
    "producer_statement_sha256",
    "old_policy_sha256",
    "new_policy_sha256",
    "authority_id",
    "trust_domain",
    "logical_state_id",
    "tree_size",
    "anchor_sha256",
    "membership_root_sha256",
}
_ROLE_CERTIFICATE_KEYS = {
    "schema",
    "verified",
    "role",
    "handoff_statement_sha256",
    "witness_policy_sha256",
    "threshold",
    "authorized_witness_count",
    "minimum_quorum_intersection",
    "witness_count",
    "witness_ids",
    "handoff_observation_sha256",
}
_HANDOFF_CERTIFICATE_KEYS = {
    "schema",
    "verified",
    "reason",
    "handoff_statement_sha256",
    "producer_statement_sha256",
    "authority_id",
    "trust_domain",
    "logical_state_id",
    "tree_size",
    "anchor_sha256",
    "membership_root_sha256",
    "policy_id",
    "old_policy_sha256",
    "new_policy_sha256",
    "old_policy_epoch",
    "new_policy_epoch",
    "old_active_certificate_sha256",
    "old_handoff_certificate_sha256",
    "new_handoff_certificate_sha256",
    "new_activation_certificate_sha256",
    "old_minimum_quorum_intersection",
    "new_minimum_quorum_intersection",
    "old_continuity_witness_ids",
    "new_continuity_witness_ids",
    "cross_policy_handoff_witness_ids",
    "handoff_contract_sha256",
    "authorization_contract_sha256",
    "no_unprotected_acceptance_gap",
    "conditional_handoff_status",
    "conditional_non_equivocation_status",
    "global_non_equivocation_status",
}
_HANDOFF_PACKAGE_KEYS = {
    "schema",
    "old_active_quorum_package",
    "new_activation_quorum_package",
    "handoff_statement",
    "handoff_observations",
    "old_handoff_certificate",
    "new_handoff_certificate",
    "handoff_certificate",
}
_HANDOFF_EQUIVOCATION_EVIDENCE_KEYS = {
    "schema",
    "verified",
    "reason",
    "equivocation_detected",
    "authority_id",
    "producer_statement_sha256",
    "old_policy_sha256",
    "old_policy_epoch",
    "handoff_statement_a_sha256",
    "handoff_statement_b_sha256",
    "new_policy_a_sha256",
    "new_policy_b_sha256",
    "old_handoff_certificate_a_sha256",
    "old_handoff_certificate_b_sha256",
    "minimum_old_quorum_intersection",
    "double_signing_old_witness_ids",
    "double_signing_observation_a_sha256",
    "double_signing_observation_b_sha256",
    "conditional_non_equivocation_status",
    "global_non_equivocation_status",
}


@dataclass(frozen=True)
class WitnessPolicyHandoffDecision:
    """Result of independently verifying one dual-quorum policy handoff."""

    verified: bool
    reason: str
    handoff_certificate_sha256: Optional[str] = None
    old_policy_sha256: Optional[str] = None
    new_policy_sha256: Optional[str] = None
    old_active_certificate_sha256: Optional[str] = None
    new_activation_certificate_sha256: Optional[str] = None
    old_handoff_certificate_sha256: Optional[str] = None
    new_handoff_certificate_sha256: Optional[str] = None
    old_continuity_witness_ids: Tuple[str, ...] = ()
    new_continuity_witness_ids: Tuple[str, ...] = ()
    cross_policy_handoff_witness_ids: Tuple[str, ...] = ()
    old_minimum_quorum_intersection: int = 0
    new_minimum_quorum_intersection: int = 0
    no_unprotected_acceptance_gap: bool = False
    conditional_handoff_status: str = CONDITIONAL_HANDOFF_STATUS
    conditional_non_equivocation_status: str = CONDITIONAL_NON_EQUIVOCATION_STATUS
    global_non_equivocation_status: str = GLOBAL_NON_EQUIVOCATION_STATUS


@dataclass(frozen=True)
class WitnessPolicyHandoffEquivocationDecision:
    """Result of comparing two supplied handoffs from one old policy/view."""

    verified: bool
    reason: str
    equivocation_detected: bool = False
    double_signing_old_witness_ids: Tuple[str, ...] = ()
    evidence: Optional[Dict[str, Any]] = None
    conditional_non_equivocation_status: str = CONDITIONAL_NON_EQUIVOCATION_STATUS
    global_non_equivocation_status: str = GLOBAL_NON_EQUIVOCATION_STATUS


def _text(value: Any) -> bool:
    return isinstance(value, str) and bool(value)


def _positive_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value > 0


def _nonzero_sha256(value: Any) -> bool:
    return is_sha256(value) and value != ZERO_SHA256


def _same_bytes(a: Any, b: Any) -> bool:
    return digest_json(a) == digest_json(b)


def _package_context(package: Mapping[str, Any]) -> Tuple[Any, Any, Any, Any]:
    return (
        package["membership_anchor"],
        package["current_accumulator"],
        package["producer_statement"],
        package["witness_policy"],
    )


def _validate_policy_transition(old_policy: Any, new_policy: Any) -> bool:
    if not validate_lineage_witness_policy(old_policy):
        return False
    if not validate_lineage_witness_policy(new_policy):
        return False
    assert isinstance(old_policy, Mapping)
    assert isinstance(new_policy, Mapping)
    return (
        old_policy["policy_id"] == new_policy["policy_id"]
        and int(new_policy["policy_epoch"]) == int(old_policy["policy_epoch"]) + 1
        and digest_json(old_policy) != digest_json(new_policy)
    )


def build_witness_policy_handoff_statement(
    membership_anchor: Mapping[str, Any],
    current_accumulator: Mapping[str, Any],
    producer_statement: Mapping[str, Any],
    old_policy: Mapping[str, Any],
    new_policy: Mapping[str, Any],
    *,
    verified: bool,
    handoff_contract_sha256: str,
    authorization_contract_sha256: str,
    handoff_provenance_sha256: str,
) -> Dict[str, Any]:
    """Build one externally verified statement binding one exact policy rotation."""

    if not validate_lineage_anchor_statement(
        producer_statement, membership_anchor, current_accumulator
    ):
        raise ValueError("producer_statement_invalid")
    if not _validate_policy_transition(old_policy, new_policy):
        raise ValueError("witness_policy_transition_invalid")
    if verified is not True:
        raise ValueError("witness_policy_handoff_unverified")
    for name, value in (
        ("handoff_contract_sha256", handoff_contract_sha256),
        ("authorization_contract_sha256", authorization_contract_sha256),
        ("handoff_provenance_sha256", handoff_provenance_sha256),
    ):
        if not _nonzero_sha256(value):
            raise ValueError(f"{name}_invalid")
    statement = {
        "schema": LINEAGE_WITNESS_POLICY_HANDOFF_STATEMENT_SCHEMA,
        "verified": True,
        "authority_id": producer_statement["authority_id"],
        "trust_domain": producer_statement["trust_domain"],
        "logical_state_id": producer_statement["logical_state_id"],
        "tree_size": producer_statement["tree_size"],
        "anchor_sha256": producer_statement["anchor_sha256"],
        "membership_root_sha256": producer_statement["membership_root_sha256"],
        "producer_statement_sha256": digest_json(producer_statement),
        "policy_id": old_policy["policy_id"],
        "old_policy_sha256": digest_json(old_policy),
        "new_policy_sha256": digest_json(new_policy),
        "old_policy_epoch": old_policy["policy_epoch"],
        "new_policy_epoch": new_policy["policy_epoch"],
        "handoff_contract_sha256": handoff_contract_sha256,
        "authorization_contract_sha256": authorization_contract_sha256,
        "handoff_provenance_sha256": handoff_provenance_sha256,
    }
    if not validate_witness_policy_handoff_statement(
        statement,
        membership_anchor,
        current_accumulator,
        producer_statement,
        old_policy,
        new_policy,
    ):
        raise ValueError("witness_policy_handoff_statement_invalid")
    return statement


def validate_witness_policy_handoff_statement(
    statement: Any,
    membership_anchor: Any,
    current_accumulator: Any,
    producer_statement: Any,
    old_policy: Any,
    new_policy: Any,
) -> bool:
    """Validate the exact handoff statement and all view/policy bindings."""

    if (
        not isinstance(statement, Mapping)
        or set(statement) != _HANDOFF_STATEMENT_KEYS
        or not validate_lineage_anchor_statement(
            producer_statement, membership_anchor, current_accumulator
        )
        or not _validate_policy_transition(old_policy, new_policy)
    ):
        return False
    assert isinstance(producer_statement, Mapping)
    assert isinstance(old_policy, Mapping)
    assert isinstance(new_policy, Mapping)
    return (
        statement.get("schema")
        == LINEAGE_WITNESS_POLICY_HANDOFF_STATEMENT_SCHEMA
        and statement.get("verified") is True
        and statement.get("authority_id") == producer_statement["authority_id"]
        and statement.get("trust_domain") == producer_statement["trust_domain"]
        and statement.get("logical_state_id")
        == producer_statement["logical_state_id"]
        and statement.get("tree_size") == producer_statement["tree_size"]
        and statement.get("anchor_sha256") == producer_statement["anchor_sha256"]
        and statement.get("membership_root_sha256")
        == producer_statement["membership_root_sha256"]
        and statement.get("producer_statement_sha256")
        == digest_json(producer_statement)
        and statement.get("policy_id") == old_policy["policy_id"]
        and statement.get("old_policy_sha256") == digest_json(old_policy)
        and statement.get("new_policy_sha256") == digest_json(new_policy)
        and statement.get("old_policy_epoch") == old_policy["policy_epoch"]
        and statement.get("new_policy_epoch") == new_policy["policy_epoch"]
        and _nonzero_sha256(statement.get("handoff_contract_sha256"))
        and _nonzero_sha256(statement.get("authorization_contract_sha256"))
        and _nonzero_sha256(statement.get("handoff_provenance_sha256"))
    )


def build_witness_policy_handoff_observation(
    handoff_statement: Mapping[str, Any],
    old_policy: Mapping[str, Any],
    new_policy: Mapping[str, Any],
    *,
    verified: bool,
    witness_id: str,
    witness_sequence: int,
    previous_observation_sha256: str,
    observation_provenance_sha256: str,
) -> Dict[str, Any]:
    """Normalize one externally verified witness observation of the handoff."""

    if not _validate_policy_transition(old_policy, new_policy):
        raise ValueError("witness_policy_transition_invalid")
    if not isinstance(handoff_statement, Mapping):
        raise ValueError("witness_policy_handoff_statement_invalid")
    if verified is not True:
        raise ValueError("witness_policy_handoff_observation_unverified")
    authorized = set(old_policy["authorized_witness_ids"]) | set(
        new_policy["authorized_witness_ids"]
    )
    if witness_id not in authorized:
        raise ValueError("witness_policy_handoff_observation_unauthorized")
    if not _positive_int(witness_sequence):
        raise ValueError("witness_policy_handoff_observation_sequence_invalid")
    if witness_sequence == 1:
        if previous_observation_sha256 != ZERO_SHA256:
            raise ValueError("witness_policy_handoff_seed_predecessor_invalid")
    elif not _nonzero_sha256(previous_observation_sha256):
        raise ValueError("witness_policy_handoff_predecessor_invalid")
    if not _nonzero_sha256(observation_provenance_sha256):
        raise ValueError("witness_policy_handoff_observation_provenance_invalid")
    observation = {
        "schema": LINEAGE_WITNESS_POLICY_HANDOFF_OBSERVATION_SCHEMA,
        "verified": True,
        "witness_id": witness_id,
        "witness_sequence": witness_sequence,
        "previous_observation_sha256": previous_observation_sha256,
        "observation_provenance_sha256": observation_provenance_sha256,
        "handoff_statement_sha256": digest_json(handoff_statement),
        "producer_statement_sha256": handoff_statement[
            "producer_statement_sha256"
        ],
        "old_policy_sha256": digest_json(old_policy),
        "new_policy_sha256": digest_json(new_policy),
        "authority_id": handoff_statement["authority_id"],
        "trust_domain": handoff_statement["trust_domain"],
        "logical_state_id": handoff_statement["logical_state_id"],
        "tree_size": handoff_statement["tree_size"],
        "anchor_sha256": handoff_statement["anchor_sha256"],
        "membership_root_sha256": handoff_statement["membership_root_sha256"],
    }
    if not validate_witness_policy_handoff_observation(
        observation, handoff_statement, old_policy, new_policy
    ):
        raise ValueError("witness_policy_handoff_observation_invalid")
    return observation


def validate_witness_policy_handoff_observation(
    observation: Any,
    handoff_statement: Any,
    old_policy: Any,
    new_policy: Any,
) -> bool:
    """Validate exact observation shape and handoff/policy binding."""

    if (
        not isinstance(observation, Mapping)
        or set(observation) != _HANDOFF_OBSERVATION_KEYS
        or not isinstance(handoff_statement, Mapping)
        or not _validate_policy_transition(old_policy, new_policy)
    ):
        return False
    assert isinstance(old_policy, Mapping)
    assert isinstance(new_policy, Mapping)
    authorized = set(old_policy["authorized_witness_ids"]) | set(
        new_policy["authorized_witness_ids"]
    )
    sequence = observation.get("witness_sequence")
    previous = observation.get("previous_observation_sha256")
    return (
        observation.get("schema")
        == LINEAGE_WITNESS_POLICY_HANDOFF_OBSERVATION_SCHEMA
        and observation.get("verified") is True
        and observation.get("witness_id") in authorized
        and _positive_int(sequence)
        and (
            previous == ZERO_SHA256
            if sequence == 1
            else _nonzero_sha256(previous)
        )
        and _nonzero_sha256(observation.get("observation_provenance_sha256"))
        and observation.get("handoff_statement_sha256")
        == digest_json(handoff_statement)
        and observation.get("producer_statement_sha256")
        == handoff_statement.get("producer_statement_sha256")
        and observation.get("old_policy_sha256") == digest_json(old_policy)
        and observation.get("new_policy_sha256") == digest_json(new_policy)
        and observation.get("authority_id") == handoff_statement.get("authority_id")
        and observation.get("trust_domain")
        == handoff_statement.get("trust_domain")
        and observation.get("logical_state_id")
        == handoff_statement.get("logical_state_id")
        and observation.get("tree_size") == handoff_statement.get("tree_size")
        and observation.get("anchor_sha256")
        == handoff_statement.get("anchor_sha256")
        and observation.get("membership_root_sha256")
        == handoff_statement.get("membership_root_sha256")
    )


def _role_certificate(
    *,
    role: str,
    policy: Mapping[str, Any],
    handoff_statement: Mapping[str, Any],
    observations_by_id: Mapping[str, Mapping[str, Any]],
    selected_witness_ids: Sequence[str],
) -> Dict[str, Any]:
    """Build one role-specific quorum certificate from canonical observations."""

    if role not in {"old", "new"}:
        raise ValueError("witness_policy_handoff_role_invalid")
    witness_ids = sorted(selected_witness_ids)
    if not witness_ids or len(witness_ids) != len(set(witness_ids)):
        raise ValueError("witness_policy_handoff_witness_set_invalid")
    if len(witness_ids) < int(policy["threshold"]):
        raise ValueError(f"{role}_handoff_quorum_insufficient")
    if not set(witness_ids) <= set(policy["authorized_witness_ids"]):
        raise ValueError(f"{role}_handoff_witness_unauthorized")
    try:
        observations = [observations_by_id[item] for item in witness_ids]
    except KeyError as exc:
        raise ValueError("witness_policy_handoff_observation_missing") from exc
    return {
        "schema": LINEAGE_WITNESS_POLICY_HANDOFF_QUORUM_CERTIFICATE_SCHEMA,
        "verified": True,
        "role": role,
        "handoff_statement_sha256": digest_json(handoff_statement),
        "witness_policy_sha256": digest_json(policy),
        "threshold": policy["threshold"],
        "authorized_witness_count": len(policy["authorized_witness_ids"]),
        "minimum_quorum_intersection": minimum_quorum_intersection(policy),
        "witness_count": len(observations),
        "witness_ids": witness_ids,
        "handoff_observation_sha256": [digest_json(item) for item in observations],
    }


def _validate_role_certificate(
    certificate: Any,
    *,
    role: str,
    policy: Mapping[str, Any],
    handoff_statement: Mapping[str, Any],
    observations_by_id: Mapping[str, Mapping[str, Any]],
) -> bool:
    """Recompute one role certificate from its exact selected witness IDs."""

    if (
        not isinstance(certificate, Mapping)
        or set(certificate) != _ROLE_CERTIFICATE_KEYS
    ):
        return False
    witness_ids = certificate.get("witness_ids")
    if not isinstance(witness_ids, list):
        return False
    try:
        expected = _role_certificate(
            role=role,
            policy=policy,
            handoff_statement=handoff_statement,
            observations_by_id=observations_by_id,
            selected_witness_ids=witness_ids,
        )
    except ValueError:
        return False
    return dict(certificate) == expected


def _normal_observations_by_id(
    package: Mapping[str, Any],
) -> Dict[str, Mapping[str, Any]]:
    return {
        str(item["witness_id"]): item
        for item in package["witness_observations"]
    }


def _handoff_observations_by_id(
    observations: Sequence[Mapping[str, Any]],
) -> Dict[str, Mapping[str, Any]]:
    return {str(item["witness_id"]): item for item in observations}


def _validate_handoff_package_parts(
    *,
    old_active_package: Any,
    new_activation_package: Any,
    handoff_statement: Any,
    handoff_observations: Any,
    old_certificate: Any,
    new_certificate: Any,
) -> Tuple[bool, str, Dict[str, Any]]:
    """Validate all pre-receipt handoff objects and return derived continuity data."""

    old_decision = verify_lineage_witness_quorum_package(old_active_package)
    if not old_decision.verified:
        return False, old_decision.reason, {}
    new_decision = verify_lineage_witness_quorum_package(new_activation_package)
    if not new_decision.verified:
        return False, new_decision.reason, {}
    assert isinstance(old_active_package, Mapping)
    assert isinstance(new_activation_package, Mapping)
    old_anchor, old_accumulator, old_statement, old_policy = _package_context(
        old_active_package
    )
    new_anchor, new_accumulator, new_statement, new_policy = _package_context(
        new_activation_package
    )
    if not _validate_policy_transition(old_policy, new_policy):
        return False, "witness_policy_transition_invalid", {}
    if not (
        _same_bytes(old_anchor, new_anchor)
        and _same_bytes(old_accumulator, new_accumulator)
        and _same_bytes(old_statement, new_statement)
    ):
        return False, "witness_policy_handoff_view_mismatch", {}
    if not validate_witness_policy_handoff_statement(
        handoff_statement,
        old_anchor,
        old_accumulator,
        old_statement,
        old_policy,
        new_policy,
    ):
        return False, "witness_policy_handoff_statement_invalid", {}
    if not isinstance(handoff_observations, list) or not all(
        isinstance(item, Mapping) for item in handoff_observations
    ):
        return False, "witness_policy_handoff_observations_invalid", {}
    if handoff_observations != sorted(
        handoff_observations, key=lambda item: str(item.get("witness_id"))
    ):
        return False, "witness_policy_handoff_observation_order_invalid", {}
    witness_ids = [item.get("witness_id") for item in handoff_observations]
    if not all(_text(item) for item in witness_ids):
        return False, "witness_policy_handoff_observation_invalid", {}
    if len(witness_ids) != len(set(witness_ids)):
        return False, "witness_policy_handoff_observation_duplicate", {}
    if not all(
        validate_witness_policy_handoff_observation(
            item, handoff_statement, old_policy, new_policy
        )
        for item in handoff_observations
    ):
        return False, "witness_policy_handoff_observation_invalid", {}
    handoff_map = _handoff_observations_by_id(handoff_observations)
    if not _validate_role_certificate(
        old_certificate,
        role="old",
        policy=old_policy,
        handoff_statement=handoff_statement,
        observations_by_id=handoff_map,
    ):
        return False, "old_handoff_certificate_invalid", {}
    if not _validate_role_certificate(
        new_certificate,
        role="new",
        policy=new_policy,
        handoff_statement=handoff_statement,
        observations_by_id=handoff_map,
    ):
        return False, "new_handoff_certificate_invalid", {}
    assert isinstance(old_certificate, Mapping)
    assert isinstance(new_certificate, Mapping)
    covered_witness_ids = set(old_certificate["witness_ids"]) | set(
        new_certificate["witness_ids"]
    )
    if set(handoff_map) != covered_witness_ids:
        return False, "witness_policy_handoff_observation_coverage_invalid", {}
    old_active_map = _normal_observations_by_id(old_active_package)
    new_activation_map = _normal_observations_by_id(new_activation_package)
    old_overlap = tuple(
        sorted(set(old_active_map) & set(old_certificate["witness_ids"]))
    )
    new_overlap = tuple(
        sorted(set(new_activation_map) & set(new_certificate["witness_ids"]))
    )
    old_minimum = minimum_quorum_intersection(old_policy)
    new_minimum = minimum_quorum_intersection(new_policy)
    if len(old_overlap) < old_minimum:
        return False, "old_handoff_continuity_intersection_insufficient", {}
    if len(new_overlap) < new_minimum:
        return False, "new_handoff_continuity_intersection_insufficient", {}
    for witness_id in old_overlap:
        previous = old_active_map[witness_id]
        current = handoff_map[witness_id]
        if int(current["witness_sequence"]) != int(previous["witness_sequence"]) + 1:
            return False, "old_handoff_witness_sequence_discontinuity", {}
        if current["previous_observation_sha256"] != digest_json(previous):
            return False, "old_handoff_witness_predecessor_mismatch", {}
    for witness_id in new_overlap:
        previous = handoff_map[witness_id]
        current = new_activation_map[witness_id]
        if int(current["witness_sequence"]) != int(previous["witness_sequence"]) + 1:
            return False, "new_handoff_witness_sequence_discontinuity", {}
        if current["previous_observation_sha256"] != digest_json(previous):
            return False, "new_handoff_witness_predecessor_mismatch", {}
    return True, LINEAGE_WITNESS_POLICY_HANDOFF_REASON, {
        "old_decision": old_decision,
        "new_decision": new_decision,
        "old_policy": old_policy,
        "new_policy": new_policy,
        "old_statement": old_statement,
        "old_overlap": old_overlap,
        "new_overlap": new_overlap,
        "cross_policy_overlap": tuple(
            sorted(
                set(old_certificate["witness_ids"])
                & set(new_certificate["witness_ids"])
            )
        ),
        "old_minimum": old_minimum,
        "new_minimum": new_minimum,
    }


def _handoff_receipt(
    *,
    handoff_statement: Mapping[str, Any],
    old_certificate: Mapping[str, Any],
    new_certificate: Mapping[str, Any],
    derived: Mapping[str, Any],
) -> Dict[str, Any]:
    """Build the exact portable dual-quorum handoff receipt."""

    old_policy = derived["old_policy"]
    new_policy = derived["new_policy"]
    old_statement = derived["old_statement"]
    old_decision = derived["old_decision"]
    new_decision = derived["new_decision"]
    return {
        "schema": LINEAGE_WITNESS_POLICY_HANDOFF_CERTIFICATE_SCHEMA,
        "verified": True,
        "reason": LINEAGE_WITNESS_POLICY_HANDOFF_REASON,
        "handoff_statement_sha256": digest_json(handoff_statement),
        "producer_statement_sha256": digest_json(old_statement),
        "authority_id": old_statement["authority_id"],
        "trust_domain": old_statement["trust_domain"],
        "logical_state_id": old_statement["logical_state_id"],
        "tree_size": old_statement["tree_size"],
        "anchor_sha256": old_statement["anchor_sha256"],
        "membership_root_sha256": old_statement["membership_root_sha256"],
        "policy_id": old_policy["policy_id"],
        "old_policy_sha256": digest_json(old_policy),
        "new_policy_sha256": digest_json(new_policy),
        "old_policy_epoch": old_policy["policy_epoch"],
        "new_policy_epoch": new_policy["policy_epoch"],
        "old_active_certificate_sha256": old_decision.certificate_sha256,
        "old_handoff_certificate_sha256": digest_json(old_certificate),
        "new_handoff_certificate_sha256": digest_json(new_certificate),
        "new_activation_certificate_sha256": new_decision.certificate_sha256,
        "old_minimum_quorum_intersection": derived["old_minimum"],
        "new_minimum_quorum_intersection": derived["new_minimum"],
        "old_continuity_witness_ids": list(derived["old_overlap"]),
        "new_continuity_witness_ids": list(derived["new_overlap"]),
        "cross_policy_handoff_witness_ids": list(
            derived["cross_policy_overlap"]
        ),
        "handoff_contract_sha256": handoff_statement[
            "handoff_contract_sha256"
        ],
        "authorization_contract_sha256": handoff_statement[
            "authorization_contract_sha256"
        ],
        "no_unprotected_acceptance_gap": True,
        "conditional_handoff_status": CONDITIONAL_HANDOFF_STATUS,
        "conditional_non_equivocation_status": CONDITIONAL_NON_EQUIVOCATION_STATUS,
        "global_non_equivocation_status": GLOBAL_NON_EQUIVOCATION_STATUS,
    }


def build_witness_policy_handoff_package(
    old_active_quorum_package: Mapping[str, Any],
    new_activation_quorum_package: Mapping[str, Any],
    handoff_statement: Mapping[str, Any],
    handoff_observations: Sequence[Mapping[str, Any]],
    *,
    old_handoff_witness_ids: Sequence[str],
    new_handoff_witness_ids: Sequence[str],
) -> Dict[str, Any]:
    """Build one canonical dual-quorum policy handoff package."""

    observations = sorted(
        handoff_observations, key=lambda item: str(item.get("witness_id"))
    )
    observation_map = _handoff_observations_by_id(observations)
    old_policy = old_active_quorum_package["witness_policy"]
    new_policy = new_activation_quorum_package["witness_policy"]
    old_certificate = _role_certificate(
        role="old",
        policy=old_policy,
        handoff_statement=handoff_statement,
        observations_by_id=observation_map,
        selected_witness_ids=old_handoff_witness_ids,
    )
    new_certificate = _role_certificate(
        role="new",
        policy=new_policy,
        handoff_statement=handoff_statement,
        observations_by_id=observation_map,
        selected_witness_ids=new_handoff_witness_ids,
    )
    valid, reason, derived = _validate_handoff_package_parts(
        old_active_package=old_active_quorum_package,
        new_activation_package=new_activation_quorum_package,
        handoff_statement=handoff_statement,
        handoff_observations=observations,
        old_certificate=old_certificate,
        new_certificate=new_certificate,
    )
    if not valid:
        raise ValueError(reason)
    receipt = _handoff_receipt(
        handoff_statement=handoff_statement,
        old_certificate=old_certificate,
        new_certificate=new_certificate,
        derived=derived,
    )
    package = {
        "schema": LINEAGE_WITNESS_POLICY_HANDOFF_PACKAGE_SCHEMA,
        "old_active_quorum_package": dict(old_active_quorum_package),
        "new_activation_quorum_package": dict(new_activation_quorum_package),
        "handoff_statement": dict(handoff_statement),
        "handoff_observations": [dict(item) for item in observations],
        "old_handoff_certificate": old_certificate,
        "new_handoff_certificate": new_certificate,
        "handoff_certificate": receipt,
    }
    decision = verify_witness_policy_handoff_package(package)
    if not decision.verified:
        raise ValueError(decision.reason)
    return package


def verify_witness_policy_handoff_package(
    package: Any,
) -> WitnessPolicyHandoffDecision:
    """Independently validate a complete dual-quorum handoff package."""

    if not isinstance(package, Mapping) or set(package) != _HANDOFF_PACKAGE_KEYS:
        return WitnessPolicyHandoffDecision(
            False, "witness_policy_handoff_package_shape_invalid"
        )
    if package.get("schema") != LINEAGE_WITNESS_POLICY_HANDOFF_PACKAGE_SCHEMA:
        return WitnessPolicyHandoffDecision(
            False, "witness_policy_handoff_package_schema_invalid"
        )
    old_package = package.get("old_active_quorum_package")
    new_package = package.get("new_activation_quorum_package")
    statement = package.get("handoff_statement")
    observations = package.get("handoff_observations")
    old_certificate = package.get("old_handoff_certificate")
    new_certificate = package.get("new_handoff_certificate")
    receipt = package.get("handoff_certificate")
    valid, reason, derived = _validate_handoff_package_parts(
        old_active_package=old_package,
        new_activation_package=new_package,
        handoff_statement=statement,
        handoff_observations=observations,
        old_certificate=old_certificate,
        new_certificate=new_certificate,
    )
    if not valid:
        return WitnessPolicyHandoffDecision(False, reason)
    if not isinstance(receipt, Mapping) or set(receipt) != _HANDOFF_CERTIFICATE_KEYS:
        return WitnessPolicyHandoffDecision(
            False, "witness_policy_handoff_certificate_shape_invalid"
        )
    expected = _handoff_receipt(
        handoff_statement=statement,
        old_certificate=old_certificate,
        new_certificate=new_certificate,
        derived=derived,
    )
    if dict(receipt) != expected:
        return WitnessPolicyHandoffDecision(
            False, "witness_policy_handoff_certificate_mismatch"
        )
    return WitnessPolicyHandoffDecision(
        True,
        LINEAGE_WITNESS_POLICY_HANDOFF_REASON,
        handoff_certificate_sha256=digest_json(receipt),
        old_policy_sha256=receipt["old_policy_sha256"],
        new_policy_sha256=receipt["new_policy_sha256"],
        old_active_certificate_sha256=receipt["old_active_certificate_sha256"],
        new_activation_certificate_sha256=receipt[
            "new_activation_certificate_sha256"
        ],
        old_handoff_certificate_sha256=receipt[
            "old_handoff_certificate_sha256"
        ],
        new_handoff_certificate_sha256=receipt[
            "new_handoff_certificate_sha256"
        ],
        old_continuity_witness_ids=tuple(
            receipt["old_continuity_witness_ids"]
        ),
        new_continuity_witness_ids=tuple(
            receipt["new_continuity_witness_ids"]
        ),
        cross_policy_handoff_witness_ids=tuple(
            receipt["cross_policy_handoff_witness_ids"]
        ),
        old_minimum_quorum_intersection=receipt[
            "old_minimum_quorum_intersection"
        ],
        new_minimum_quorum_intersection=receipt[
            "new_minimum_quorum_intersection"
        ],
        no_unprotected_acceptance_gap=True,
    )


def detect_witness_policy_handoff_equivocation(
    package_a: Any,
    package_b: Any,
) -> WitnessPolicyHandoffEquivocationDecision:
    """Detect conflicting rotations from one old policy and accepted lineage view."""

    decision_a = verify_witness_policy_handoff_package(package_a)
    if not decision_a.verified:
        return WitnessPolicyHandoffEquivocationDecision(False, decision_a.reason)
    decision_b = verify_witness_policy_handoff_package(package_b)
    if not decision_b.verified:
        return WitnessPolicyHandoffEquivocationDecision(False, decision_b.reason)
    assert isinstance(package_a, Mapping)
    assert isinstance(package_b, Mapping)
    statement_a = package_a["handoff_statement"]
    statement_b = package_b["handoff_statement"]
    old_policy_a = package_a["old_active_quorum_package"]["witness_policy"]
    old_policy_b = package_b["old_active_quorum_package"]["witness_policy"]
    producer_a = package_a["old_active_quorum_package"]["producer_statement"]
    producer_b = package_b["old_active_quorum_package"]["producer_statement"]
    if digest_json(old_policy_a) != digest_json(old_policy_b):
        return WitnessPolicyHandoffEquivocationDecision(
            False, "old_witness_policy_context_mismatch"
        )
    if digest_json(producer_a) != digest_json(producer_b):
        return WitnessPolicyHandoffEquivocationDecision(
            False, "handoff_producer_statement_context_mismatch"
        )
    semantic_a = (
        statement_a["new_policy_sha256"],
        statement_a["handoff_contract_sha256"],
        statement_a["authorization_contract_sha256"],
    )
    semantic_b = (
        statement_b["new_policy_sha256"],
        statement_b["handoff_contract_sha256"],
        statement_b["authorization_contract_sha256"],
    )
    if semantic_a == semantic_b:
        return WitnessPolicyHandoffEquivocationDecision(
            True, LINEAGE_WITNESS_POLICY_HANDOFF_EQUIVOCATION_NOT_PROVEN_REASON
        )
    old_certificate_a = package_a["old_handoff_certificate"]
    old_certificate_b = package_b["old_handoff_certificate"]
    overlap = tuple(
        sorted(
            set(old_certificate_a["witness_ids"])
            & set(old_certificate_b["witness_ids"])
        )
    )
    minimum = minimum_quorum_intersection(old_policy_a)
    if len(overlap) < minimum:
        return WitnessPolicyHandoffEquivocationDecision(
            False, "old_handoff_quorum_intersection_insufficient"
        )
    observations_a = _handoff_observations_by_id(
        package_a["handoff_observations"]
    )
    observations_b = _handoff_observations_by_id(
        package_b["handoff_observations"]
    )
    evidence = {
        "schema": LINEAGE_WITNESS_POLICY_HANDOFF_EQUIVOCATION_EVIDENCE_SCHEMA,
        "verified": True,
        "reason": LINEAGE_WITNESS_POLICY_HANDOFF_EQUIVOCATION_DETECTED_REASON,
        "equivocation_detected": True,
        "authority_id": statement_a["authority_id"],
        "producer_statement_sha256": statement_a["producer_statement_sha256"],
        "old_policy_sha256": statement_a["old_policy_sha256"],
        "old_policy_epoch": statement_a["old_policy_epoch"],
        "handoff_statement_a_sha256": digest_json(statement_a),
        "handoff_statement_b_sha256": digest_json(statement_b),
        "new_policy_a_sha256": statement_a["new_policy_sha256"],
        "new_policy_b_sha256": statement_b["new_policy_sha256"],
        "old_handoff_certificate_a_sha256": digest_json(old_certificate_a),
        "old_handoff_certificate_b_sha256": digest_json(old_certificate_b),
        "minimum_old_quorum_intersection": minimum,
        "double_signing_old_witness_ids": list(overlap),
        "double_signing_observation_a_sha256": [
            digest_json(observations_a[item]) for item in overlap
        ],
        "double_signing_observation_b_sha256": [
            digest_json(observations_b[item]) for item in overlap
        ],
        "conditional_non_equivocation_status": CONDITIONAL_NON_EQUIVOCATION_STATUS,
        "global_non_equivocation_status": GLOBAL_NON_EQUIVOCATION_STATUS,
    }
    if set(evidence) != _HANDOFF_EQUIVOCATION_EVIDENCE_KEYS:
        return WitnessPolicyHandoffEquivocationDecision(
            False, "witness_policy_handoff_equivocation_evidence_shape_invalid"
        )
    return WitnessPolicyHandoffEquivocationDecision(
        True,
        LINEAGE_WITNESS_POLICY_HANDOFF_EQUIVOCATION_DETECTED_REASON,
        equivocation_detected=True,
        double_signing_old_witness_ids=overlap,
        evidence=evidence,
    )
