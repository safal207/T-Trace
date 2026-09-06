"""Witness-quorum anchoring for conditional lineage anti-equivocation.

This profile sits above structural membership-root consistency. It does not alter
membership roots or portable causal identity. Instead, it normalizes externally
verified witness observations, builds exact quorum certificates, verifies direct
certificate continuity, and emits attributable evidence when overlapping witnesses
co-sign conflicting producer statements.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Mapping, Optional, Sequence, Tuple

from .lineage_compaction import ZERO_SHA256
from .lineage_consistency import (
    GLOBAL_NON_EQUIVOCATION_STATUS,
    detect_lineage_anchor_equivocation,
    validate_lineage_anchor_statement,
    verify_authorized_lineage_root_consistency,
)
from .portable_causality import digest_json, is_sha256

LINEAGE_WITNESS_POLICY_SCHEMA = "ttrace-lineage-witness-policy/v0.1"
LINEAGE_WITNESS_OBSERVATION_SCHEMA = "ttrace-lineage-witness-observation/v0.1"
LINEAGE_WITNESS_QUORUM_CERTIFICATE_SCHEMA = (
    "ttrace-lineage-witness-quorum-certificate/v0.1"
)
LINEAGE_WITNESS_QUORUM_PACKAGE_SCHEMA = "ttrace-lineage-witness-quorum-package/v0.1"
LINEAGE_WITNESS_EQUIVOCATION_EVIDENCE_SCHEMA = (
    "ttrace-lineage-witness-equivocation-evidence/v0.1"
)
LINEAGE_WITNESS_QUORUM_REASON = "lineage_witness_quorum_verified"
LINEAGE_WITNESSED_CONSISTENCY_REASON = (
    "lineage_witnessed_root_consistency_verified"
)
LINEAGE_WITNESS_EQUIVOCATION_DETECTED_REASON = (
    "lineage_witness_equivocation_detected"
)
LINEAGE_WITNESS_EQUIVOCATION_NOT_PROVEN_REASON = (
    "lineage_witness_equivocation_not_proven"
)
CONDITIONAL_NON_EQUIVOCATION_STATUS = (
    "supported-under-witness-quorum-assumptions"
)

_POLICY_KEYS = {
    "schema",
    "policy_id",
    "policy_epoch",
    "authorized_witness_ids",
    "threshold",
    "witness_contract_sha256",
    "authorization_contract_sha256",
}
_OBSERVATION_KEYS = {
    "schema",
    "verified",
    "witness_id",
    "witness_sequence",
    "previous_observation_sha256",
    "observation_provenance_sha256",
    "witness_policy_sha256",
    "producer_statement_sha256",
    "authority_id",
    "trust_domain",
    "logical_state_id",
    "tree_size",
    "anchor_sha256",
    "membership_root_sha256",
    "tree_algorithm",
    "membership_contract_sha256",
    "authorization_contract_sha256",
}
_CERTIFICATE_KEYS = {
    "schema",
    "verified",
    "witness_policy_sha256",
    "producer_statement_sha256",
    "authority_id",
    "statement_sequence",
    "trust_domain",
    "logical_state_id",
    "tree_size",
    "anchor_sha256",
    "membership_root_sha256",
    "tree_algorithm",
    "membership_contract_sha256",
    "authorization_contract_sha256",
    "threshold",
    "authorized_witness_count",
    "minimum_quorum_intersection",
    "witness_count",
    "witness_ids",
    "witness_observation_sha256",
}
_PACKAGE_KEYS = {
    "schema",
    "membership_anchor",
    "current_accumulator",
    "producer_statement",
    "witness_policy",
    "witness_observations",
    "quorum_certificate",
}
_EQUIVOCATION_EVIDENCE_KEYS = {
    "schema",
    "verified",
    "reason",
    "equivocation_detected",
    "producer_authority_id",
    "witness_policy_sha256",
    "threshold",
    "authorized_witness_count",
    "minimum_quorum_intersection",
    "certificate_a_sha256",
    "certificate_b_sha256",
    "producer_statement_a_sha256",
    "producer_statement_b_sha256",
    "producer_equivocation_evidence_sha256",
    "double_signing_witness_ids",
    "double_signing_observation_a_sha256",
    "double_signing_observation_b_sha256",
    "conditional_non_equivocation_status",
    "global_non_equivocation_status",
}


@dataclass(frozen=True)
class WitnessQuorumDecision:
    """Result of independently validating one witness-quorum package."""

    verified: bool
    reason: str
    certificate_sha256: Optional[str] = None
    producer_statement_sha256: Optional[str] = None
    witness_ids: Tuple[str, ...] = ()
    witness_count: int = 0
    threshold: int = 0
    minimum_quorum_intersection: int = 0
    conditional_non_equivocation_status: str = CONDITIONAL_NON_EQUIVOCATION_STATUS
    global_non_equivocation_status: str = GLOBAL_NON_EQUIVOCATION_STATUS


@dataclass(frozen=True)
class WitnessedLineageConsistencyDecision:
    """Result of append-only root verification plus witness-quorum continuity."""

    verified: bool
    reason: str
    authority_id: Optional[str] = None
    witness_policy_sha256: Optional[str] = None
    old_certificate_sha256: Optional[str] = None
    new_certificate_sha256: Optional[str] = None
    overlapping_witness_ids: Tuple[str, ...] = ()
    minimum_quorum_intersection: int = 0
    append_only_consistent: bool = False
    authority_chain_continuous: bool = False
    witness_chains_continuous: bool = False
    conditional_non_equivocation_status: str = CONDITIONAL_NON_EQUIVOCATION_STATUS
    global_non_equivocation_status: str = GLOBAL_NON_EQUIVOCATION_STATUS


@dataclass(frozen=True)
class WitnessQuorumEquivocationDecision:
    """Result of comparing two witnessed views for attributable split-view evidence."""

    verified: bool
    reason: str
    equivocation_detected: bool = False
    double_signing_witness_ids: Tuple[str, ...] = ()
    evidence: Optional[Dict[str, Any]] = None
    conditional_non_equivocation_status: str = CONDITIONAL_NON_EQUIVOCATION_STATUS
    global_non_equivocation_status: str = GLOBAL_NON_EQUIVOCATION_STATUS


def _text(value: Any) -> bool:
    """Return true only for a non-empty string."""

    return isinstance(value, str) and bool(value)


def _positive_int(value: Any) -> bool:
    """Apply strict JSON integer semantics and reject Python booleans."""

    return isinstance(value, int) and not isinstance(value, bool) and value > 0


def _nonzero_sha256(value: Any) -> bool:
    """Return true for a lowercase SHA-256 digest other than the zero sentinel."""

    return is_sha256(value) and value != ZERO_SHA256


def build_lineage_witness_policy(
    *,
    policy_id: str,
    policy_epoch: int,
    authorized_witness_ids: Sequence[str],
    threshold: int,
    witness_contract_sha256: str,
    authorization_contract_sha256: str,
) -> Dict[str, Any]:
    """Build an exact threshold policy whose quorums necessarily intersect."""

    policy = {
        "schema": LINEAGE_WITNESS_POLICY_SCHEMA,
        "policy_id": policy_id,
        "policy_epoch": policy_epoch,
        "authorized_witness_ids": sorted(authorized_witness_ids),
        "threshold": threshold,
        "witness_contract_sha256": witness_contract_sha256,
        "authorization_contract_sha256": authorization_contract_sha256,
    }
    if not validate_lineage_witness_policy(policy):
        raise ValueError("lineage_witness_policy_invalid")
    return policy


def validate_lineage_witness_policy(value: Any) -> bool:
    """Validate policy shape, authorized set, threshold, and intersection property."""

    if not isinstance(value, Mapping) or set(value) != _POLICY_KEYS:
        return False
    witnesses = value.get("authorized_witness_ids")
    threshold = value.get("threshold")
    if not isinstance(witnesses, list) or not witnesses:
        return False
    if witnesses != sorted(witnesses):
        return False
    if not all(_text(item) for item in witnesses):
        return False
    if len(witnesses) != len(set(witnesses)):
        return False
    return (
        value.get("schema") == LINEAGE_WITNESS_POLICY_SCHEMA
        and _text(value.get("policy_id"))
        and _positive_int(value.get("policy_epoch"))
        and _positive_int(threshold)
        and threshold <= len(witnesses)
        and 2 * threshold > len(witnesses)
        and _nonzero_sha256(value.get("witness_contract_sha256"))
        and _nonzero_sha256(value.get("authorization_contract_sha256"))
    )


def minimum_quorum_intersection(policy: Mapping[str, Any]) -> int:
    """Return the guaranteed intersection size for any two valid policy quorums."""

    if not validate_lineage_witness_policy(policy):
        raise ValueError("lineage_witness_policy_invalid")
    return 2 * int(policy["threshold"]) - len(policy["authorized_witness_ids"])


def build_lineage_witness_observation(
    membership_anchor: Mapping[str, Any],
    current_accumulator: Mapping[str, Any],
    producer_statement: Mapping[str, Any],
    witness_policy: Mapping[str, Any],
    *,
    verified: bool,
    witness_id: str,
    witness_sequence: int,
    previous_observation_sha256: str,
    observation_provenance_sha256: str,
) -> Dict[str, Any]:
    """Normalize one externally verified witness observation of an anchor statement."""

    if not validate_lineage_witness_policy(witness_policy):
        raise ValueError("lineage_witness_policy_invalid")
    if not validate_lineage_anchor_statement(
        producer_statement, membership_anchor, current_accumulator
    ):
        raise ValueError("producer_statement_invalid")
    if verified is not True:
        raise ValueError("witness_observation_unverified")
    if witness_id not in witness_policy["authorized_witness_ids"]:
        raise ValueError("witness_observation_unauthorized")
    if not _positive_int(witness_sequence):
        raise ValueError("witness_observation_sequence_invalid")
    if witness_sequence == 1:
        if previous_observation_sha256 != ZERO_SHA256:
            raise ValueError("witness_observation_seed_predecessor_invalid")
    elif not _nonzero_sha256(previous_observation_sha256):
        raise ValueError("witness_observation_predecessor_invalid")
    if not _nonzero_sha256(observation_provenance_sha256):
        raise ValueError("witness_observation_provenance_invalid")

    observation = {
        "schema": LINEAGE_WITNESS_OBSERVATION_SCHEMA,
        "verified": True,
        "witness_id": witness_id,
        "witness_sequence": witness_sequence,
        "previous_observation_sha256": previous_observation_sha256,
        "observation_provenance_sha256": observation_provenance_sha256,
        "witness_policy_sha256": digest_json(witness_policy),
        "producer_statement_sha256": digest_json(producer_statement),
        "authority_id": producer_statement["authority_id"],
        "trust_domain": producer_statement["trust_domain"],
        "logical_state_id": producer_statement["logical_state_id"],
        "tree_size": producer_statement["tree_size"],
        "anchor_sha256": producer_statement["anchor_sha256"],
        "membership_root_sha256": producer_statement["membership_root_sha256"],
        "tree_algorithm": producer_statement["tree_algorithm"],
        "membership_contract_sha256": producer_statement[
            "membership_contract_sha256"
        ],
        "authorization_contract_sha256": producer_statement[
            "authorization_contract_sha256"
        ],
    }
    if not validate_lineage_witness_observation(
        observation,
        membership_anchor,
        current_accumulator,
        producer_statement,
        witness_policy,
    ):
        raise ValueError("witness_observation_invalid")
    return observation


def validate_lineage_witness_observation(
    observation: Any,
    membership_anchor: Any,
    current_accumulator: Any,
    producer_statement: Any,
    witness_policy: Any,
) -> bool:
    """Validate exact observation shape and every statement/policy binding."""

    if (
        not isinstance(observation, Mapping)
        or set(observation) != _OBSERVATION_KEYS
        or not validate_lineage_witness_policy(witness_policy)
        or not validate_lineage_anchor_statement(
            producer_statement, membership_anchor, current_accumulator
        )
    ):
        return False
    assert isinstance(producer_statement, Mapping)
    assert isinstance(witness_policy, Mapping)
    sequence = observation.get("witness_sequence")
    previous = observation.get("previous_observation_sha256")
    return (
        observation.get("schema") == LINEAGE_WITNESS_OBSERVATION_SCHEMA
        and observation.get("verified") is True
        and observation.get("witness_id")
        in witness_policy["authorized_witness_ids"]
        and _positive_int(sequence)
        and (
            previous == ZERO_SHA256
            if sequence == 1
            else _nonzero_sha256(previous)
        )
        and _nonzero_sha256(observation.get("observation_provenance_sha256"))
        and observation.get("witness_policy_sha256") == digest_json(witness_policy)
        and observation.get("producer_statement_sha256")
        == digest_json(producer_statement)
        and observation.get("authority_id") == producer_statement.get("authority_id")
        and observation.get("trust_domain")
        == producer_statement.get("trust_domain")
        and observation.get("logical_state_id")
        == producer_statement.get("logical_state_id")
        and observation.get("tree_size") == producer_statement.get("tree_size")
        and observation.get("anchor_sha256")
        == producer_statement.get("anchor_sha256")
        and observation.get("membership_root_sha256")
        == producer_statement.get("membership_root_sha256")
        and observation.get("tree_algorithm")
        == producer_statement.get("tree_algorithm")
        and observation.get("membership_contract_sha256")
        == producer_statement.get("membership_contract_sha256")
        and observation.get("authorization_contract_sha256")
        == producer_statement.get("authorization_contract_sha256")
    )


def _certificate_for(
    producer_statement: Mapping[str, Any],
    witness_policy: Mapping[str, Any],
    observations: Sequence[Mapping[str, Any]],
) -> Dict[str, Any]:
    """Construct the exact portable certificate from sorted valid observations."""

    witness_ids = [str(item["witness_id"]) for item in observations]
    return {
        "schema": LINEAGE_WITNESS_QUORUM_CERTIFICATE_SCHEMA,
        "verified": True,
        "witness_policy_sha256": digest_json(witness_policy),
        "producer_statement_sha256": digest_json(producer_statement),
        "authority_id": producer_statement["authority_id"],
        "statement_sequence": producer_statement["statement_sequence"],
        "trust_domain": producer_statement["trust_domain"],
        "logical_state_id": producer_statement["logical_state_id"],
        "tree_size": producer_statement["tree_size"],
        "anchor_sha256": producer_statement["anchor_sha256"],
        "membership_root_sha256": producer_statement["membership_root_sha256"],
        "tree_algorithm": producer_statement["tree_algorithm"],
        "membership_contract_sha256": producer_statement[
            "membership_contract_sha256"
        ],
        "authorization_contract_sha256": producer_statement[
            "authorization_contract_sha256"
        ],
        "threshold": witness_policy["threshold"],
        "authorized_witness_count": len(witness_policy["authorized_witness_ids"]),
        "minimum_quorum_intersection": minimum_quorum_intersection(witness_policy),
        "witness_count": len(observations),
        "witness_ids": witness_ids,
        "witness_observation_sha256": [digest_json(item) for item in observations],
    }


def build_lineage_witness_quorum_package(
    membership_anchor: Mapping[str, Any],
    current_accumulator: Mapping[str, Any],
    producer_statement: Mapping[str, Any],
    witness_policy: Mapping[str, Any],
    witness_observations: Sequence[Mapping[str, Any]],
) -> Dict[str, Any]:
    """Build a canonical quorum package over one verified producer statement."""

    if not validate_lineage_witness_policy(witness_policy):
        raise ValueError("lineage_witness_policy_invalid")
    if not validate_lineage_anchor_statement(
        producer_statement, membership_anchor, current_accumulator
    ):
        raise ValueError("producer_statement_invalid")
    if not all(isinstance(item, Mapping) for item in witness_observations):
        raise ValueError("witness_observation_invalid")
    observations = sorted(
        witness_observations, key=lambda item: str(item.get("witness_id"))
    )
    witness_ids = [item.get("witness_id") for item in observations]
    if not all(_text(item) for item in witness_ids):
        raise ValueError("witness_observation_invalid")
    if len(witness_ids) != len(set(witness_ids)):
        raise ValueError("witness_observation_duplicate")
    if len(observations) < int(witness_policy["threshold"]):
        raise ValueError("witness_quorum_insufficient")
    if not all(
        validate_lineage_witness_observation(
            item,
            membership_anchor,
            current_accumulator,
            producer_statement,
            witness_policy,
        )
        for item in observations
    ):
        raise ValueError("witness_observation_invalid")

    certificate = _certificate_for(producer_statement, witness_policy, observations)
    package = {
        "schema": LINEAGE_WITNESS_QUORUM_PACKAGE_SCHEMA,
        "membership_anchor": dict(membership_anchor),
        "current_accumulator": dict(current_accumulator),
        "producer_statement": dict(producer_statement),
        "witness_policy": dict(witness_policy),
        "witness_observations": [dict(item) for item in observations],
        "quorum_certificate": certificate,
    }
    decision = verify_lineage_witness_quorum_package(package)
    if not decision.verified:
        raise ValueError(decision.reason)
    return package


def verify_lineage_witness_quorum_package(package: Any) -> WitnessQuorumDecision:
    """Independently validate a package and recompute its quorum certificate."""

    if not isinstance(package, Mapping) or set(package) != _PACKAGE_KEYS:
        return WitnessQuorumDecision(False, "witness_quorum_package_shape_invalid")
    if package.get("schema") != LINEAGE_WITNESS_QUORUM_PACKAGE_SCHEMA:
        return WitnessQuorumDecision(False, "witness_quorum_package_schema_invalid")
    anchor = package.get("membership_anchor")
    accumulator = package.get("current_accumulator")
    statement = package.get("producer_statement")
    policy = package.get("witness_policy")
    observations = package.get("witness_observations")
    certificate = package.get("quorum_certificate")
    if not validate_lineage_witness_policy(policy):
        return WitnessQuorumDecision(False, "lineage_witness_policy_invalid")
    if not validate_lineage_anchor_statement(statement, anchor, accumulator):
        return WitnessQuorumDecision(False, "producer_statement_invalid")
    if not isinstance(observations, list) or not all(
        isinstance(item, Mapping) for item in observations
    ):
        return WitnessQuorumDecision(False, "witness_observations_invalid")
    if observations != sorted(
        observations, key=lambda item: str(item.get("witness_id"))
    ):
        return WitnessQuorumDecision(False, "witness_observation_order_invalid")
    witness_ids = [item.get("witness_id") for item in observations]
    if not all(_text(item) for item in witness_ids):
        return WitnessQuorumDecision(False, "witness_observation_invalid")
    if len(witness_ids) != len(set(witness_ids)):
        return WitnessQuorumDecision(False, "witness_observation_duplicate")
    assert isinstance(policy, Mapping)
    if len(observations) < int(policy["threshold"]):
        return WitnessQuorumDecision(False, "witness_quorum_insufficient")
    if not all(
        validate_lineage_witness_observation(
            item, anchor, accumulator, statement, policy
        )
        for item in observations
    ):
        return WitnessQuorumDecision(False, "witness_observation_invalid")
    if not isinstance(certificate, Mapping) or set(certificate) != _CERTIFICATE_KEYS:
        return WitnessQuorumDecision(False, "witness_quorum_certificate_shape_invalid")
    expected = _certificate_for(statement, policy, observations)
    if dict(certificate) != expected:
        return WitnessQuorumDecision(False, "witness_quorum_certificate_mismatch")
    return WitnessQuorumDecision(
        True,
        LINEAGE_WITNESS_QUORUM_REASON,
        certificate_sha256=digest_json(certificate),
        producer_statement_sha256=digest_json(statement),
        witness_ids=tuple(str(item) for item in witness_ids),
        witness_count=len(observations),
        threshold=int(policy["threshold"]),
        minimum_quorum_intersection=minimum_quorum_intersection(policy),
    )


def _observations_by_witness(package: Mapping[str, Any]) -> Dict[str, Mapping[str, Any]]:
    """Index an already validated package by witness identifier."""

    return {
        str(item["witness_id"]): item
        for item in package["witness_observations"]
    }


def verify_witnessed_lineage_root_consistency(
    consistency_package: Any,
    old_quorum_package: Any,
    new_quorum_package: Any,
) -> WitnessedLineageConsistencyDecision:
    """Verify root extension, producer continuity, and intersecting witness chains."""

    old_decision = verify_lineage_witness_quorum_package(old_quorum_package)
    if not old_decision.verified:
        return WitnessedLineageConsistencyDecision(False, old_decision.reason)
    new_decision = verify_lineage_witness_quorum_package(new_quorum_package)
    if not new_decision.verified:
        return WitnessedLineageConsistencyDecision(False, new_decision.reason)
    assert isinstance(old_quorum_package, Mapping)
    assert isinstance(new_quorum_package, Mapping)
    old_statement = old_quorum_package["producer_statement"]
    new_statement = new_quorum_package["producer_statement"]
    authorized = verify_authorized_lineage_root_consistency(
        consistency_package, old_statement, new_statement
    )
    if not authorized.verified:
        return WitnessedLineageConsistencyDecision(False, authorized.reason)
    old_policy = old_quorum_package["witness_policy"]
    new_policy = new_quorum_package["witness_policy"]
    if digest_json(old_policy) != digest_json(new_policy):
        return WitnessedLineageConsistencyDecision(False, "witness_policy_drift")
    old_map = _observations_by_witness(old_quorum_package)
    new_map = _observations_by_witness(new_quorum_package)
    overlap = tuple(sorted(set(old_map) & set(new_map)))
    assert isinstance(old_policy, Mapping)
    minimum = minimum_quorum_intersection(old_policy)
    if len(overlap) < minimum:
        return WitnessedLineageConsistencyDecision(
            False, "witness_quorum_intersection_insufficient"
        )
    for witness_id in overlap:
        old_observation = old_map[witness_id]
        new_observation = new_map[witness_id]
        if int(new_observation["witness_sequence"]) != int(
            old_observation["witness_sequence"]
        ) + 1:
            return WitnessedLineageConsistencyDecision(
                False, "witness_observation_sequence_discontinuity"
            )
        if new_observation["previous_observation_sha256"] != digest_json(
            old_observation
        ):
            return WitnessedLineageConsistencyDecision(
                False, "witness_observation_predecessor_mismatch"
            )
    return WitnessedLineageConsistencyDecision(
        True,
        LINEAGE_WITNESSED_CONSISTENCY_REASON,
        authority_id=str(old_statement["authority_id"]),
        witness_policy_sha256=digest_json(old_policy),
        old_certificate_sha256=old_decision.certificate_sha256,
        new_certificate_sha256=new_decision.certificate_sha256,
        overlapping_witness_ids=overlap,
        minimum_quorum_intersection=minimum,
        append_only_consistent=True,
        authority_chain_continuous=True,
        witness_chains_continuous=True,
    )


def detect_witness_quorum_equivocation(
    package_a: Any,
    package_b: Any,
) -> WitnessQuorumEquivocationDecision:
    """Detect a supplied split view and identify overlapping double-signing witnesses."""

    decision_a = verify_lineage_witness_quorum_package(package_a)
    if not decision_a.verified:
        return WitnessQuorumEquivocationDecision(False, decision_a.reason)
    decision_b = verify_lineage_witness_quorum_package(package_b)
    if not decision_b.verified:
        return WitnessQuorumEquivocationDecision(False, decision_b.reason)
    assert isinstance(package_a, Mapping)
    assert isinstance(package_b, Mapping)
    policy_a = package_a["witness_policy"]
    policy_b = package_b["witness_policy"]
    if digest_json(policy_a) != digest_json(policy_b):
        return WitnessQuorumEquivocationDecision(False, "witness_policy_context_mismatch")

    producer = detect_lineage_anchor_equivocation(
        package_a["membership_anchor"],
        package_a["current_accumulator"],
        package_a["producer_statement"],
        package_b["membership_anchor"],
        package_b["current_accumulator"],
        package_b["producer_statement"],
    )
    if not producer.verified:
        return WitnessQuorumEquivocationDecision(False, producer.reason)
    if not producer.equivocation_detected:
        return WitnessQuorumEquivocationDecision(
            True, LINEAGE_WITNESS_EQUIVOCATION_NOT_PROVEN_REASON
        )

    observations_a = _observations_by_witness(package_a)
    observations_b = _observations_by_witness(package_b)
    overlap = tuple(sorted(set(observations_a) & set(observations_b)))
    assert isinstance(policy_a, Mapping)
    minimum = minimum_quorum_intersection(policy_a)
    if len(overlap) < minimum:
        return WitnessQuorumEquivocationDecision(
            False, "witness_quorum_intersection_insufficient"
        )
    certificate_a = package_a["quorum_certificate"]
    certificate_b = package_b["quorum_certificate"]
    producer_evidence = producer.evidence
    if not isinstance(producer_evidence, Mapping):
        return WitnessQuorumEquivocationDecision(
            False, "producer_equivocation_evidence_missing"
        )
    evidence = {
        "schema": LINEAGE_WITNESS_EQUIVOCATION_EVIDENCE_SCHEMA,
        "verified": True,
        "reason": LINEAGE_WITNESS_EQUIVOCATION_DETECTED_REASON,
        "equivocation_detected": True,
        "producer_authority_id": package_a["producer_statement"]["authority_id"],
        "witness_policy_sha256": digest_json(policy_a),
        "threshold": policy_a["threshold"],
        "authorized_witness_count": len(policy_a["authorized_witness_ids"]),
        "minimum_quorum_intersection": minimum,
        "certificate_a_sha256": digest_json(certificate_a),
        "certificate_b_sha256": digest_json(certificate_b),
        "producer_statement_a_sha256": digest_json(
            package_a["producer_statement"]
        ),
        "producer_statement_b_sha256": digest_json(
            package_b["producer_statement"]
        ),
        "producer_equivocation_evidence_sha256": digest_json(producer_evidence),
        "double_signing_witness_ids": list(overlap),
        "double_signing_observation_a_sha256": [
            digest_json(observations_a[item]) for item in overlap
        ],
        "double_signing_observation_b_sha256": [
            digest_json(observations_b[item]) for item in overlap
        ],
        "conditional_non_equivocation_status": CONDITIONAL_NON_EQUIVOCATION_STATUS,
        "global_non_equivocation_status": GLOBAL_NON_EQUIVOCATION_STATUS,
    }
    if set(evidence) != _EQUIVOCATION_EVIDENCE_KEYS:
        return WitnessQuorumEquivocationDecision(
            False, "witness_equivocation_evidence_shape_invalid"
        )
    return WitnessQuorumEquivocationDecision(
        True,
        LINEAGE_WITNESS_EQUIVOCATION_DETECTED_REASON,
        equivocation_detected=True,
        double_signing_witness_ids=overlap,
        evidence=evidence,
    )
