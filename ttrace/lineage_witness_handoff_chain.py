"""Fixed-shape continuity for repeated witness-policy handoffs.

A single handoff proves one old-policy -> new-policy transfer.  This profile keeps
that verifier unchanged and adds a rolling chain reference so a relying party that
pins the previous tip can reject rollback, skipped epochs, truncated history, and
parallel successors.  Complete handoff packages remain external evidence.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Mapping, Optional, Sequence, Tuple

from .lineage_compaction import ZERO_SHA256
from .lineage_consistency import GLOBAL_NON_EQUIVOCATION_STATUS
from .lineage_witness import CONDITIONAL_NON_EQUIVOCATION_STATUS
from .lineage_witness_handoff import (
    CONDITIONAL_HANDOFF_STATUS,
    verify_witness_policy_handoff_package,
)
from .portable_causality import canonical_json_bytes, digest_json, is_sha256

CHAIN_STEP_SCHEMA = "ttrace-witness-policy-handoff-chain-step/v0.1"
CHAIN_REF_SCHEMA = "ttrace-witness-policy-handoff-chain-ref/v0.1"
CHAIN_ROOT_INPUT_SCHEMA = "ttrace-witness-policy-handoff-chain-root-input/v0.1"
CHAIN_RECEIPT_SCHEMA = "ttrace-witness-policy-handoff-chain-receipt/v0.1"
CHAIN_FORK_EVIDENCE_SCHEMA = (
    "ttrace-witness-policy-handoff-chain-fork-evidence/v0.1"
)
CHAIN_REASON = "repeated_witness_policy_handoff_chain_verified"
CHAIN_FORK_REASON = "witness_policy_handoff_chain_fork_detected"
CHAIN_FORK_NOT_PROVEN_REASON = "witness_policy_handoff_chain_fork_not_proven"
CONDITIONAL_HANDOFF_CHAIN_STATUS = "pinned-predecessor-handoff-chain-verified"

CHAIN_REF_KEYS = {
    "schema",
    "chain_id",
    "policy_id",
    "genesis_policy_epoch",
    "genesis_policy_sha256",
    "completed_handoffs",
    "current_policy_epoch",
    "current_policy_sha256",
    "current_activation_package_sha256",
    "current_activation_certificate_sha256",
    "current_handoff_package_sha256",
    "current_handoff_certificate_sha256",
    "previous_chain_ref_sha256",
    "previous_chain_root_sha256",
    "step_commitment_sha256",
    "chain_root_sha256",
    "chain_contract_sha256",
    "authorization_contract_sha256",
}
STEP_KEYS = {
    "schema",
    "chain_id",
    "handoff_index",
    "policy_id",
    "old_policy_epoch",
    "new_policy_epoch",
    "old_policy_sha256",
    "new_policy_sha256",
    "old_active_package_sha256",
    "new_activation_package_sha256",
    "old_active_certificate_sha256",
    "new_activation_certificate_sha256",
    "handoff_package_sha256",
    "handoff_certificate_sha256",
    "producer_statement_sha256",
    "anchor_sha256",
    "membership_root_sha256",
    "previous_chain_ref_sha256",
    "previous_chain_root_sha256",
    "chain_contract_sha256",
    "authorization_contract_sha256",
}
RECEIPT_KEYS = {
    "schema",
    "verified",
    "reason",
    "chain_id",
    "policy_id",
    "previous_handoffs",
    "completed_handoffs",
    "genesis_policy_epoch",
    "old_policy_epoch",
    "new_policy_epoch",
    "genesis_policy_sha256",
    "old_policy_sha256",
    "new_policy_sha256",
    "old_active_package_sha256",
    "new_activation_package_sha256",
    "old_active_certificate_sha256",
    "new_activation_certificate_sha256",
    "handoff_package_sha256",
    "handoff_certificate_sha256",
    "previous_chain_ref_sha256",
    "previous_chain_root_sha256",
    "step_commitment_sha256",
    "chain_root_sha256",
    "chain_ref_sha256",
    "exact_activation_carry_forward",
    "policy_epoch_contiguous",
    "active_shape_fixed",
    "rollback_resistance_status",
    "conditional_handoff_status",
    "conditional_non_equivocation_status",
    "global_non_equivocation_status",
}
FORK_EVIDENCE_KEYS = {
    "schema",
    "verified",
    "reason",
    "fork_detected",
    "chain_id",
    "policy_id",
    "previous_chain_ref_sha256",
    "previous_chain_root_sha256",
    "old_policy_epoch",
    "old_policy_sha256",
    "candidate_a_chain_ref_sha256",
    "candidate_b_chain_ref_sha256",
    "candidate_a_chain_root_sha256",
    "candidate_b_chain_root_sha256",
    "candidate_a_new_policy_sha256",
    "candidate_b_new_policy_sha256",
    "candidate_a_handoff_package_sha256",
    "candidate_b_handoff_package_sha256",
    "conditional_handoff_chain_status",
    "conditional_non_equivocation_status",
    "global_non_equivocation_status",
}


@dataclass(frozen=True)
class WitnessPolicyHandoffChainAgreement:
    verified: bool
    reason: str
    step_commitment: Optional[Dict[str, Any]] = None
    chain_ref: Optional[Dict[str, Any]] = None
    receipt: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "verified": self.verified,
            "reason": self.reason,
            "step_commitment": self.step_commitment,
            "chain_ref": self.chain_ref,
            "receipt": self.receipt,
        }


@dataclass(frozen=True)
class WitnessPolicyHandoffChainDecision:
    verified: bool
    reason: str
    chain_ref_sha256: Optional[str] = None
    chain_root_sha256: Optional[str] = None
    completed_handoffs: int = 0
    current_policy_epoch: int = 0
    current_policy_sha256: Optional[str] = None
    conditional_handoff_chain_status: str = CONDITIONAL_HANDOFF_CHAIN_STATUS
    global_non_equivocation_status: str = GLOBAL_NON_EQUIVOCATION_STATUS


@dataclass(frozen=True)
class WitnessPolicyHandoffChainForkDecision:
    verified: bool
    reason: str
    fork_detected: bool = False
    evidence: Optional[Dict[str, Any]] = None
    conditional_handoff_chain_status: str = CONDITIONAL_HANDOFF_CHAIN_STATUS
    global_non_equivocation_status: str = GLOBAL_NON_EQUIVOCATION_STATUS


def _text(value: Any) -> bool:
    return isinstance(value, str) and bool(value)


def _positive_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value > 0


def _nonzero_sha(value: Any) -> bool:
    return is_sha256(value) and value != ZERO_SHA256


def _context(package: Any) -> Tuple[bool, str, Dict[str, Any]]:
    decision = verify_witness_policy_handoff_package(package)
    if not decision.verified:
        return False, decision.reason, {}
    if not isinstance(package, Mapping):
        return False, "handoff_package_invalid", {}
    old = package.get("old_active_quorum_package")
    new = package.get("new_activation_quorum_package")
    statement = package.get("handoff_statement")
    receipt = package.get("handoff_certificate")
    if not all(isinstance(x, Mapping) for x in (old, new, statement, receipt)):
        return False, "handoff_package_invalid", {}
    old_policy = old.get("witness_policy")
    new_policy = new.get("witness_policy")
    old_cert = old.get("quorum_certificate")
    new_cert = new.get("quorum_certificate")
    if not all(
        isinstance(x, Mapping)
        for x in (old_policy, new_policy, old_cert, new_cert)
    ):
        return False, "handoff_package_context_missing", {}
    return True, CHAIN_REASON, {
        "old": old,
        "new": new,
        "old_policy": old_policy,
        "new_policy": new_policy,
        "old_cert": old_cert,
        "new_cert": new_cert,
        "statement": statement,
        "receipt": receipt,
    }


def _step(
    package: Mapping[str, Any],
    ctx: Mapping[str, Any],
    *,
    chain_id: str,
    index: int,
    previous_ref: str,
    previous_root: str,
    chain_contract: str,
    authorization_contract: str,
) -> Dict[str, Any]:
    old_policy = ctx["old_policy"]
    new_policy = ctx["new_policy"]
    statement = ctx["statement"]
    return {
        "schema": CHAIN_STEP_SCHEMA,
        "chain_id": chain_id,
        "handoff_index": index,
        "policy_id": old_policy["policy_id"],
        "old_policy_epoch": old_policy["policy_epoch"],
        "new_policy_epoch": new_policy["policy_epoch"],
        "old_policy_sha256": digest_json(old_policy),
        "new_policy_sha256": digest_json(new_policy),
        "old_active_package_sha256": digest_json(ctx["old"]),
        "new_activation_package_sha256": digest_json(ctx["new"]),
        "old_active_certificate_sha256": digest_json(ctx["old_cert"]),
        "new_activation_certificate_sha256": digest_json(ctx["new_cert"]),
        "handoff_package_sha256": digest_json(package),
        "handoff_certificate_sha256": digest_json(ctx["receipt"]),
        "producer_statement_sha256": statement["producer_statement_sha256"],
        "anchor_sha256": statement["anchor_sha256"],
        "membership_root_sha256": statement["membership_root_sha256"],
        "previous_chain_ref_sha256": previous_ref,
        "previous_chain_root_sha256": previous_root,
        "chain_contract_sha256": chain_contract,
        "authorization_contract_sha256": authorization_contract,
    }


def validate_witness_policy_handoff_chain_step(value: Any) -> bool:
    if not isinstance(value, Mapping) or set(value) != STEP_KEYS:
        return False
    index = value.get("handoff_index")
    if not (
        value.get("schema") == CHAIN_STEP_SCHEMA
        and _text(value.get("chain_id"))
        and _positive_int(index)
        and _text(value.get("policy_id"))
        and _positive_int(value.get("old_policy_epoch"))
        and value.get("new_policy_epoch") == value.get("old_policy_epoch") + 1
        and all(
            is_sha256(value.get(key))
            for key in STEP_KEYS
            if key.endswith("_sha256")
        )
        and all(
            _nonzero_sha(value.get(key))
            for key in STEP_KEYS
            if key.endswith("_sha256")
            and key
            not in {"previous_chain_ref_sha256", "previous_chain_root_sha256"}
        )
    ):
        return False
    previous = (
        value.get("previous_chain_ref_sha256"),
        value.get("previous_chain_root_sha256"),
    )
    return (
        previous == (ZERO_SHA256, ZERO_SHA256)
        if index == 1
        else all(_nonzero_sha(item) for item in previous)
    )


def _root_input(ref: Mapping[str, Any]) -> Dict[str, Any]:
    return {
        "schema": CHAIN_ROOT_INPUT_SCHEMA,
        **{
            key: ref[key]
            for key in CHAIN_REF_KEYS
            if key not in {"schema", "chain_root_sha256"}
        },
    }


def validate_witness_policy_handoff_chain_ref(value: Any) -> bool:
    if not isinstance(value, Mapping) or set(value) != CHAIN_REF_KEYS:
        return False
    count = value.get("completed_handoffs")
    genesis = value.get("genesis_policy_epoch")
    current = value.get("current_policy_epoch")
    if not (
        value.get("schema") == CHAIN_REF_SCHEMA
        and _text(value.get("chain_id"))
        and _text(value.get("policy_id"))
        and _positive_int(genesis)
        and _positive_int(count)
        and current == genesis + count
        and all(
            is_sha256(value.get(key))
            for key in CHAIN_REF_KEYS
            if key.endswith("_sha256")
        )
        and all(
            _nonzero_sha(value.get(key))
            for key in CHAIN_REF_KEYS
            if key.endswith("_sha256")
            and key
            not in {"previous_chain_ref_sha256", "previous_chain_root_sha256"}
        )
    ):
        return False
    previous = (
        value.get("previous_chain_ref_sha256"),
        value.get("previous_chain_root_sha256"),
    )
    if count == 1 and previous != (ZERO_SHA256, ZERO_SHA256):
        return False
    if count > 1 and not all(_nonzero_sha(item) for item in previous):
        return False
    return value.get("chain_root_sha256") == digest_json(_root_input(value))


def _build_ref(
    package: Mapping[str, Any],
    ctx: Mapping[str, Any],
    *,
    chain_id: str,
    genesis_epoch: int,
    genesis_policy: str,
    index: int,
    previous_ref: str,
    previous_root: str,
    chain_contract: str,
    authorization_contract: str,
) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    step = _step(
        package,
        ctx,
        chain_id=chain_id,
        index=index,
        previous_ref=previous_ref,
        previous_root=previous_root,
        chain_contract=chain_contract,
        authorization_contract=authorization_contract,
    )
    if not validate_witness_policy_handoff_chain_step(step):
        raise ValueError("handoff_chain_step_invalid")
    new_policy = ctx["new_policy"]
    ref: Dict[str, Any] = {
        "schema": CHAIN_REF_SCHEMA,
        "chain_id": chain_id,
        "policy_id": new_policy["policy_id"],
        "genesis_policy_epoch": genesis_epoch,
        "genesis_policy_sha256": genesis_policy,
        "completed_handoffs": index,
        "current_policy_epoch": new_policy["policy_epoch"],
        "current_policy_sha256": digest_json(new_policy),
        "current_activation_package_sha256": digest_json(ctx["new"]),
        "current_activation_certificate_sha256": digest_json(ctx["new_cert"]),
        "current_handoff_package_sha256": digest_json(package),
        "current_handoff_certificate_sha256": digest_json(ctx["receipt"]),
        "previous_chain_ref_sha256": previous_ref,
        "previous_chain_root_sha256": previous_root,
        "step_commitment_sha256": digest_json(step),
        "chain_root_sha256": ZERO_SHA256,
        "chain_contract_sha256": chain_contract,
        "authorization_contract_sha256": authorization_contract,
    }
    ref["chain_root_sha256"] = digest_json(_root_input(ref))
    if not validate_witness_policy_handoff_chain_ref(ref):
        raise ValueError("handoff_chain_ref_invalid")
    return step, ref


def _receipt(
    package: Mapping[str, Any],
    ctx: Mapping[str, Any],
    step: Mapping[str, Any],
    ref: Mapping[str, Any],
    previous_count: int,
) -> Dict[str, Any]:
    return {
        "schema": CHAIN_RECEIPT_SCHEMA,
        "verified": True,
        "reason": CHAIN_REASON,
        "chain_id": ref["chain_id"],
        "policy_id": ref["policy_id"],
        "previous_handoffs": previous_count,
        "completed_handoffs": ref["completed_handoffs"],
        "genesis_policy_epoch": ref["genesis_policy_epoch"],
        "old_policy_epoch": ctx["old_policy"]["policy_epoch"],
        "new_policy_epoch": ctx["new_policy"]["policy_epoch"],
        "genesis_policy_sha256": ref["genesis_policy_sha256"],
        "old_policy_sha256": digest_json(ctx["old_policy"]),
        "new_policy_sha256": digest_json(ctx["new_policy"]),
        "old_active_package_sha256": digest_json(ctx["old"]),
        "new_activation_package_sha256": digest_json(ctx["new"]),
        "old_active_certificate_sha256": digest_json(ctx["old_cert"]),
        "new_activation_certificate_sha256": digest_json(ctx["new_cert"]),
        "handoff_package_sha256": digest_json(package),
        "handoff_certificate_sha256": digest_json(ctx["receipt"]),
        "previous_chain_ref_sha256": ref["previous_chain_ref_sha256"],
        "previous_chain_root_sha256": ref["previous_chain_root_sha256"],
        "step_commitment_sha256": digest_json(step),
        "chain_root_sha256": ref["chain_root_sha256"],
        "chain_ref_sha256": digest_json(ref),
        "exact_activation_carry_forward": True,
        "policy_epoch_contiguous": True,
        "active_shape_fixed": True,
        "rollback_resistance_status": "supported-under-pinned-chain-predecessor",
        "conditional_handoff_status": CONDITIONAL_HANDOFF_STATUS,
        "conditional_non_equivocation_status": CONDITIONAL_NON_EQUIVOCATION_STATUS,
        "global_non_equivocation_status": GLOBAL_NON_EQUIVOCATION_STATUS,
    }


def _agreement(
    package: Mapping[str, Any],
    ctx: Mapping[str, Any],
    step: Dict[str, Any],
    ref: Dict[str, Any],
    previous_count: int,
) -> WitnessPolicyHandoffChainAgreement:
    receipt = _receipt(package, ctx, step, ref, previous_count)
    if set(receipt) != RECEIPT_KEYS:
        return WitnessPolicyHandoffChainAgreement(
            False, "handoff_chain_receipt_invalid"
        )
    return WitnessPolicyHandoffChainAgreement(True, CHAIN_REASON, step, ref, receipt)


def build_seed_witness_policy_handoff_chain(
    package: Mapping[str, Any],
    *,
    chain_id: str,
    expected_genesis_policy_epoch: int,
    expected_genesis_policy_sha256: str,
    chain_contract_sha256: str,
    authorization_contract_sha256: str,
) -> WitnessPolicyHandoffChainAgreement:
    valid, reason, ctx = _context(package)
    if not valid:
        return WitnessPolicyHandoffChainAgreement(False, reason)
    if not _text(chain_id):
        return WitnessPolicyHandoffChainAgreement(False, "handoff_chain_id_invalid")
    if not _positive_int(expected_genesis_policy_epoch):
        return WitnessPolicyHandoffChainAgreement(
            False, "handoff_chain_genesis_invalid"
        )
    if not all(
        _nonzero_sha(item)
        for item in (
            expected_genesis_policy_sha256,
            chain_contract_sha256,
            authorization_contract_sha256,
        )
    ):
        return WitnessPolicyHandoffChainAgreement(
            False, "handoff_chain_contract_invalid"
        )
    old_policy = ctx["old_policy"]
    if old_policy["policy_epoch"] != expected_genesis_policy_epoch:
        return WitnessPolicyHandoffChainAgreement(
            False, "handoff_chain_genesis_epoch_mismatch"
        )
    if digest_json(old_policy) != expected_genesis_policy_sha256:
        return WitnessPolicyHandoffChainAgreement(
            False, "handoff_chain_genesis_policy_mismatch"
        )
    try:
        step, ref = _build_ref(
            package,
            ctx,
            chain_id=chain_id,
            genesis_epoch=expected_genesis_policy_epoch,
            genesis_policy=expected_genesis_policy_sha256,
            index=1,
            previous_ref=ZERO_SHA256,
            previous_root=ZERO_SHA256,
            chain_contract=chain_contract_sha256,
            authorization_contract=authorization_contract_sha256,
        )
    except ValueError as error:
        return WitnessPolicyHandoffChainAgreement(False, str(error))
    return _agreement(package, ctx, step, ref, 0)


def advance_witness_policy_handoff_chain(
    previous: Mapping[str, Any],
    package: Mapping[str, Any],
) -> WitnessPolicyHandoffChainAgreement:
    if not validate_witness_policy_handoff_chain_ref(previous):
        return WitnessPolicyHandoffChainAgreement(
            False, "previous_handoff_chain_ref_invalid"
        )
    valid, reason, ctx = _context(package)
    if not valid:
        return WitnessPolicyHandoffChainAgreement(False, reason)
    old_policy = ctx["old_policy"]
    if old_policy["policy_id"] != previous["policy_id"]:
        return WitnessPolicyHandoffChainAgreement(
            False, "handoff_chain_policy_id_mismatch"
        )
    if old_policy["policy_epoch"] != previous["current_policy_epoch"]:
        return WitnessPolicyHandoffChainAgreement(
            False, "handoff_chain_old_policy_epoch_mismatch"
        )
    if digest_json(old_policy) != previous["current_policy_sha256"]:
        return WitnessPolicyHandoffChainAgreement(
            False, "handoff_chain_old_policy_mismatch"
        )
    if digest_json(ctx["old"]) != previous["current_activation_package_sha256"]:
        return WitnessPolicyHandoffChainAgreement(
            False, "handoff_chain_activation_carry_forward_mismatch"
        )
    if digest_json(ctx["old_cert"]) != previous[
        "current_activation_certificate_sha256"
    ]:
        return WitnessPolicyHandoffChainAgreement(
            False, "handoff_chain_activation_certificate_mismatch"
        )
    try:
        step, ref = _build_ref(
            package,
            ctx,
            chain_id=str(previous["chain_id"]),
            genesis_epoch=int(previous["genesis_policy_epoch"]),
            genesis_policy=str(previous["genesis_policy_sha256"]),
            index=int(previous["completed_handoffs"]) + 1,
            previous_ref=digest_json(previous),
            previous_root=str(previous["chain_root_sha256"]),
            chain_contract=str(previous["chain_contract_sha256"]),
            authorization_contract=str(previous["authorization_contract_sha256"]),
        )
    except ValueError as error:
        return WitnessPolicyHandoffChainAgreement(False, str(error))
    return _agreement(package, ctx, step, ref, int(previous["completed_handoffs"]))


def validate_witness_policy_handoff_chain_agreement(
    agreement: WitnessPolicyHandoffChainAgreement,
    package: Mapping[str, Any],
    *,
    previous_chain_ref: Optional[Mapping[str, Any]],
    chain_id: Optional[str] = None,
    expected_genesis_policy_epoch: Optional[int] = None,
    expected_genesis_policy_sha256: Optional[str] = None,
    chain_contract_sha256: Optional[str] = None,
    authorization_contract_sha256: Optional[str] = None,
) -> bool:
    if not isinstance(agreement, WitnessPolicyHandoffChainAgreement):
        return False
    if previous_chain_ref is None:
        values = (
            chain_id,
            expected_genesis_policy_epoch,
            expected_genesis_policy_sha256,
            chain_contract_sha256,
            authorization_contract_sha256,
        )
        if any(item is None for item in values):
            return False
        expected = build_seed_witness_policy_handoff_chain(
            package,
            chain_id=str(chain_id),
            expected_genesis_policy_epoch=int(expected_genesis_policy_epoch),
            expected_genesis_policy_sha256=str(expected_genesis_policy_sha256),
            chain_contract_sha256=str(chain_contract_sha256),
            authorization_contract_sha256=str(authorization_contract_sha256),
        )
    else:
        expected = advance_witness_policy_handoff_chain(previous_chain_ref, package)
    return expected.verified and canonical_json_bytes(expected.to_dict()) == (
        canonical_json_bytes(agreement.to_dict())
    )


def verify_witness_policy_handoff_chain(
    packages: Sequence[Mapping[str, Any]],
    expected_ref: Mapping[str, Any],
    *,
    chain_id: str,
    expected_genesis_policy_epoch: int,
    expected_genesis_policy_sha256: str,
    chain_contract_sha256: str,
    authorization_contract_sha256: str,
) -> WitnessPolicyHandoffChainDecision:
    if not isinstance(packages, Sequence) or isinstance(packages, (str, bytes)):
        return WitnessPolicyHandoffChainDecision(
            False, "handoff_chain_packages_invalid"
        )
    if not packages:
        return WitnessPolicyHandoffChainDecision(False, "handoff_chain_packages_empty")
    result = build_seed_witness_policy_handoff_chain(
        packages[0],
        chain_id=chain_id,
        expected_genesis_policy_epoch=expected_genesis_policy_epoch,
        expected_genesis_policy_sha256=expected_genesis_policy_sha256,
        chain_contract_sha256=chain_contract_sha256,
        authorization_contract_sha256=authorization_contract_sha256,
    )
    if not result.verified or result.chain_ref is None:
        return WitnessPolicyHandoffChainDecision(False, result.reason)
    current = result.chain_ref
    for package in packages[1:]:
        result = advance_witness_policy_handoff_chain(current, package)
        if not result.verified or result.chain_ref is None:
            return WitnessPolicyHandoffChainDecision(False, result.reason)
        current = result.chain_ref
    if not validate_witness_policy_handoff_chain_ref(expected_ref):
        return WitnessPolicyHandoffChainDecision(
            False, "expected_handoff_chain_ref_invalid"
        )
    if canonical_json_bytes(current) != canonical_json_bytes(expected_ref):
        return WitnessPolicyHandoffChainDecision(False, "handoff_chain_tip_mismatch")
    return WitnessPolicyHandoffChainDecision(
        True,
        CHAIN_REASON,
        digest_json(current),
        str(current["chain_root_sha256"]),
        int(current["completed_handoffs"]),
        int(current["current_policy_epoch"]),
        str(current["current_policy_sha256"]),
    )


def detect_witness_policy_handoff_chain_fork(
    previous: Mapping[str, Any],
    package_a: Mapping[str, Any],
    package_b: Mapping[str, Any],
) -> WitnessPolicyHandoffChainForkDecision:
    first = advance_witness_policy_handoff_chain(previous, package_a)
    if not first.verified or first.chain_ref is None:
        return WitnessPolicyHandoffChainForkDecision(False, first.reason)
    second = advance_witness_policy_handoff_chain(previous, package_b)
    if not second.verified or second.chain_ref is None:
        return WitnessPolicyHandoffChainForkDecision(False, second.reason)
    if canonical_json_bytes(first.chain_ref) == canonical_json_bytes(second.chain_ref):
        return WitnessPolicyHandoffChainForkDecision(True, CHAIN_FORK_NOT_PROVEN_REASON)
    semantic_a = (
        first.chain_ref["current_policy_sha256"],
        first.chain_ref["current_handoff_package_sha256"],
        first.chain_ref["current_handoff_certificate_sha256"],
    )
    semantic_b = (
        second.chain_ref["current_policy_sha256"],
        second.chain_ref["current_handoff_package_sha256"],
        second.chain_ref["current_handoff_certificate_sha256"],
    )
    if semantic_a == semantic_b:
        return WitnessPolicyHandoffChainForkDecision(True, CHAIN_FORK_NOT_PROVEN_REASON)
    evidence = {
        "schema": CHAIN_FORK_EVIDENCE_SCHEMA,
        "verified": True,
        "reason": CHAIN_FORK_REASON,
        "fork_detected": True,
        "chain_id": previous["chain_id"],
        "policy_id": previous["policy_id"],
        "previous_chain_ref_sha256": digest_json(previous),
        "previous_chain_root_sha256": previous["chain_root_sha256"],
        "old_policy_epoch": previous["current_policy_epoch"],
        "old_policy_sha256": previous["current_policy_sha256"],
        "candidate_a_chain_ref_sha256": digest_json(first.chain_ref),
        "candidate_b_chain_ref_sha256": digest_json(second.chain_ref),
        "candidate_a_chain_root_sha256": first.chain_ref["chain_root_sha256"],
        "candidate_b_chain_root_sha256": second.chain_ref["chain_root_sha256"],
        "candidate_a_new_policy_sha256": first.chain_ref["current_policy_sha256"],
        "candidate_b_new_policy_sha256": second.chain_ref["current_policy_sha256"],
        "candidate_a_handoff_package_sha256": first.chain_ref[
            "current_handoff_package_sha256"
        ],
        "candidate_b_handoff_package_sha256": second.chain_ref[
            "current_handoff_package_sha256"
        ],
        "conditional_handoff_chain_status": CONDITIONAL_HANDOFF_CHAIN_STATUS,
        "conditional_non_equivocation_status": CONDITIONAL_NON_EQUIVOCATION_STATUS,
        "global_non_equivocation_status": GLOBAL_NON_EQUIVOCATION_STATUS,
    }
    if set(evidence) != FORK_EVIDENCE_KEYS:
        return WitnessPolicyHandoffChainForkDecision(
            False, "handoff_chain_fork_evidence_shape_invalid"
        )
    return WitnessPolicyHandoffChainForkDecision(
        True, CHAIN_FORK_REASON, True, evidence
    )
