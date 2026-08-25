"""Canonical two-parent causal reconciliation for T-Trace."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from ttrace.branch import BranchObservation, ForkBranch, validate_fork_branch
from ttrace.canonical import canonical_json_bytes, digest_object, require_sha256
from ttrace.state import CausalStateRef

RECONCILIATION_VOTE_SCHEMA = "ttrace-causal-reconciliation-vote/v0.1"
RECONCILIATION_REF_SCHEMA = "ttrace-causal-reconciliation-ref/v0.1"
RECONCILIATION_CHECKPOINT_SCHEMA = "ttrace-causal-reconciliation-checkpoint/v0.1"
RECONCILIATION_WITNESS_SCHEMA = "ttrace-causal-reconciliation-witness/v0.1"
RECONCILIATION_RECEIPT_SCHEMA = "ttrace-causal-reconciliation-receipt/v0.1"

_PARENT_KEYS = {
    "logical_branch_id",
    "branch_ref_sha256",
    "state_ref_sha256",
    "checkpoint_sha256",
    "witness_sha256",
}
_RECONCILIATION_REF_KEYS = {
    "schema",
    "trust_domain",
    "logical_state_id",
    "logical_reconciliation_id",
    "fork_causal_epoch",
    "reconciled_causal_epoch",
    "common_state_ref_sha256",
    "common_checkpoint_sha256",
    "common_witness_sha256",
    "parents",
    "parent_set_sha256",
    "reconciled_state_ref_sha256",
    "reconciliation_contract_sha256",
    "authorization_contract_sha256",
}
_RECONCILIATION_CHECKPOINT_KEYS = {
    "schema",
    "state_ref",
    "reconciliation_ref",
    "parent_checkpoint_sha256",
}
_RECONCILIATION_WITNESS_KEYS = {
    "schema",
    "state_ref",
    "reconciliation_ref_sha256",
    "checkpoint_sha256",
    "parent_witness_sha256",
}
_RECONCILIATION_RECEIPT_KEYS = {
    "schema",
    "verified",
    "reason",
    "fork_causal_epoch",
    "reconciled_causal_epoch",
    "lineage_parent_count",
    "both_lineages_preserved",
    "fork_semantics_divergent",
    "branch_order_canonical",
    "raw_evidence_embedded",
    "parent_set_sha256",
    "reconciled_state_ref_sha256",
    "reconciliation_ref_sha256",
    "checkpoint_sha256",
    "witness_sha256",
}


def _require_text(value: object, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"invalid_text:{field}")
    return value


@dataclass(frozen=True)
class ReconciliationVote:
    verified: bool
    authority_id: str
    evidence_sha256: str
    branch_ref_sha256: str
    branch_state_ref_sha256: str
    branch_checkpoint_sha256: str
    branch_witness_sha256: str
    target_semantic_state_sha256: str
    reconciliation_contract_sha256: str
    authorization_contract_sha256: str

    def __post_init__(self) -> None:
        if self.verified is not True:
            raise ValueError("reconciliation_vote_unverified")
        _require_text(self.authority_id, "authority_id")
        for field, value in (
            ("evidence_sha256", self.evidence_sha256),
            ("branch_ref_sha256", self.branch_ref_sha256),
            ("branch_state_ref_sha256", self.branch_state_ref_sha256),
            ("branch_checkpoint_sha256", self.branch_checkpoint_sha256),
            ("branch_witness_sha256", self.branch_witness_sha256),
            ("target_semantic_state_sha256", self.target_semantic_state_sha256),
            ("reconciliation_contract_sha256", self.reconciliation_contract_sha256),
            ("authorization_contract_sha256", self.authorization_contract_sha256),
        ):
            require_sha256(value, field)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": RECONCILIATION_VOTE_SCHEMA,
            "verified": True,
            "authority_id": self.authority_id,
            "evidence_sha256": self.evidence_sha256,
            "branch_ref_sha256": self.branch_ref_sha256,
            "branch_state_ref_sha256": self.branch_state_ref_sha256,
            "branch_checkpoint_sha256": self.branch_checkpoint_sha256,
            "branch_witness_sha256": self.branch_witness_sha256,
            "target_semantic_state_sha256": self.target_semantic_state_sha256,
            "reconciliation_contract_sha256": self.reconciliation_contract_sha256,
            "authorization_contract_sha256": self.authorization_contract_sha256,
        }


@dataclass(frozen=True)
class ReconciliationResult:
    state_ref: CausalStateRef
    reconciliation_ref: dict[str, Any]
    checkpoint: dict[str, Any]
    witness: dict[str, Any]
    receipt: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "state_ref": self.state_ref.to_dict(),
            "reconciliation_ref": self.reconciliation_ref,
            "checkpoint": self.checkpoint,
            "witness": self.witness,
            "receipt": self.receipt,
        }

    def digest(self) -> str:
        return digest_object(self.to_dict())


def build_reconciliation_vote(
    observation: BranchObservation,
    *,
    vote_evidence_sha256: str,
    target_semantic_state_sha256: str,
    reconciliation_contract_sha256: str,
    authorization_contract_sha256: str,
) -> ReconciliationVote:
    branch = observation.branch
    return ReconciliationVote(
        verified=True,
        authority_id=observation.authority_id,
        evidence_sha256=require_sha256(
            vote_evidence_sha256, "vote_evidence_sha256"
        ),
        branch_ref_sha256=digest_object(branch.branch_ref),
        branch_state_ref_sha256=branch.state_ref.digest(),
        branch_checkpoint_sha256=digest_object(branch.checkpoint),
        branch_witness_sha256=digest_object(branch.witness),
        target_semantic_state_sha256=require_sha256(
            target_semantic_state_sha256, "target_semantic_state_sha256"
        ),
        reconciliation_contract_sha256=require_sha256(
            reconciliation_contract_sha256, "reconciliation_contract_sha256"
        ),
        authorization_contract_sha256=require_sha256(
            authorization_contract_sha256, "authorization_contract_sha256"
        ),
    )


def _vote_matches(observation: BranchObservation, vote: ReconciliationVote) -> bool:
    branch = observation.branch
    return (
        vote.verified is True
        and vote.authority_id == observation.authority_id
        and vote.branch_ref_sha256 == digest_object(branch.branch_ref)
        and vote.branch_state_ref_sha256 == branch.state_ref.digest()
        and vote.branch_checkpoint_sha256 == digest_object(branch.checkpoint)
        and vote.branch_witness_sha256 == digest_object(branch.witness)
    )


def _parent_entry(branch: ForkBranch) -> dict[str, str]:
    return {
        "logical_branch_id": branch.branch_ref["logical_branch_id"],
        "branch_ref_sha256": digest_object(branch.branch_ref),
        "state_ref_sha256": branch.state_ref.digest(),
        "checkpoint_sha256": digest_object(branch.checkpoint),
        "witness_sha256": digest_object(branch.witness),
    }


def reconcile_two_branches(
    common_state: CausalStateRef,
    *,
    common_checkpoint_sha256: str,
    common_witness_sha256: str,
    logical_reconciliation_id: str,
    primary: BranchObservation,
    secondary: BranchObservation,
    primary_vote: ReconciliationVote,
    secondary_vote: ReconciliationVote,
) -> ReconciliationResult:
    common_checkpoint_sha256 = require_sha256(
        common_checkpoint_sha256, "common_checkpoint_sha256"
    )
    common_witness_sha256 = require_sha256(
        common_witness_sha256, "common_witness_sha256"
    )
    for observation in (primary, secondary):
        if not validate_fork_branch(
            observation.branch,
            common_state=common_state,
            common_checkpoint_sha256=common_checkpoint_sha256,
            common_witness_sha256=common_witness_sha256,
        ):
            raise ValueError("fork_branch_invalid")

    if primary.provider_id == secondary.provider_id:
        raise ValueError("branch_provider_not_independent")
    if primary.authority_id == secondary.authority_id:
        raise ValueError("branch_authority_not_independent")
    if primary.evidence_sha256 == secondary.evidence_sha256:
        raise ValueError("branch_evidence_not_independent")
    if (
        primary.branch.branch_ref["logical_branch_id"]
        == secondary.branch.branch_ref["logical_branch_id"]
    ):
        raise ValueError("logical_branch_id_not_distinct")
    if (
        primary.branch.state_ref.semantic_state_sha256
        == secondary.branch.state_ref.semantic_state_sha256
    ):
        raise ValueError("fork_semantics_not_divergent")
    if canonical_json_bytes(primary.branch.checkpoint) == canonical_json_bytes(
        secondary.branch.checkpoint
    ):
        raise ValueError("fork_checkpoint_not_distinct")

    if not _vote_matches(primary, primary_vote) or not _vote_matches(
        secondary, secondary_vote
    ):
        raise ValueError("reconciliation_vote_branch_binding_mismatch")
    if primary_vote.evidence_sha256 == secondary_vote.evidence_sha256:
        raise ValueError("reconciliation_vote_evidence_not_independent")
    if (
        primary_vote.target_semantic_state_sha256
        != secondary_vote.target_semantic_state_sha256
    ):
        raise ValueError("reconciliation_target_mismatch")
    if (
        primary_vote.reconciliation_contract_sha256
        != secondary_vote.reconciliation_contract_sha256
    ):
        raise ValueError("reconciliation_contract_mismatch")
    if (
        primary_vote.authorization_contract_sha256
        != secondary_vote.authorization_contract_sha256
    ):
        raise ValueError("reconciliation_authorization_mismatch")

    target = primary_vote.target_semantic_state_sha256
    if target in {
        primary.branch.state_ref.semantic_state_sha256,
        secondary.branch.state_ref.semantic_state_sha256,
        common_state.semantic_state_sha256,
    }:
        raise ValueError("reconciliation_target_not_new")

    branch_epoch = primary.branch.state_ref.causal_epoch
    if secondary.branch.state_ref.causal_epoch != branch_epoch:
        raise ValueError("fork_epoch_mismatch")
    reconciled_state = CausalStateRef(
        trust_domain=common_state.trust_domain,
        logical_state_id=common_state.logical_state_id,
        causal_epoch=branch_epoch + 1,
        semantic_state_sha256=target,
    )

    parent_entries = [_parent_entry(primary.branch), _parent_entry(secondary.branch)]
    parent_entries.sort(key=lambda item: item["checkpoint_sha256"])
    if parent_entries[0]["checkpoint_sha256"] == parent_entries[1]["checkpoint_sha256"]:
        raise ValueError("duplicate_reconciliation_parent")

    reconciliation_ref = {
        "schema": RECONCILIATION_REF_SCHEMA,
        "trust_domain": common_state.trust_domain,
        "logical_state_id": common_state.logical_state_id,
        "logical_reconciliation_id": _require_text(
            logical_reconciliation_id, "logical_reconciliation_id"
        ),
        "fork_causal_epoch": branch_epoch,
        "reconciled_causal_epoch": reconciled_state.causal_epoch,
        "common_state_ref_sha256": common_state.digest(),
        "common_checkpoint_sha256": common_checkpoint_sha256,
        "common_witness_sha256": common_witness_sha256,
        "parents": parent_entries,
        "parent_set_sha256": digest_object(parent_entries),
        "reconciled_state_ref_sha256": reconciled_state.digest(),
        "reconciliation_contract_sha256": primary_vote.reconciliation_contract_sha256,
        "authorization_contract_sha256": primary_vote.authorization_contract_sha256,
    }
    checkpoint = {
        "schema": RECONCILIATION_CHECKPOINT_SCHEMA,
        "state_ref": reconciled_state.to_dict(),
        "reconciliation_ref": reconciliation_ref,
        "parent_checkpoint_sha256": [
            item["checkpoint_sha256"] for item in parent_entries
        ],
    }
    witness = {
        "schema": RECONCILIATION_WITNESS_SCHEMA,
        "state_ref": reconciled_state.to_dict(),
        "reconciliation_ref_sha256": digest_object(reconciliation_ref),
        "checkpoint_sha256": digest_object(checkpoint),
        "parent_witness_sha256": [item["witness_sha256"] for item in parent_entries],
    }
    receipt = {
        "schema": RECONCILIATION_RECEIPT_SCHEMA,
        "verified": True,
        "reason": "causal_fork_reconciliation_verified",
        "fork_causal_epoch": branch_epoch,
        "reconciled_causal_epoch": reconciled_state.causal_epoch,
        "lineage_parent_count": 2,
        "both_lineages_preserved": True,
        "fork_semantics_divergent": True,
        "branch_order_canonical": True,
        "raw_evidence_embedded": False,
        "parent_set_sha256": reconciliation_ref["parent_set_sha256"],
        "reconciled_state_ref_sha256": reconciled_state.digest(),
        "reconciliation_ref_sha256": digest_object(reconciliation_ref),
        "checkpoint_sha256": digest_object(checkpoint),
        "witness_sha256": digest_object(witness),
    }
    result = ReconciliationResult(
        reconciled_state, reconciliation_ref, checkpoint, witness, receipt
    )
    if not validate_reconciliation_result(
        result,
        common_state=common_state,
        common_checkpoint_sha256=common_checkpoint_sha256,
        common_witness_sha256=common_witness_sha256,
    ):
        raise ValueError("reconciliation_result_invalid")
    return result


def _valid_parent(parent: object) -> bool:
    if not isinstance(parent, dict) or set(parent) != _PARENT_KEYS:
        return False
    try:
        _require_text(parent.get("logical_branch_id"), "logical_branch_id")
        for field in (
            "branch_ref_sha256",
            "state_ref_sha256",
            "checkpoint_sha256",
            "witness_sha256",
        ):
            require_sha256(parent.get(field), field)
    except ValueError:
        return False
    return True


def validate_reconciliation_result(
    result: ReconciliationResult,
    *,
    common_state: CausalStateRef,
    common_checkpoint_sha256: str,
    common_witness_sha256: str,
) -> bool:
    try:
        require_sha256(common_checkpoint_sha256, "common_checkpoint_sha256")
        require_sha256(common_witness_sha256, "common_witness_sha256")
        ref = result.reconciliation_ref
        checkpoint = result.checkpoint
        witness = result.witness
        receipt = result.receipt
        if not isinstance(ref, dict) or set(ref) != _RECONCILIATION_REF_KEYS:
            return False
        if not isinstance(checkpoint, dict) or set(checkpoint) != _RECONCILIATION_CHECKPOINT_KEYS:
            return False
        if not isinstance(witness, dict) or set(witness) != _RECONCILIATION_WITNESS_KEYS:
            return False
        if not isinstance(receipt, dict) or set(receipt) != _RECONCILIATION_RECEIPT_KEYS:
            return False
        parents = ref.get("parents")
        if not isinstance(parents, list) or len(parents) != 2:
            return False
        if not all(_valid_parent(parent) for parent in parents):
            return False
        if parents != sorted(parents, key=lambda item: item["checkpoint_sha256"]):
            return False
        for field in (
            "logical_branch_id",
            "branch_ref_sha256",
            "state_ref_sha256",
            "checkpoint_sha256",
            "witness_sha256",
        ):
            if len({item[field] for item in parents}) != 2:
                return False
        _require_text(ref.get("logical_reconciliation_id"), "logical_reconciliation_id")
        for field in (
            "common_state_ref_sha256",
            "common_checkpoint_sha256",
            "common_witness_sha256",
            "parent_set_sha256",
            "reconciled_state_ref_sha256",
            "reconciliation_contract_sha256",
            "authorization_contract_sha256",
        ):
            require_sha256(ref.get(field), field)

        expected_checkpoint = {
            "schema": RECONCILIATION_CHECKPOINT_SCHEMA,
            "state_ref": result.state_ref.to_dict(),
            "reconciliation_ref": ref,
            "parent_checkpoint_sha256": [
                item["checkpoint_sha256"] for item in parents
            ],
        }
        expected_witness = {
            "schema": RECONCILIATION_WITNESS_SCHEMA,
            "state_ref": result.state_ref.to_dict(),
            "reconciliation_ref_sha256": digest_object(ref),
            "checkpoint_sha256": digest_object(expected_checkpoint),
            "parent_witness_sha256": [item["witness_sha256"] for item in parents],
        }
        expected_receipt = {
            "schema": RECONCILIATION_RECEIPT_SCHEMA,
            "verified": True,
            "reason": "causal_fork_reconciliation_verified",
            "fork_causal_epoch": common_state.causal_epoch + 1,
            "reconciled_causal_epoch": common_state.causal_epoch + 2,
            "lineage_parent_count": 2,
            "both_lineages_preserved": True,
            "fork_semantics_divergent": True,
            "branch_order_canonical": True,
            "raw_evidence_embedded": False,
            "parent_set_sha256": digest_object(parents),
            "reconciled_state_ref_sha256": result.state_ref.digest(),
            "reconciliation_ref_sha256": digest_object(ref),
            "checkpoint_sha256": digest_object(expected_checkpoint),
            "witness_sha256": digest_object(expected_witness),
        }
        return (
            ref.get("schema") == RECONCILIATION_REF_SCHEMA
            and ref.get("trust_domain") == common_state.trust_domain
            and ref.get("logical_state_id") == common_state.logical_state_id
            and ref.get("common_state_ref_sha256") == common_state.digest()
            and ref.get("common_checkpoint_sha256") == common_checkpoint_sha256
            and ref.get("common_witness_sha256") == common_witness_sha256
            and ref.get("fork_causal_epoch") == common_state.causal_epoch + 1
            and ref.get("reconciled_causal_epoch") == common_state.causal_epoch + 2
            and ref.get("parent_set_sha256") == digest_object(parents)
            and ref.get("reconciled_state_ref_sha256") == result.state_ref.digest()
            and result.state_ref.trust_domain == common_state.trust_domain
            and result.state_ref.logical_state_id == common_state.logical_state_id
            and result.state_ref.causal_epoch == common_state.causal_epoch + 2
            and result.state_ref.semantic_state_sha256 != common_state.semantic_state_sha256
            and checkpoint == expected_checkpoint
            and witness == expected_witness
            and receipt == expected_receipt
        )
    except (KeyError, TypeError, ValueError):
        return False
