"""Portable fork-branch identity and exact common-tip binding."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from ttrace.canonical import digest_object, require_sha256
from ttrace.state import CausalStateRef, advance_state

BRANCH_REF_SCHEMA = "ttrace-fork-branch-ref/v0.1"
BRANCH_CHECKPOINT_SCHEMA = "ttrace-fork-branch-checkpoint/v0.1"
BRANCH_WITNESS_SCHEMA = "ttrace-fork-branch-witness/v0.1"

_BRANCH_REF_KEYS = {
    "schema",
    "trust_domain",
    "logical_state_id",
    "logical_branch_id",
    "from_causal_epoch",
    "to_causal_epoch",
    "common_state_ref_sha256",
    "branch_state_ref_sha256",
    "branch_contract_sha256",
    "authorization_contract_sha256",
}
_BRANCH_CHECKPOINT_KEYS = {
    "schema",
    "state_ref",
    "branch_ref",
    "previous_checkpoint_sha256",
}
_BRANCH_WITNESS_KEYS = {
    "schema",
    "state_ref",
    "branch_ref_sha256",
    "checkpoint_sha256",
    "previous_witness_sha256",
}


def _require_text(value: object, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"invalid_text:{field}")
    return value


@dataclass(frozen=True)
class ForkBranch:
    state_ref: CausalStateRef
    branch_ref: dict[str, Any]
    checkpoint: dict[str, Any]
    witness: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "state_ref": self.state_ref.to_dict(),
            "branch_ref": self.branch_ref,
            "checkpoint": self.checkpoint,
            "witness": self.witness,
        }


@dataclass(frozen=True)
class BranchObservation:
    """Verified branch evidence kept outside portable branch identity."""

    verified: bool
    provider_id: str
    authority_id: str
    evidence_sha256: str
    branch: ForkBranch

    def __post_init__(self) -> None:
        if self.verified is not True:
            raise ValueError("branch_observation_unverified")
        _require_text(self.provider_id, "provider_id")
        _require_text(self.authority_id, "authority_id")
        require_sha256(self.evidence_sha256, "evidence_sha256")


def build_fork_branch(
    common_state: CausalStateRef,
    *,
    common_checkpoint_sha256: str,
    common_witness_sha256: str,
    logical_branch_id: str,
    semantic_state_sha256: str,
    branch_contract_sha256: str,
    authorization_contract_sha256: str,
) -> ForkBranch:
    common_checkpoint_sha256 = require_sha256(
        common_checkpoint_sha256, "common_checkpoint_sha256"
    )
    common_witness_sha256 = require_sha256(
        common_witness_sha256, "common_witness_sha256"
    )
    branch_state = advance_state(
        common_state, semantic_state_sha256=semantic_state_sha256
    )
    branch_ref = {
        "schema": BRANCH_REF_SCHEMA,
        "trust_domain": common_state.trust_domain,
        "logical_state_id": common_state.logical_state_id,
        "logical_branch_id": _require_text(logical_branch_id, "logical_branch_id"),
        "from_causal_epoch": common_state.causal_epoch,
        "to_causal_epoch": branch_state.causal_epoch,
        "common_state_ref_sha256": common_state.digest(),
        "branch_state_ref_sha256": branch_state.digest(),
        "branch_contract_sha256": require_sha256(
            branch_contract_sha256, "branch_contract_sha256"
        ),
        "authorization_contract_sha256": require_sha256(
            authorization_contract_sha256, "authorization_contract_sha256"
        ),
    }
    checkpoint = {
        "schema": BRANCH_CHECKPOINT_SCHEMA,
        "state_ref": branch_state.to_dict(),
        "branch_ref": branch_ref,
        "previous_checkpoint_sha256": common_checkpoint_sha256,
    }
    witness = {
        "schema": BRANCH_WITNESS_SCHEMA,
        "state_ref": branch_state.to_dict(),
        "branch_ref_sha256": digest_object(branch_ref),
        "checkpoint_sha256": digest_object(checkpoint),
        "previous_witness_sha256": common_witness_sha256,
    }
    branch = ForkBranch(branch_state, branch_ref, checkpoint, witness)
    if not validate_fork_branch(
        branch,
        common_state=common_state,
        common_checkpoint_sha256=common_checkpoint_sha256,
        common_witness_sha256=common_witness_sha256,
    ):
        raise ValueError("fork_branch_invalid")
    return branch


def validate_fork_branch(
    branch: ForkBranch,
    *,
    common_state: CausalStateRef,
    common_checkpoint_sha256: str,
    common_witness_sha256: str,
) -> bool:
    try:
        require_sha256(common_checkpoint_sha256, "common_checkpoint_sha256")
        require_sha256(common_witness_sha256, "common_witness_sha256")
        state = branch.state_ref
        ref = branch.branch_ref
        checkpoint = branch.checkpoint
        witness = branch.witness
        if not isinstance(ref, dict) or set(ref) != _BRANCH_REF_KEYS:
            return False
        if not isinstance(checkpoint, dict) or set(checkpoint) != _BRANCH_CHECKPOINT_KEYS:
            return False
        if not isinstance(witness, dict) or set(witness) != _BRANCH_WITNESS_KEYS:
            return False
        for field in (
            "common_state_ref_sha256",
            "branch_state_ref_sha256",
            "branch_contract_sha256",
            "authorization_contract_sha256",
        ):
            require_sha256(ref.get(field), field)
        require_sha256(
            checkpoint.get("previous_checkpoint_sha256"),
            "previous_checkpoint_sha256",
        )
        for field in (
            "branch_ref_sha256",
            "checkpoint_sha256",
            "previous_witness_sha256",
        ):
            require_sha256(witness.get(field), field)
        return (
            state.trust_domain == common_state.trust_domain
            and state.logical_state_id == common_state.logical_state_id
            and state.causal_epoch == common_state.causal_epoch + 1
            and state.semantic_state_sha256 != common_state.semantic_state_sha256
            and ref.get("schema") == BRANCH_REF_SCHEMA
            and ref.get("trust_domain") == common_state.trust_domain
            and ref.get("logical_state_id") == common_state.logical_state_id
            and isinstance(ref.get("logical_branch_id"), str)
            and bool(ref.get("logical_branch_id"))
            and ref.get("from_causal_epoch") == common_state.causal_epoch
            and ref.get("to_causal_epoch") == state.causal_epoch
            and ref.get("common_state_ref_sha256") == common_state.digest()
            and ref.get("branch_state_ref_sha256") == state.digest()
            and checkpoint
            == {
                "schema": BRANCH_CHECKPOINT_SCHEMA,
                "state_ref": state.to_dict(),
                "branch_ref": ref,
                "previous_checkpoint_sha256": common_checkpoint_sha256,
            }
            and witness
            == {
                "schema": BRANCH_WITNESS_SCHEMA,
                "state_ref": state.to_dict(),
                "branch_ref_sha256": digest_object(ref),
                "checkpoint_sha256": digest_object(checkpoint),
                "previous_witness_sha256": common_witness_sha256,
            }
        )
    except (KeyError, TypeError, ValueError):
        return False
