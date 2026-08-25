"""Portable transition identity between T-Trace causal states."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from ttrace.canonical import digest_object, require_sha256
from ttrace.state import CausalStateRef

TRANSITION_REF_SCHEMA = "ttrace-causal-transition-ref/v0.1"


def _require_text(value: object, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"invalid_text:{field}")
    return value


@dataclass(frozen=True)
class CausalTransitionRef:
    trust_domain: str
    logical_state_id: str
    logical_transition_id: str
    from_causal_epoch: int
    to_causal_epoch: int
    from_state_ref_sha256: str
    to_state_ref_sha256: str
    transition_contract_sha256: str
    authorization_contract_sha256: str

    def __post_init__(self) -> None:
        _require_text(self.trust_domain, "trust_domain")
        _require_text(self.logical_state_id, "logical_state_id")
        _require_text(self.logical_transition_id, "logical_transition_id")
        if self.to_causal_epoch != self.from_causal_epoch + 1:
            raise ValueError("causal_epoch_gap")
        if self.from_causal_epoch < 0:
            raise ValueError("negative_causal_epoch")
        for field, value in (
            ("from_state_ref_sha256", self.from_state_ref_sha256),
            ("to_state_ref_sha256", self.to_state_ref_sha256),
            ("transition_contract_sha256", self.transition_contract_sha256),
            ("authorization_contract_sha256", self.authorization_contract_sha256),
        ):
            require_sha256(value, field)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": TRANSITION_REF_SCHEMA,
            "trust_domain": self.trust_domain,
            "logical_state_id": self.logical_state_id,
            "logical_transition_id": self.logical_transition_id,
            "from_causal_epoch": self.from_causal_epoch,
            "to_causal_epoch": self.to_causal_epoch,
            "from_state_ref_sha256": self.from_state_ref_sha256,
            "to_state_ref_sha256": self.to_state_ref_sha256,
            "transition_contract_sha256": self.transition_contract_sha256,
            "authorization_contract_sha256": self.authorization_contract_sha256,
        }

    def digest(self) -> str:
        return digest_object(self.to_dict())


def build_transition_ref(
    previous: CausalStateRef,
    next_state: CausalStateRef,
    *,
    logical_transition_id: str,
    transition_contract_sha256: str,
    authorization_contract_sha256: str,
) -> CausalTransitionRef:
    if previous.trust_domain != next_state.trust_domain:
        raise ValueError("transition_trust_domain_mismatch")
    if previous.logical_state_id != next_state.logical_state_id:
        raise ValueError("transition_logical_state_mismatch")
    if next_state.causal_epoch != previous.causal_epoch + 1:
        raise ValueError("causal_epoch_gap")
    if next_state.semantic_state_sha256 == previous.semantic_state_sha256:
        raise ValueError("semantic_state_did_not_change")
    return CausalTransitionRef(
        trust_domain=previous.trust_domain,
        logical_state_id=previous.logical_state_id,
        logical_transition_id=_require_text(
            logical_transition_id, "logical_transition_id"
        ),
        from_causal_epoch=previous.causal_epoch,
        to_causal_epoch=next_state.causal_epoch,
        from_state_ref_sha256=previous.digest(),
        to_state_ref_sha256=next_state.digest(),
        transition_contract_sha256=require_sha256(
            transition_contract_sha256, "transition_contract_sha256"
        ),
        authorization_contract_sha256=require_sha256(
            authorization_contract_sha256, "authorization_contract_sha256"
        ),
    )
