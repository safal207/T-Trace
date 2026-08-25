"""Portable semantic state identity for T-Trace."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from ttrace.canonical import digest_object, require_sha256

STATE_REF_SCHEMA = "ttrace-causal-state-ref/v0.1"
_STATE_KEYS = {
    "schema",
    "trust_domain",
    "logical_state_id",
    "causal_epoch",
    "semantic_state_sha256",
}


def _require_text(value: object, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"invalid_text:{field}")
    return value


@dataclass(frozen=True)
class CausalStateRef:
    """History-free identity of one semantic state at one causal epoch."""

    trust_domain: str
    logical_state_id: str
    causal_epoch: int
    semantic_state_sha256: str

    def __post_init__(self) -> None:
        _require_text(self.trust_domain, "trust_domain")
        _require_text(self.logical_state_id, "logical_state_id")
        if isinstance(self.causal_epoch, bool) or not isinstance(self.causal_epoch, int):
            raise ValueError("invalid_causal_epoch")
        if self.causal_epoch < 0:
            raise ValueError("negative_causal_epoch")
        require_sha256(self.semantic_state_sha256, "semantic_state_sha256")

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": STATE_REF_SCHEMA,
            "trust_domain": self.trust_domain,
            "logical_state_id": self.logical_state_id,
            "causal_epoch": self.causal_epoch,
            "semantic_state_sha256": self.semantic_state_sha256,
        }

    def digest(self) -> str:
        return digest_object(self.to_dict())

    @classmethod
    def from_dict(cls, value: object) -> "CausalStateRef":
        if not isinstance(value, dict) or set(value) != _STATE_KEYS:
            raise ValueError("causal_state_ref_shape_invalid")
        if value.get("schema") != STATE_REF_SCHEMA:
            raise ValueError("causal_state_ref_schema_invalid")
        return cls(
            trust_domain=_require_text(value.get("trust_domain"), "trust_domain"),
            logical_state_id=_require_text(
                value.get("logical_state_id"), "logical_state_id"
            ),
            causal_epoch=value.get("causal_epoch"),
            semantic_state_sha256=require_sha256(
                value.get("semantic_state_sha256"), "semantic_state_sha256"
            ),
        )


def advance_state(
    previous: CausalStateRef,
    *,
    semantic_state_sha256: str,
) -> CausalStateRef:
    """Advance one portable causal epoch to a different semantic state."""

    require_sha256(semantic_state_sha256, "semantic_state_sha256")
    if semantic_state_sha256 == previous.semantic_state_sha256:
        raise ValueError("semantic_state_did_not_change")
    return CausalStateRef(
        trust_domain=previous.trust_domain,
        logical_state_id=previous.logical_state_id,
        causal_epoch=previous.causal_epoch + 1,
        semantic_state_sha256=semantic_state_sha256,
    )
