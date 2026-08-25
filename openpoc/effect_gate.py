from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any


def _canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


@dataclass(frozen=True)
class Effect:
    """A simplified real-world effect produced by an agent tool call."""

    effect_id: str
    action: str
    target: str
    payload: dict[str, Any]

    @property
    def digest(self) -> str:
        envelope = {
            "effect_id": self.effect_id,
            "action": self.action,
            "target": self.target,
            "payload": self.payload,
        }
        return hashlib.sha256(_canonical_json(envelope)).hexdigest()


@dataclass(frozen=True)
class Precommitment:
    token: str
    effect_id: str
    effect_digest: str


@dataclass(frozen=True)
class Receipt:
    receipt_id: str
    effect_id: str
    effect_digest: str
    precommitment_token: str
    status: str = "applied"


class EffectBlocked(RuntimeError):
    """Raised when an effect reaches the gate without valid prior evidence."""


class Recorder:
    """Minimal recorder for precommitments and post-effect receipts.

    This class is deliberately not a production cryptographic signer. It models
    the ordering requirement under test: evidence must enter the path before the
    effect can occur.
    """

    def __init__(self) -> None:
        self._precommitments: dict[str, Precommitment] = {}
        self._receipts: dict[str, Receipt] = {}

    def precommit(self, effect: Effect) -> Precommitment:
        token_material = f"precommit:{effect.effect_id}:{effect.digest}".encode("utf-8")
        token = hashlib.sha256(token_material).hexdigest()
        precommitment = Precommitment(
            token=token,
            effect_id=effect.effect_id,
            effect_digest=effect.digest,
        )
        self._precommitments[token] = precommitment
        return precommitment

    def is_valid_precommitment(
        self,
        effect: Effect,
        precommitment: Precommitment | None,
    ) -> bool:
        if precommitment is None:
            return False
        stored = self._precommitments.get(precommitment.token)
        return (
            stored == precommitment
            and precommitment.effect_id == effect.effect_id
            and precommitment.effect_digest == effect.digest
        )

    def finalize(self, effect: Effect, precommitment: Precommitment) -> Receipt:
        if not self.is_valid_precommitment(effect, precommitment):
            raise EffectBlocked("effect is not bound to a valid precommitment")

        receipt_material = (
            f"receipt:{precommitment.token}:{effect.effect_id}:{effect.digest}"
        ).encode("utf-8")
        receipt = Receipt(
            receipt_id=hashlib.sha256(receipt_material).hexdigest(),
            effect_id=effect.effect_id,
            effect_digest=effect.digest,
            precommitment_token=precommitment.token,
        )
        self._receipts[effect.effect_id] = receipt
        return receipt

    @property
    def receipt_effect_ids(self) -> set[str]:
        return set(self._receipts)

    @property
    def precommitted_effect_ids(self) -> set[str]:
        return {item.effect_id for item in self._precommitments.values()}


class EffectStore:
    """A tiny stand-in for an external system changed by an agent action."""

    def __init__(self) -> None:
        self._effects: dict[str, Effect] = {}

    def apply(self, effect: Effect) -> None:
        if effect.effect_id in self._effects:
            raise ValueError(f"effect '{effect.effect_id}' already applied")
        self._effects[effect.effect_id] = effect

    @property
    def effect_ids(self) -> set[str]:
        return set(self._effects)


class EffectGate:
    """Effect point that requires a recorder precommitment before execution."""

    def __init__(self, store: EffectStore, recorder: Recorder) -> None:
        self._store = store
        self._recorder = recorder

    def execute(
        self,
        effect: Effect,
        precommitment: Precommitment | None,
    ) -> Receipt:
        if not self._recorder.is_valid_precommitment(effect, precommitment):
            raise EffectBlocked("effect blocked: valid precommitment required")

        assert precommitment is not None
        self._store.apply(effect)
        return self._recorder.finalize(effect, precommitment)


class BypassableRuntime:
    """Demonstrates the deployment failure: direct access around the gate."""

    def __init__(self, store: EffectStore, recorder: Recorder) -> None:
        self.store = store
        self.recorder = recorder
        self.gate = EffectGate(store=store, recorder=recorder)

    def execute_via_gate(self, effect: Effect) -> Receipt:
        precommitment = self.recorder.precommit(effect)
        return self.gate.execute(effect, precommitment)

    def execute_bypass(self, effect: Effect) -> None:
        """Apply an effect without producing recorder evidence.

        This method is intentionally present only to make the falsification
        fixture explicit. A production L3 deployment must make this path
        impossible, not merely discourage it.
        """

        self.store.apply(effect)
