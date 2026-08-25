"""Provider-agnostic portable causal identity and two-parent reconciliation."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

STATE_REF_SCHEMA = "ttrace-portable-state-ref/v0.1"
TRANSITION_REF_SCHEMA = "ttrace-portable-transition-ref/v0.1"
BRANCH_REF_SCHEMA = "ttrace-portable-fork-branch-ref/v0.1"
BRANCH_TIP_SCHEMA = "ttrace-portable-fork-branch-tip/v0.1"
PARENT_SET_SCHEMA = "ttrace-portable-causal-parent-set/v0.1"
RECONCILIATION_REF_SCHEMA = "ttrace-portable-reconciliation-ref/v0.1"
RECONCILIATION_RECEIPT_SCHEMA = "ttrace-portable-reconciliation-receipt/v0.1"
RECONCILIATION_REASON = "portable_causal_reconciliation_verified"
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


class CausalValidationError(ValueError):
    """Portable causal material failed closed."""


@dataclass(frozen=True)
class BranchEvidence:
    verified: bool
    provider_id: str
    authority_id: str
    provenance_sha256: str
    trust_domain: str
    logical_branch_id: str
    from_state_ref_sha256: str
    to_semantic_state_sha256: str
    branch_contract_sha256: str
    authorization_contract_sha256: str


@dataclass(frozen=True)
class ReconciliationVote:
    verified: bool
    provider_id: str
    authority_id: str
    provenance_sha256: str
    trust_domain: str
    logical_reconciliation_id: str
    branch_ref_sha256: str
    branch_state_ref_sha256: str
    branch_tip_sha256: str
    target_semantic_state_sha256: str
    reconciliation_contract_sha256: str
    authorization_contract_sha256: str


@dataclass(frozen=True)
class ReconciliationAgreement:
    verified: bool
    reason: str
    branch_tips: Tuple[Dict[str, Any], ...] = ()
    parent_set: Optional[Dict[str, Any]] = None
    reconciled_state_ref: Optional[Dict[str, Any]] = None
    reconciliation_ref: Optional[Dict[str, Any]] = None
    receipt: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "verified": self.verified,
            "reason": self.reason,
            "branch_tips": list(self.branch_tips),
            "parent_set": self.parent_set,
            "reconciled_state_ref": self.reconciled_state_ref,
            "reconciliation_ref": self.reconciliation_ref,
            "receipt": self.receipt,
        }


def canonical_json_bytes(value: Any) -> bytes:
    """Serialize JSON deterministically for portable identity hashing."""

    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def digest_json(value: Any) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def is_sha256(value: Any) -> bool:
    return isinstance(value, str) and _SHA256_RE.fullmatch(value) is not None


def _text(value: Any) -> bool:
    return isinstance(value, str) and bool(value)


def validate_state_ref(value: Any) -> bool:
    if not isinstance(value, Mapping) or set(value) != {
        "schema",
        "trust_domain",
        "logical_state_id",
        "causal_epoch",
        "semantic_state_sha256",
    }:
        return False
    epoch = value.get("causal_epoch")
    return (
        value.get("schema") == STATE_REF_SCHEMA
        and _text(value.get("trust_domain"))
        and _text(value.get("logical_state_id"))
        and isinstance(epoch, int)
        and not isinstance(epoch, bool)
        and epoch >= 0
        and is_sha256(value.get("semantic_state_sha256"))
    )


def make_state_ref(
    *,
    trust_domain: str,
    logical_state_id: str,
    causal_epoch: int,
    semantic_state_sha256: str,
) -> Dict[str, Any]:
    value = {
        "schema": STATE_REF_SCHEMA,
        "trust_domain": trust_domain,
        "logical_state_id": logical_state_id,
        "causal_epoch": causal_epoch,
        "semantic_state_sha256": semantic_state_sha256,
    }
    if not validate_state_ref(value):
        raise CausalValidationError("state_ref_invalid")
    return value


def build_transition_ref(
    previous_state_ref: Mapping[str, Any],
    *,
    logical_transition_id: str,
    next_semantic_state_sha256: str,
    transition_contract_sha256: str,
    authorization_contract_sha256: str,
) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    if not validate_state_ref(previous_state_ref):
        raise CausalValidationError("previous_state_ref_invalid")
    if not _text(logical_transition_id):
        raise CausalValidationError("logical_transition_id_invalid")
    for name, value in (
        ("next_semantic_state_sha256", next_semantic_state_sha256),
        ("transition_contract_sha256", transition_contract_sha256),
        ("authorization_contract_sha256", authorization_contract_sha256),
    ):
        if not is_sha256(value):
            raise CausalValidationError("%s_invalid" % name)
    if next_semantic_state_sha256 == previous_state_ref["semantic_state_sha256"]:
        raise CausalValidationError("causal_transition_semantic_noop")

    next_state = make_state_ref(
        trust_domain=str(previous_state_ref["trust_domain"]),
        logical_state_id=str(previous_state_ref["logical_state_id"]),
        causal_epoch=int(previous_state_ref["causal_epoch"]) + 1,
        semantic_state_sha256=next_semantic_state_sha256,
    )
    ref = {
        "schema": TRANSITION_REF_SCHEMA,
        "trust_domain": previous_state_ref["trust_domain"],
        "logical_state_id": previous_state_ref["logical_state_id"],
        "logical_transition_id": logical_transition_id,
        "from_causal_epoch": previous_state_ref["causal_epoch"],
        "to_causal_epoch": next_state["causal_epoch"],
        "from_state_ref_sha256": digest_json(previous_state_ref),
        "to_state_ref_sha256": digest_json(next_state),
        "transition_contract_sha256": transition_contract_sha256,
        "authorization_contract_sha256": authorization_contract_sha256,
    }
    if not validate_transition_ref(
        ref,
        previous_state_ref=previous_state_ref,
        next_state_ref=next_state,
    ):
        raise CausalValidationError("transition_ref_invalid")
    return next_state, ref


def validate_transition_ref(
    value: Any,
    *,
    previous_state_ref: Mapping[str, Any],
    next_state_ref: Mapping[str, Any],
) -> bool:
    keys = {
        "schema",
        "trust_domain",
        "logical_state_id",
        "logical_transition_id",
        "from_causal_epoch",
        "to_causal_epoch",
        "from_state_ref_sha256",
        "to_state_ref_sha256",
        "transition_contract_sha256",
        "authorization_contract_sha256",
    }
    if not validate_state_ref(previous_state_ref) or not validate_state_ref(
        next_state_ref
    ):
        return False
    if not isinstance(value, Mapping) or set(value) != keys:
        return False
    return (
        value.get("schema") == TRANSITION_REF_SCHEMA
        and value.get("trust_domain")
        == previous_state_ref["trust_domain"]
        == next_state_ref["trust_domain"]
        and value.get("logical_state_id")
        == previous_state_ref["logical_state_id"]
        == next_state_ref["logical_state_id"]
        and _text(value.get("logical_transition_id"))
        and value.get("from_causal_epoch") == previous_state_ref["causal_epoch"]
        and value.get("to_causal_epoch") == next_state_ref["causal_epoch"]
        and value.get("to_causal_epoch") == value.get("from_causal_epoch") + 1
        and value.get("from_state_ref_sha256") == digest_json(previous_state_ref)
        and value.get("to_state_ref_sha256") == digest_json(next_state_ref)
        and is_sha256(value.get("transition_contract_sha256"))
        and is_sha256(value.get("authorization_contract_sha256"))
        and previous_state_ref["semantic_state_sha256"]
        != next_state_ref["semantic_state_sha256"]
    )


def _valid_branch(value: Any) -> bool:
    return (
        isinstance(value, BranchEvidence)
        and value.verified is True
        and all(
            (
                _text(value.provider_id),
                _text(value.authority_id),
                is_sha256(value.provenance_sha256),
                _text(value.trust_domain),
                _text(value.logical_branch_id),
                is_sha256(value.from_state_ref_sha256),
                is_sha256(value.to_semantic_state_sha256),
                is_sha256(value.branch_contract_sha256),
                is_sha256(value.authorization_contract_sha256),
            )
        )
    )


def _valid_vote(value: Any) -> bool:
    return (
        isinstance(value, ReconciliationVote)
        and value.verified is True
        and all(
            (
                _text(value.provider_id),
                _text(value.authority_id),
                is_sha256(value.provenance_sha256),
                _text(value.trust_domain),
                _text(value.logical_reconciliation_id),
                is_sha256(value.branch_ref_sha256),
                is_sha256(value.branch_state_ref_sha256),
                is_sha256(value.branch_tip_sha256),
                is_sha256(value.target_semantic_state_sha256),
                is_sha256(value.reconciliation_contract_sha256),
                is_sha256(value.authorization_contract_sha256),
            )
        )
    )


def build_branch_tip(
    common_state_ref: Mapping[str, Any], evidence: BranchEvidence
) -> Dict[str, Any]:
    if not validate_state_ref(common_state_ref):
        raise CausalValidationError("common_state_ref_invalid")
    if not _valid_branch(evidence):
        raise CausalValidationError("branch_evidence_invalid")
    if evidence.trust_domain != common_state_ref["trust_domain"]:
        raise CausalValidationError("branch_trust_domain_mismatch")
    if evidence.from_state_ref_sha256 != digest_json(common_state_ref):
        raise CausalValidationError("branch_common_state_mismatch")
    if evidence.to_semantic_state_sha256 == common_state_ref["semantic_state_sha256"]:
        raise CausalValidationError("branch_semantic_noop")

    state = make_state_ref(
        trust_domain=str(common_state_ref["trust_domain"]),
        logical_state_id=str(common_state_ref["logical_state_id"]),
        causal_epoch=int(common_state_ref["causal_epoch"]) + 1,
        semantic_state_sha256=evidence.to_semantic_state_sha256,
    )
    ref = {
        "schema": BRANCH_REF_SCHEMA,
        "trust_domain": common_state_ref["trust_domain"],
        "logical_state_id": common_state_ref["logical_state_id"],
        "logical_branch_id": evidence.logical_branch_id,
        "from_causal_epoch": common_state_ref["causal_epoch"],
        "to_causal_epoch": state["causal_epoch"],
        "from_state_ref_sha256": digest_json(common_state_ref),
        "to_state_ref_sha256": digest_json(state),
        "branch_contract_sha256": evidence.branch_contract_sha256,
        "authorization_contract_sha256": evidence.authorization_contract_sha256,
    }
    tip = {"schema": BRANCH_TIP_SCHEMA, "state_ref": state, "branch_ref": ref}
    if not validate_branch_tip(tip, common_state_ref=common_state_ref):
        raise CausalValidationError("branch_tip_invalid")
    return tip


def validate_branch_tip(
    value: Any, *, common_state_ref: Mapping[str, Any]
) -> bool:
    if not validate_state_ref(common_state_ref) or not isinstance(value, Mapping):
        return False
    if set(value) != {"schema", "state_ref", "branch_ref"}:
        return False
    state = value.get("state_ref")
    ref = value.get("branch_ref")
    keys = {
        "schema",
        "trust_domain",
        "logical_state_id",
        "logical_branch_id",
        "from_causal_epoch",
        "to_causal_epoch",
        "from_state_ref_sha256",
        "to_state_ref_sha256",
        "branch_contract_sha256",
        "authorization_contract_sha256",
    }
    if not validate_state_ref(state) or not isinstance(ref, Mapping) or set(ref) != keys:
        return False
    assert isinstance(state, Mapping)
    return (
        value.get("schema") == BRANCH_TIP_SCHEMA
        and ref.get("schema") == BRANCH_REF_SCHEMA
        and ref.get("trust_domain")
        == common_state_ref["trust_domain"]
        == state["trust_domain"]
        and ref.get("logical_state_id")
        == common_state_ref["logical_state_id"]
        == state["logical_state_id"]
        and _text(ref.get("logical_branch_id"))
        and ref.get("from_causal_epoch") == common_state_ref["causal_epoch"]
        and ref.get("to_causal_epoch") == state["causal_epoch"]
        and ref.get("to_causal_epoch") == ref.get("from_causal_epoch") + 1
        and ref.get("from_state_ref_sha256") == digest_json(common_state_ref)
        and ref.get("to_state_ref_sha256") == digest_json(state)
        and is_sha256(ref.get("branch_contract_sha256"))
        and is_sha256(ref.get("authorization_contract_sha256"))
        and state["semantic_state_sha256"]
        != common_state_ref["semantic_state_sha256"]
    )


def _unique(values: Iterable[str], reason: str) -> None:
    items = list(values)
    if len(items) != len(set(items)):
        raise CausalValidationError(reason)


def _strings(value: Any) -> List[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, Mapping):
        return [text for item in value.values() for text in _strings(item)]
    if isinstance(value, (list, tuple)):
        return [text for item in value for text in _strings(item)]
    return []


def reconcile_two_branches(
    common_state_ref: Mapping[str, Any],
    branches: Sequence[BranchEvidence],
    votes: Sequence[ReconciliationVote],
) -> ReconciliationAgreement:
    try:
        if not validate_state_ref(common_state_ref):
            raise CausalValidationError("common_state_ref_invalid")
        if len(branches) != 2:
            raise CausalValidationError("branch_cardinality_invalid")
        if len(votes) != 2:
            raise CausalValidationError("vote_cardinality_invalid")
        if not all(_valid_branch(item) for item in branches):
            raise CausalValidationError("branch_evidence_invalid")
        if not all(_valid_vote(item) for item in votes):
            raise CausalValidationError("reconciliation_vote_invalid")

        _unique(
            (item.provider_id for item in branches),
            "branch_provider_not_independent",
        )
        _unique(
            (item.authority_id for item in branches),
            "branch_authority_not_independent",
        )
        _unique(
            (item.provenance_sha256 for item in branches),
            "branch_provenance_not_independent",
        )
        _unique(
            (item.logical_branch_id for item in branches),
            "logical_branch_id_duplicate",
        )
        if (
            len({item.trust_domain for item in branches}) != 1
            or branches[0].trust_domain != common_state_ref["trust_domain"]
        ):
            raise CausalValidationError("branch_trust_domain_mismatch")
        if (
            len({item.from_state_ref_sha256 for item in branches}) != 1
            or branches[0].from_state_ref_sha256 != digest_json(common_state_ref)
        ):
            raise CausalValidationError("branch_common_state_mismatch")
        if len({item.branch_contract_sha256 for item in branches}) != 1:
            raise CausalValidationError("branch_contract_mismatch")
        if len({item.authorization_contract_sha256 for item in branches}) != 1:
            raise CausalValidationError("branch_authorization_mismatch")
        if len({item.to_semantic_state_sha256 for item in branches}) != 2:
            raise CausalValidationError("fork_semantics_not_divergent")

        built = [(item, build_branch_tip(common_state_ref, item)) for item in branches]
        by_ref = {
            digest_json(tip["branch_ref"]): (evidence, tip)
            for evidence, tip in built
        }
        if len(by_ref) != 2:
            raise CausalValidationError("branch_ref_duplicate")
        vote_by_ref = {item.branch_ref_sha256: item for item in votes}
        if len(vote_by_ref) != 2:
            raise CausalValidationError("vote_branch_duplicate")
        if set(vote_by_ref) != set(by_ref):
            raise CausalValidationError("vote_branch_set_mismatch")
        _unique(
            (item.provenance_sha256 for item in votes),
            "vote_provenance_not_independent",
        )

        checks = (
            (
                {item.logical_reconciliation_id for item in votes},
                "logical_reconciliation_mismatch",
            ),
            (
                {item.target_semantic_state_sha256 for item in votes},
                "reconciliation_target_mismatch",
            ),
            (
                {item.reconciliation_contract_sha256 for item in votes},
                "reconciliation_contract_mismatch",
            ),
            (
                {item.authorization_contract_sha256 for item in votes},
                "reconciliation_authorization_mismatch",
            ),
            (
                {item.trust_domain for item in votes},
                "reconciliation_trust_domain_mismatch",
            ),
        )
        for values, reason in checks:
            if len(values) != 1:
                raise CausalValidationError(reason)
        if votes[0].trust_domain != common_state_ref["trust_domain"]:
            raise CausalValidationError("reconciliation_trust_domain_mismatch")

        target = votes[0].target_semantic_state_sha256
        excluded_targets = {
            common_state_ref["semantic_state_sha256"],
            *(item.to_semantic_state_sha256 for item in branches),
        }
        if target in excluded_targets:
            raise CausalValidationError("reconciliation_target_not_new")

        for ref_sha, (evidence, tip) in by_ref.items():
            vote = vote_by_ref[ref_sha]
            if vote.provider_id != evidence.provider_id:
                raise CausalValidationError("vote_provider_binding_mismatch")
            if vote.authority_id != evidence.authority_id:
                raise CausalValidationError("vote_authority_binding_mismatch")
            if vote.branch_state_ref_sha256 != digest_json(tip["state_ref"]):
                raise CausalValidationError("vote_branch_state_binding_mismatch")
            if vote.branch_tip_sha256 != digest_json(tip):
                raise CausalValidationError("vote_branch_tip_binding_mismatch")

        tips = sorted((tip for _, tip in built), key=digest_json)
        parents = [
            {
                "branch_tip_sha256": digest_json(tip),
                "branch_ref_sha256": digest_json(tip["branch_ref"]),
                "state_ref_sha256": digest_json(tip["state_ref"]),
            }
            for tip in tips
        ]
        if len({item["branch_tip_sha256"] for item in parents}) != 2:
            raise CausalValidationError("reconciliation_parent_duplicate")
        parent_set = {"schema": PARENT_SET_SCHEMA, "parents": parents}

        result_state = make_state_ref(
            trust_domain=str(common_state_ref["trust_domain"]),
            logical_state_id=str(common_state_ref["logical_state_id"]),
            causal_epoch=int(common_state_ref["causal_epoch"]) + 2,
            semantic_state_sha256=target,
        )
        ref = {
            "schema": RECONCILIATION_REF_SCHEMA,
            "trust_domain": common_state_ref["trust_domain"],
            "logical_state_id": common_state_ref["logical_state_id"],
            "logical_reconciliation_id": votes[0].logical_reconciliation_id,
            "common_state_ref_sha256": digest_json(common_state_ref),
            "fork_causal_epoch": int(common_state_ref["causal_epoch"]) + 1,
            "reconciled_causal_epoch": result_state["causal_epoch"],
            "parent_set_sha256": digest_json(parent_set),
            "parent_tip_sha256": [item["branch_tip_sha256"] for item in parents],
            "result_state_ref_sha256": digest_json(result_state),
            "reconciliation_contract_sha256": votes[0].reconciliation_contract_sha256,
            "authorization_contract_sha256": votes[0].authorization_contract_sha256,
        }
        portable = {
            "branch_tips": tips,
            "parent_set": parent_set,
            "reconciled_state_ref": result_state,
            "reconciliation_ref": ref,
        }
        forbidden = {
            *(item.provider_id for item in branches),
            *(item.authority_id for item in branches),
            *(item.provenance_sha256 for item in branches),
            *(item.provenance_sha256 for item in votes),
        }
        if forbidden & set(_strings(portable)):
            raise CausalValidationError("raw_evidence_embedded")

        receipt = {
            "schema": RECONCILIATION_RECEIPT_SCHEMA,
            "verified": True,
            "reason": RECONCILIATION_REASON,
            "common_state_ref_sha256": digest_json(common_state_ref),
            "fork_causal_epoch": int(common_state_ref["causal_epoch"]) + 1,
            "reconciled_causal_epoch": result_state["causal_epoch"],
            "lineage_parent_count": 2,
            "both_lineages_preserved": True,
            "fork_semantics_divergent": True,
            "branch_order_canonical": True,
            "raw_evidence_embedded": False,
            "parent_set_sha256": digest_json(parent_set),
            "result_state_ref_sha256": digest_json(result_state),
            "reconciliation_ref_sha256": digest_json(ref),
        }
        agreement = ReconciliationAgreement(
            True,
            RECONCILIATION_REASON,
            tuple(tips),
            parent_set,
            result_state,
            ref,
            receipt,
        )
        if not validate_reconciliation_agreement(agreement, common_state_ref):
            raise CausalValidationError("reconciliation_agreement_invalid")
        return agreement
    except CausalValidationError as error:
        return ReconciliationAgreement(False, str(error))


def validate_reconciliation_agreement(
    agreement: ReconciliationAgreement,
    common_state_ref: Mapping[str, Any],
) -> bool:
    """Recompute all portable fork and reconciliation invariants.

    This function intentionally does not trust the receipt's booleans. It derives
    parent uniqueness, branch divergence, target freshness, canonical ordering,
    and every digest binding from the portable objects themselves.
    """

    if (
        not isinstance(agreement, ReconciliationAgreement)
        or not agreement.verified
        or agreement.reason != RECONCILIATION_REASON
        or not validate_state_ref(common_state_ref)
    ):
        return False

    tips = agreement.branch_tips
    if len(tips) != 2:
        return False
    if not all(
        validate_branch_tip(tip, common_state_ref=common_state_ref) for tip in tips
    ):
        return False
    if list(tips) != sorted(tips, key=digest_json):
        return False

    tip_digests = [digest_json(tip) for tip in tips]
    branch_ref_digests = [digest_json(tip["branch_ref"]) for tip in tips]
    state_ref_digests = [digest_json(tip["state_ref"]) for tip in tips]
    logical_branch_ids = [tip["branch_ref"]["logical_branch_id"] for tip in tips]
    semantic_states = [tip["state_ref"]["semantic_state_sha256"] for tip in tips]
    if any(
        len(set(values)) != 2
        for values in (
            tip_digests,
            branch_ref_digests,
            state_ref_digests,
            logical_branch_ids,
            semantic_states,
        )
    ):
        return False
    if common_state_ref["semantic_state_sha256"] in semantic_states:
        return False
    if len({tip["branch_ref"]["branch_contract_sha256"] for tip in tips}) != 1:
        return False
    if (
        len(
            {
                tip["branch_ref"]["authorization_contract_sha256"]
                for tip in tips
            }
        )
        != 1
    ):
        return False

    parent_set = agreement.parent_set
    if (
        not isinstance(parent_set, Mapping)
        or set(parent_set) != {"schema", "parents"}
        or parent_set.get("schema") != PARENT_SET_SCHEMA
    ):
        return False
    parents = parent_set.get("parents")
    expected_parents = [
        {
            "branch_tip_sha256": digest_json(tip),
            "branch_ref_sha256": digest_json(tip["branch_ref"]),
            "state_ref_sha256": digest_json(tip["state_ref"]),
        }
        for tip in tips
    ]
    if parents != expected_parents:
        return False
    if not isinstance(parents, list) or len(parents) != 2:
        return False
    if any(
        len({parent[key] for parent in parents}) != 2
        for key in (
            "branch_tip_sha256",
            "branch_ref_sha256",
            "state_ref_sha256",
        )
    ):
        return False

    result_state = agreement.reconciled_state_ref
    if not validate_state_ref(result_state):
        return False
    assert isinstance(result_state, Mapping)
    if (
        result_state["trust_domain"] != common_state_ref["trust_domain"]
        or result_state["logical_state_id"] != common_state_ref["logical_state_id"]
        or result_state["causal_epoch"] != common_state_ref["causal_epoch"] + 2
        or result_state["semantic_state_sha256"]
        in {common_state_ref["semantic_state_sha256"], *semantic_states}
    ):
        return False

    ref = agreement.reconciliation_ref
    ref_keys = {
        "schema",
        "trust_domain",
        "logical_state_id",
        "logical_reconciliation_id",
        "common_state_ref_sha256",
        "fork_causal_epoch",
        "reconciled_causal_epoch",
        "parent_set_sha256",
        "parent_tip_sha256",
        "result_state_ref_sha256",
        "reconciliation_contract_sha256",
        "authorization_contract_sha256",
    }
    if not isinstance(ref, Mapping) or set(ref) != ref_keys:
        return False
    if not (
        ref.get("schema") == RECONCILIATION_REF_SCHEMA
        and ref.get("trust_domain") == common_state_ref["trust_domain"]
        and ref.get("logical_state_id") == common_state_ref["logical_state_id"]
        and _text(ref.get("logical_reconciliation_id"))
        and ref.get("common_state_ref_sha256") == digest_json(common_state_ref)
        and ref.get("fork_causal_epoch") == common_state_ref["causal_epoch"] + 1
        and ref.get("reconciled_causal_epoch") == result_state["causal_epoch"]
        and ref.get("parent_set_sha256") == digest_json(parent_set)
        and ref.get("parent_tip_sha256")
        == [parent["branch_tip_sha256"] for parent in expected_parents]
        and ref.get("result_state_ref_sha256") == digest_json(result_state)
        and is_sha256(ref.get("reconciliation_contract_sha256"))
        and is_sha256(ref.get("authorization_contract_sha256"))
    ):
        return False

    receipt = agreement.receipt
    receipt_keys = {
        "schema",
        "verified",
        "reason",
        "common_state_ref_sha256",
        "fork_causal_epoch",
        "reconciled_causal_epoch",
        "lineage_parent_count",
        "both_lineages_preserved",
        "fork_semantics_divergent",
        "branch_order_canonical",
        "raw_evidence_embedded",
        "parent_set_sha256",
        "result_state_ref_sha256",
        "reconciliation_ref_sha256",
    }
    return isinstance(receipt, Mapping) and set(receipt) == receipt_keys and (
        receipt.get("schema") == RECONCILIATION_RECEIPT_SCHEMA
        and receipt.get("verified") is True
        and receipt.get("reason") == RECONCILIATION_REASON
        and receipt.get("common_state_ref_sha256") == digest_json(common_state_ref)
        and receipt.get("fork_causal_epoch") == common_state_ref["causal_epoch"] + 1
        and receipt.get("reconciled_causal_epoch") == result_state["causal_epoch"]
        and receipt.get("lineage_parent_count") == len(parents)
        and receipt.get("both_lineages_preserved") is True
        and receipt.get("fork_semantics_divergent") is True
        and receipt.get("branch_order_canonical") is True
        and receipt.get("raw_evidence_embedded") is False
        and receipt.get("parent_set_sha256") == digest_json(parent_set)
        and receipt.get("result_state_ref_sha256") == digest_json(result_state)
        and receipt.get("reconciliation_ref_sha256") == digest_json(ref)
    )
