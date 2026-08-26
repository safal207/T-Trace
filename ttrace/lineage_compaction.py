"""Fixed-shape lineage commitments for repeated fork/reconciliation cycles.

Complete proof material remains external. The active causal tip carries a rolling
accumulator with a constant field set. Its root commits the current portable
reconciliation, the previous accumulator, and the previous lineage root.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Mapping, Optional, Sequence

from .portable_causality import (
    BranchEvidence,
    ReconciliationAgreement,
    ReconciliationVote,
    canonical_json_bytes,
    digest_json,
    is_sha256,
    reconcile_two_branches,
    validate_reconciliation_agreement,
    validate_state_ref,
)

LINEAGE_ACCUMULATOR_SCHEMA = "ttrace-lineage-accumulator-ref/v0.1"
LINEAGE_CYCLE_SUMMARY_SCHEMA = "ttrace-lineage-cycle-summary/v0.1"
LINEAGE_ROOT_STEP_SCHEMA = "ttrace-lineage-root-step/v0.1"
LINEAGE_COMPACTION_RECEIPT_SCHEMA = "ttrace-lineage-compaction-receipt/v0.1"
LINEAGE_COMPACTION_REASON = "repeated_fork_lineage_compaction_verified"
ZERO_SHA256 = "0" * 64

_ACCUMULATOR_KEYS = {
    "schema",
    "trust_domain",
    "logical_state_id",
    "completed_reconciliation_cycles",
    "current_causal_epoch",
    "current_state_ref_sha256",
    "current_reconciliation_sha256",
    "previous_accumulator_sha256",
    "previous_lineage_root_sha256",
    "cycle_commitment_sha256",
    "lineage_root_sha256",
    "accumulator_contract_sha256",
    "authorization_contract_sha256",
}

_RECEIPT_KEYS = {
    "schema",
    "verified",
    "reason",
    "previous_reconciliation_cycles",
    "completed_reconciliation_cycles",
    "common_causal_epoch",
    "fork_causal_epoch",
    "reconciled_causal_epoch",
    "previous_accumulator_sha256",
    "previous_lineage_root_sha256",
    "cycle_commitment_sha256",
    "lineage_root_sha256",
    "lineage_accumulator_sha256",
    "active_state_ref_sha256",
    "active_reconciliation_sha256",
    "accumulator_field_count",
    "accumulator_shape_stable",
    "both_current_lineages_preserved",
    "previous_lineage_committed",
    "raw_ancestry_embedded",
    "raw_provider_evidence_embedded",
}


@dataclass(frozen=True)
class LineageCompactionAgreement:
    verified: bool
    reason: str
    reconciliation: Optional[ReconciliationAgreement] = None
    lineage_accumulator: Optional[Dict[str, Any]] = None
    receipt: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "verified": self.verified,
            "reason": self.reason,
            "reconciliation": (
                self.reconciliation.to_dict()
                if self.reconciliation is not None
                else None
            ),
            "lineage_accumulator": self.lineage_accumulator,
            "receipt": self.receipt,
        }


def _text(value: Any) -> bool:
    return isinstance(value, str) and bool(value)


def _cycle_summary(
    cycle_index: int,
    common_state_ref: Mapping[str, Any],
    reconciliation: ReconciliationAgreement,
) -> Dict[str, Any]:
    if not validate_reconciliation_agreement(reconciliation, common_state_ref):
        raise ValueError("reconciliation_agreement_invalid")
    if not isinstance(cycle_index, int) or isinstance(cycle_index, bool) or cycle_index < 1:
        raise ValueError("lineage_cycle_count_invalid")

    assert reconciliation.parent_set is not None
    assert reconciliation.reconciled_state_ref is not None
    assert reconciliation.reconciliation_ref is not None
    assert reconciliation.receipt is not None

    return {
        "schema": LINEAGE_CYCLE_SUMMARY_SCHEMA,
        "cycle_index": cycle_index,
        "common_state_ref_sha256": digest_json(common_state_ref),
        "fork_causal_epoch": reconciliation.receipt["fork_causal_epoch"],
        "reconciled_causal_epoch": reconciliation.receipt[
            "reconciled_causal_epoch"
        ],
        "branch_tip_set_sha256": digest_json(
            [digest_json(tip) for tip in reconciliation.branch_tips]
        ),
        "parent_set_sha256": digest_json(reconciliation.parent_set),
        "reconciliation_ref_sha256": digest_json(
            reconciliation.reconciliation_ref
        ),
        "result_state_ref_sha256": digest_json(
            reconciliation.reconciled_state_ref
        ),
        "receipt_sha256": digest_json(reconciliation.receipt),
        "reconciliation_contract_sha256": reconciliation.reconciliation_ref[
            "reconciliation_contract_sha256"
        ],
        "authorization_contract_sha256": reconciliation.reconciliation_ref[
            "authorization_contract_sha256"
        ],
    }


def _lineage_root(
    trust_domain: str,
    logical_state_id: str,
    completed_reconciliation_cycles: int,
    current_causal_epoch: int,
    current_state_ref_sha256: str,
    current_reconciliation_sha256: str,
    previous_accumulator_sha256: str,
    previous_lineage_root_sha256: str,
    cycle_commitment_sha256: str,
    accumulator_contract_sha256: str,
    authorization_contract_sha256: str,
) -> str:
    if not _text(trust_domain) or not _text(logical_state_id):
        raise ValueError("lineage_identity_invalid")
    if (
        not isinstance(completed_reconciliation_cycles, int)
        or isinstance(completed_reconciliation_cycles, bool)
        or completed_reconciliation_cycles < 1
    ):
        raise ValueError("lineage_cycle_count_invalid")
    if (
        not isinstance(current_causal_epoch, int)
        or isinstance(current_causal_epoch, bool)
        or current_causal_epoch < 0
    ):
        raise ValueError("lineage_epoch_invalid")
    digests = (
        current_state_ref_sha256,
        current_reconciliation_sha256,
        previous_accumulator_sha256,
        previous_lineage_root_sha256,
        cycle_commitment_sha256,
        accumulator_contract_sha256,
        authorization_contract_sha256,
    )
    if not all(is_sha256(item) for item in digests):
        raise ValueError("lineage_root_input_invalid")

    return digest_json(
        {
            "schema": LINEAGE_ROOT_STEP_SCHEMA,
            "trust_domain": trust_domain,
            "logical_state_id": logical_state_id,
            "completed_reconciliation_cycles": completed_reconciliation_cycles,
            "current_causal_epoch": current_causal_epoch,
            "current_state_ref_sha256": current_state_ref_sha256,
            "current_reconciliation_sha256": current_reconciliation_sha256,
            "previous_accumulator_sha256": previous_accumulator_sha256,
            "previous_lineage_root_sha256": previous_lineage_root_sha256,
            "cycle_commitment_sha256": cycle_commitment_sha256,
            "accumulator_contract_sha256": accumulator_contract_sha256,
            "authorization_contract_sha256": authorization_contract_sha256,
        }
    )


def _build_accumulator(
    common_state_ref: Mapping[str, Any],
    reconciliation: ReconciliationAgreement,
    cycle_index: int,
    previous_accumulator_sha256: str,
    previous_lineage_root_sha256: str,
    accumulator_contract_sha256: str,
    authorization_contract_sha256: str,
) -> Dict[str, Any]:
    if not validate_reconciliation_agreement(reconciliation, common_state_ref):
        raise ValueError("reconciliation_agreement_invalid")
    if not is_sha256(accumulator_contract_sha256):
        raise ValueError("accumulator_contract_invalid")
    if not is_sha256(authorization_contract_sha256):
        raise ValueError("accumulator_authorization_invalid")

    assert reconciliation.reconciled_state_ref is not None
    cycle_commitment = digest_json(
        _cycle_summary(cycle_index, common_state_ref, reconciliation)
    )
    accumulator: Dict[str, Any] = {
        "schema": LINEAGE_ACCUMULATOR_SCHEMA,
        "trust_domain": reconciliation.reconciled_state_ref["trust_domain"],
        "logical_state_id": reconciliation.reconciled_state_ref[
            "logical_state_id"
        ],
        "completed_reconciliation_cycles": cycle_index,
        "current_causal_epoch": reconciliation.reconciled_state_ref["causal_epoch"],
        "current_state_ref_sha256": digest_json(
            reconciliation.reconciled_state_ref
        ),
        "current_reconciliation_sha256": digest_json(reconciliation.to_dict()),
        "previous_accumulator_sha256": previous_accumulator_sha256,
        "previous_lineage_root_sha256": previous_lineage_root_sha256,
        "cycle_commitment_sha256": cycle_commitment,
        "lineage_root_sha256": ZERO_SHA256,
        "accumulator_contract_sha256": accumulator_contract_sha256,
        "authorization_contract_sha256": authorization_contract_sha256,
    }
    accumulator["lineage_root_sha256"] = _lineage_root(
        str(accumulator["trust_domain"]),
        str(accumulator["logical_state_id"]),
        int(accumulator["completed_reconciliation_cycles"]),
        int(accumulator["current_causal_epoch"]),
        str(accumulator["current_state_ref_sha256"]),
        str(accumulator["current_reconciliation_sha256"]),
        str(accumulator["previous_accumulator_sha256"]),
        str(accumulator["previous_lineage_root_sha256"]),
        str(accumulator["cycle_commitment_sha256"]),
        str(accumulator["accumulator_contract_sha256"]),
        str(accumulator["authorization_contract_sha256"]),
    )
    if not validate_lineage_accumulator(accumulator):
        raise ValueError("lineage_accumulator_invalid")
    return accumulator


def validate_lineage_accumulator(value: Any) -> bool:
    """Validate exact shape and the rolling root equation."""

    if not isinstance(value, Mapping) or set(value) != _ACCUMULATOR_KEYS:
        return False
    cycles = value.get("completed_reconciliation_cycles")
    epoch = value.get("current_causal_epoch")
    if (
        value.get("schema") != LINEAGE_ACCUMULATOR_SCHEMA
        or not _text(value.get("trust_domain"))
        or not _text(value.get("logical_state_id"))
        or not isinstance(cycles, int)
        or isinstance(cycles, bool)
        or cycles < 1
        or not isinstance(epoch, int)
        or isinstance(epoch, bool)
        or epoch < 0
    ):
        return False

    digest_fields = (
        "current_state_ref_sha256",
        "current_reconciliation_sha256",
        "previous_accumulator_sha256",
        "previous_lineage_root_sha256",
        "cycle_commitment_sha256",
        "lineage_root_sha256",
        "accumulator_contract_sha256",
        "authorization_contract_sha256",
    )
    if not all(is_sha256(value.get(field)) for field in digest_fields):
        return False
    if any(
        value.get(field) == ZERO_SHA256
        for field in (
            "current_state_ref_sha256",
            "current_reconciliation_sha256",
            "cycle_commitment_sha256",
            "lineage_root_sha256",
            "accumulator_contract_sha256",
            "authorization_contract_sha256",
        )
    ):
        return False
    if cycles == 1 and (
        value.get("previous_accumulator_sha256") != ZERO_SHA256
        or value.get("previous_lineage_root_sha256") != ZERO_SHA256
    ):
        return False
    if cycles > 1 and (
        value.get("previous_accumulator_sha256") == ZERO_SHA256
        or value.get("previous_lineage_root_sha256") == ZERO_SHA256
    ):
        return False

    try:
        expected = _lineage_root(
            str(value["trust_domain"]),
            str(value["logical_state_id"]),
            int(cycles),
            int(epoch),
            str(value["current_state_ref_sha256"]),
            str(value["current_reconciliation_sha256"]),
            str(value["previous_accumulator_sha256"]),
            str(value["previous_lineage_root_sha256"]),
            str(value["cycle_commitment_sha256"]),
            str(value["accumulator_contract_sha256"]),
            str(value["authorization_contract_sha256"]),
        )
    except (KeyError, TypeError, ValueError):
        return False
    return value.get("lineage_root_sha256") == expected


def build_seed_lineage_accumulator(
    common_state_ref: Mapping[str, Any],
    reconciliation: ReconciliationAgreement,
    *,
    accumulator_contract_sha256: str,
    authorization_contract_sha256: str,
) -> Dict[str, Any]:
    """Compact the first verified reconciliation into a fixed-shape seed."""

    return _build_accumulator(
        common_state_ref,
        reconciliation,
        1,
        ZERO_SHA256,
        ZERO_SHA256,
        accumulator_contract_sha256,
        authorization_contract_sha256,
    )


def validate_active_lineage_tip(
    accumulator: Mapping[str, Any],
    common_state_ref: Mapping[str, Any],
    reconciliation: ReconciliationAgreement,
) -> bool:
    """Bind an accumulator to a fully revalidated active reconciliation tip."""

    if not validate_reconciliation_agreement(reconciliation, common_state_ref):
        return False
    state_ref = reconciliation.reconciled_state_ref
    if not isinstance(state_ref, Mapping):
        return False
    return (
        validate_lineage_accumulator(accumulator)
        and accumulator.get("trust_domain") == state_ref.get("trust_domain")
        and accumulator.get("logical_state_id") == state_ref.get("logical_state_id")
        and accumulator.get("current_causal_epoch") == state_ref.get("causal_epoch")
        and accumulator.get("current_state_ref_sha256") == digest_json(state_ref)
        and accumulator.get("current_reconciliation_sha256")
        == digest_json(reconciliation.to_dict())
    )


def _build_receipt(
    previous_accumulator: Mapping[str, Any],
    common_state_ref: Mapping[str, Any],
    reconciliation: ReconciliationAgreement,
    accumulator: Mapping[str, Any],
) -> Dict[str, Any]:
    assert reconciliation.receipt is not None
    return {
        "schema": LINEAGE_COMPACTION_RECEIPT_SCHEMA,
        "verified": True,
        "reason": LINEAGE_COMPACTION_REASON,
        "previous_reconciliation_cycles": previous_accumulator[
            "completed_reconciliation_cycles"
        ],
        "completed_reconciliation_cycles": accumulator[
            "completed_reconciliation_cycles"
        ],
        "common_causal_epoch": common_state_ref["causal_epoch"],
        "fork_causal_epoch": reconciliation.receipt["fork_causal_epoch"],
        "reconciled_causal_epoch": reconciliation.receipt[
            "reconciled_causal_epoch"
        ],
        "previous_accumulator_sha256": digest_json(previous_accumulator),
        "previous_lineage_root_sha256": previous_accumulator[
            "lineage_root_sha256"
        ],
        "cycle_commitment_sha256": accumulator["cycle_commitment_sha256"],
        "lineage_root_sha256": accumulator["lineage_root_sha256"],
        "lineage_accumulator_sha256": digest_json(accumulator),
        "active_state_ref_sha256": accumulator["current_state_ref_sha256"],
        "active_reconciliation_sha256": accumulator[
            "current_reconciliation_sha256"
        ],
        "accumulator_field_count": len(accumulator),
        "accumulator_shape_stable": set(previous_accumulator) == set(accumulator),
        "both_current_lineages_preserved": reconciliation.receipt[
            "both_lineages_preserved"
        ],
        "previous_lineage_committed": True,
        "raw_ancestry_embedded": False,
        "raw_provider_evidence_embedded": False,
    }


def validate_lineage_compaction(
    *,
    previous_accumulator: Mapping[str, Any],
    common_state_ref: Mapping[str, Any],
    reconciliation: ReconciliationAgreement,
    lineage_accumulator: Mapping[str, Any],
    receipt: Mapping[str, Any],
) -> bool:
    """Recompute one incremental reconciliation and rolling commitment."""

    if not validate_lineage_accumulator(previous_accumulator):
        return False
    if not validate_reconciliation_agreement(reconciliation, common_state_ref):
        return False
    if previous_accumulator.get("current_state_ref_sha256") != digest_json(
        common_state_ref
    ):
        return False
    if previous_accumulator.get("trust_domain") != common_state_ref.get(
        "trust_domain"
    ):
        return False
    if previous_accumulator.get("logical_state_id") != common_state_ref.get(
        "logical_state_id"
    ):
        return False

    try:
        expected = _build_accumulator(
            common_state_ref,
            reconciliation,
            int(previous_accumulator["completed_reconciliation_cycles"]) + 1,
            digest_json(previous_accumulator),
            str(previous_accumulator["lineage_root_sha256"]),
            str(previous_accumulator["accumulator_contract_sha256"]),
            str(previous_accumulator["authorization_contract_sha256"]),
        )
    except (KeyError, TypeError, ValueError):
        return False
    if canonical_json_bytes(expected) != canonical_json_bytes(lineage_accumulator):
        return False

    expected_receipt = _build_receipt(
        previous_accumulator,
        common_state_ref,
        reconciliation,
        lineage_accumulator,
    )
    return (
        isinstance(receipt, Mapping)
        and set(receipt) == _RECEIPT_KEYS
        and canonical_json_bytes(receipt) == canonical_json_bytes(expected_receipt)
    )


def advance_lineage_accumulator(
    *,
    previous_accumulator: Mapping[str, Any],
    common_state_ref: Mapping[str, Any],
    branches: Sequence[BranchEvidence],
    votes: Sequence[ReconciliationVote],
) -> LineageCompactionAgreement:
    """Reconcile one new fork and advance the fixed-shape lineage root."""

    if not validate_lineage_accumulator(previous_accumulator):
        return LineageCompactionAgreement(
            False, "previous_lineage_accumulator_invalid"
        )
    if not validate_state_ref(common_state_ref):
        return LineageCompactionAgreement(False, "common_state_ref_invalid")
    if previous_accumulator.get("current_state_ref_sha256") != digest_json(
        common_state_ref
    ):
        return LineageCompactionAgreement(False, "compacted_common_state_mismatch")
    if (
        previous_accumulator.get("trust_domain")
        != common_state_ref.get("trust_domain")
        or previous_accumulator.get("logical_state_id")
        != common_state_ref.get("logical_state_id")
    ):
        return LineageCompactionAgreement(
            False, "compacted_common_identity_mismatch"
        )

    reconciliation = reconcile_two_branches(common_state_ref, branches, votes)
    if not reconciliation.verified:
        return LineageCompactionAgreement(False, reconciliation.reason)

    try:
        accumulator = _build_accumulator(
            common_state_ref,
            reconciliation,
            int(previous_accumulator["completed_reconciliation_cycles"]) + 1,
            digest_json(previous_accumulator),
            str(previous_accumulator["lineage_root_sha256"]),
            str(previous_accumulator["accumulator_contract_sha256"]),
            str(previous_accumulator["authorization_contract_sha256"]),
        )
        receipt = _build_receipt(
            previous_accumulator,
            common_state_ref,
            reconciliation,
            accumulator,
        )
    except (KeyError, TypeError, ValueError) as error:
        return LineageCompactionAgreement(False, str(error))

    if not validate_lineage_compaction(
        previous_accumulator=previous_accumulator,
        common_state_ref=common_state_ref,
        reconciliation=reconciliation,
        lineage_accumulator=accumulator,
        receipt=receipt,
    ):
        return LineageCompactionAgreement(
            False, "lineage_compaction_validation_failed"
        )

    forbidden = {
        *(branch.provider_id for branch in branches),
        *(branch.authority_id for branch in branches),
        *(branch.provenance_sha256 for branch in branches),
        *(vote.provenance_sha256 for vote in votes),
    }
    portable = canonical_json_bytes(
        {
            "reconciliation": reconciliation.to_dict(),
            "lineage_accumulator": accumulator,
            "receipt": receipt,
        }
    ).decode("utf-8")
    if any(value in portable for value in forbidden):
        return LineageCompactionAgreement(False, "raw_evidence_dependency")

    return LineageCompactionAgreement(
        True,
        LINEAGE_COMPACTION_REASON,
        reconciliation,
        accumulator,
        receipt,
    )
