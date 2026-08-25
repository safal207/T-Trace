"""Reference helpers for optional T-Trace profiles."""

from .portable_causality import (
    BranchEvidence,
    CausalValidationError,
    ReconciliationAgreement,
    ReconciliationVote,
    build_branch_tip,
    build_transition_ref,
    canonical_json_bytes,
    digest_json,
    make_state_ref,
    reconcile_two_branches,
    validate_reconciliation_agreement,
    validate_state_ref,
    validate_transition_ref,
)

__all__ = [
    "BranchEvidence",
    "CausalValidationError",
    "ReconciliationAgreement",
    "ReconciliationVote",
    "build_branch_tip",
    "build_transition_ref",
    "canonical_json_bytes",
    "digest_json",
    "make_state_ref",
    "reconcile_two_branches",
    "validate_reconciliation_agreement",
    "validate_state_ref",
    "validate_transition_ref",
]
