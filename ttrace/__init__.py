"""T-Trace portable causal state, transition, fork, and reconciliation primitives."""

from ttrace.branch import (
    BranchObservation,
    ForkBranch,
    build_fork_branch,
    validate_fork_branch,
)
from ttrace.canonical import canonical_json_bytes, digest_object, sha256_hex
from ttrace.reconciliation import (
    ReconciliationResult,
    ReconciliationVote,
    build_reconciliation_vote,
    reconcile_two_branches,
    validate_reconciliation_result,
)
from ttrace.state import CausalStateRef, advance_state
from ttrace.transition import CausalTransitionRef, build_transition_ref

__all__ = [
    "BranchObservation",
    "CausalStateRef",
    "CausalTransitionRef",
    "ForkBranch",
    "ReconciliationResult",
    "ReconciliationVote",
    "advance_state",
    "build_fork_branch",
    "build_reconciliation_vote",
    "build_transition_ref",
    "canonical_json_bytes",
    "digest_object",
    "reconcile_two_branches",
    "sha256_hex",
    "validate_fork_branch",
    "validate_reconciliation_result",
]
