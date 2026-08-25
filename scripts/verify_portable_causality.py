#!/usr/bin/env python3
"""Build and verify the canonical T-Trace two-parent reconciliation example."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
if str(REPOSITORY_ROOT) not in sys.path:
    sys.path.insert(0, str(REPOSITORY_ROOT))

from ttrace import (
    BranchObservation,
    CausalStateRef,
    build_fork_branch,
    build_reconciliation_vote,
    canonical_json_bytes,
    digest_object,
    reconcile_two_branches,
    validate_reconciliation_result,
)

EXAMPLE_SCHEMA = "ttrace-portable-causality-example/v0.1"


def _sha(label: str) -> str:
    return digest_object({"ttrace-example": label})


def build_example() -> dict:
    common_state = CausalStateRef(
        trust_domain="ttrace.authorization",
        logical_state_id="procurement-request-0042",
        causal_epoch=2,
        semantic_state_sha256=_sha("authorized-common-tip"),
    )
    common_checkpoint = _sha("verified-common-checkpoint")
    common_witness = _sha("verified-common-witness")
    branch_contract = _sha("fork-branch-contract-v0.1")
    branch_authorization = _sha("fork-branch-authorization-v0.1")

    branch_a = build_fork_branch(
        common_state,
        common_checkpoint_sha256=common_checkpoint,
        common_witness_sha256=common_witness,
        logical_branch_id="supplier-a-policy",
        semantic_state_sha256=_sha("supplier-a-authorized-state"),
        branch_contract_sha256=branch_contract,
        authorization_contract_sha256=branch_authorization,
    )
    branch_b = build_fork_branch(
        common_state,
        common_checkpoint_sha256=common_checkpoint,
        common_witness_sha256=common_witness,
        logical_branch_id="supplier-b-policy",
        semantic_state_sha256=_sha("supplier-b-authorized-state"),
        branch_contract_sha256=branch_contract,
        authorization_contract_sha256=branch_authorization,
    )
    observation_a = BranchObservation(
        True,
        "github-oidc-example-a",
        "example-authority-a",
        _sha("branch-a-evidence"),
        branch_a,
    )
    observation_b = BranchObservation(
        True,
        "offline-ed25519-example-b",
        "example-authority-b",
        _sha("branch-b-evidence"),
        branch_b,
    )
    target = _sha("reconciled-procurement-state")
    reconciliation_contract = _sha("reconciliation-contract-v0.1")
    reconciliation_authorization = _sha("reconciliation-authorization-v0.1")
    vote_a = build_reconciliation_vote(
        observation_a,
        vote_evidence_sha256=_sha("vote-a-evidence"),
        target_semantic_state_sha256=target,
        reconciliation_contract_sha256=reconciliation_contract,
        authorization_contract_sha256=reconciliation_authorization,
    )
    vote_b = build_reconciliation_vote(
        observation_b,
        vote_evidence_sha256=_sha("vote-b-evidence"),
        target_semantic_state_sha256=target,
        reconciliation_contract_sha256=reconciliation_contract,
        authorization_contract_sha256=reconciliation_authorization,
    )
    result = reconcile_two_branches(
        common_state,
        common_checkpoint_sha256=common_checkpoint,
        common_witness_sha256=common_witness,
        logical_reconciliation_id="procurement-supplier-reconciliation",
        primary=observation_a,
        secondary=observation_b,
        primary_vote=vote_a,
        secondary_vote=vote_b,
    )
    if not validate_reconciliation_result(
        result,
        common_state=common_state,
        common_checkpoint_sha256=common_checkpoint,
        common_witness_sha256=common_witness,
    ):
        raise RuntimeError("canonical_example_failed_validation")

    return {
        "schema": EXAMPLE_SCHEMA,
        "common_tip": {
            "state_ref": common_state.to_dict(),
            "checkpoint_sha256": common_checkpoint,
            "witness_sha256": common_witness,
        },
        "branch_a": branch_a.to_dict(),
        "branch_b": branch_b.to_dict(),
        "reconciliation": result.to_dict(),
        "claim_boundary": {
            "two_parent_reconciliation": True,
            "branch_semantics_divergent": True,
            "branch_order_canonical": True,
            "raw_provider_evidence_in_portable_result": False,
            "cryptographic_attestation_in_this_example": False,
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("example", type=Path)
    parser.add_argument("--write", action="store_true")
    args = parser.parse_args()

    expected = build_example()
    encoded = canonical_json_bytes(expected) + b"\n"
    if args.write:
        args.example.parent.mkdir(parents=True, exist_ok=True)
        args.example.write_bytes(encoded)
        print(f"WROTE {args.example} sha256={digest_object(expected)}")
        return 0

    actual = json.loads(args.example.read_text(encoding="utf-8"))
    if canonical_json_bytes(actual) != canonical_json_bytes(expected):
        raise SystemExit("FAIL canonical example differs from reference implementation")
    print(
        "PASS portable causal fork/reconciliation "
        f"sha256={digest_object(expected)}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
