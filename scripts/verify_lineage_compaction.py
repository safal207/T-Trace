#!/usr/bin/env python3
"""Verify three repeated fork/reconciliation cycles with bounded active lineage."""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from ttrace.lineage_compaction import (  # noqa: E402
    advance_lineage_accumulator,
    build_seed_lineage_accumulator,
    validate_lineage_accumulator,
)
from ttrace.portable_causality import (  # noqa: E402
    BranchEvidence,
    ReconciliationVote,
    build_branch_tip,
    digest_json,
    make_state_ref,
    reconcile_two_branches,
)


def _sha(label: str) -> str:
    return digest_json({"label": label})


def _branches(common: dict, cycle: int):
    shared = {
        "from_state_ref_sha256": digest_json(common),
        "branch_contract_sha256": _sha("branch-contract"),
        "authorization_contract_sha256": _sha("branch-authorization"),
        "trust_domain": common["trust_domain"],
    }
    return (
        BranchEvidence(
            verified=True,
            provider_id=f"provider-{cycle}-left",
            authority_id=f"authority-{cycle}-left",
            provenance_sha256=_sha(f"branch-{cycle}-left-proof"),
            logical_branch_id=f"cycle-{cycle}-left",
            to_semantic_state_sha256=_sha(f"cycle-{cycle}-left-state"),
            **shared,
        ),
        BranchEvidence(
            verified=True,
            provider_id=f"provider-{cycle}-right",
            authority_id=f"authority-{cycle}-right",
            provenance_sha256=_sha(f"branch-{cycle}-right-proof"),
            logical_branch_id=f"cycle-{cycle}-right",
            to_semantic_state_sha256=_sha(f"cycle-{cycle}-right-state"),
            **shared,
        ),
    )


def _votes(common: dict, branches, cycle: int):
    target = _sha(f"cycle-{cycle}-reconciled-state")
    votes = []
    for side, branch in zip(("left", "right"), branches):
        tip = build_branch_tip(common, branch)
        votes.append(
            ReconciliationVote(
                verified=True,
                provider_id=branch.provider_id,
                authority_id=branch.authority_id,
                provenance_sha256=_sha(f"vote-{cycle}-{side}-proof"),
                trust_domain=branch.trust_domain,
                logical_reconciliation_id=f"cycle-{cycle}-reconcile",
                branch_ref_sha256=digest_json(tip["branch_ref"]),
                branch_state_ref_sha256=digest_json(tip["state_ref"]),
                branch_tip_sha256=digest_json(tip),
                target_semantic_state_sha256=target,
                reconciliation_contract_sha256=_sha("reconciliation-contract"),
                authorization_contract_sha256=_sha(
                    "reconciliation-authorization"
                ),
            )
        )
    return tuple(votes)


def main() -> int:
    common = make_state_ref(
        trust_domain="example.procurement",
        logical_state_id="authorization-state",
        causal_epoch=0,
        semantic_state_sha256=_sha("epoch-0"),
    )

    first_branches = _branches(common, 1)
    first = reconcile_two_branches(
        common,
        first_branches,
        _votes(common, first_branches, 1),
    )
    if not first.verified or first.reconciled_state_ref is None:
        raise ValueError(f"first_cycle_rejected:{first.reason}")

    accumulator = build_seed_lineage_accumulator(
        common,
        first,
        accumulator_contract_sha256=_sha("accumulator-contract"),
        authorization_contract_sha256=_sha("accumulator-authorization"),
    )
    common = first.reconciled_state_ref

    last_receipt = None
    for cycle in (2, 3):
        branches = _branches(common, cycle)
        result = advance_lineage_accumulator(
            previous_accumulator=accumulator,
            common_state_ref=common,
            branches=branches,
            votes=_votes(common, branches, cycle),
        )
        if (
            not result.verified
            or result.lineage_accumulator is None
            or result.reconciliation is None
            or result.reconciliation.reconciled_state_ref is None
            or result.receipt is None
        ):
            raise ValueError(f"cycle_{cycle}_rejected:{result.reason}")
        accumulator = result.lineage_accumulator
        common = result.reconciliation.reconciled_state_ref
        last_receipt = result.receipt

    if not validate_lineage_accumulator(accumulator):
        raise ValueError("final_accumulator_invalid")
    if len(accumulator) != 13:
        raise ValueError("accumulator_shape_changed")

    result = {
        "verified": True,
        "reason": "repeated_fork_lineage_compaction_verified",
        "completed_reconciliation_cycles": accumulator[
            "completed_reconciliation_cycles"
        ],
        "final_causal_epoch": accumulator["current_causal_epoch"],
        "accumulator_field_count": len(accumulator),
        "lineage_root_sha256": accumulator["lineage_root_sha256"],
        "lineage_accumulator_sha256": digest_json(accumulator),
        "final_receipt_sha256": digest_json(last_receipt),
        "raw_ancestry_embedded": False,
        "raw_provider_evidence_embedded": False,
    }
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
