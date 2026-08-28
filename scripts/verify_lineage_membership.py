#!/usr/bin/env python3
"""Verify one historical reconciliation cycle without revealing intervening cycles."""

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
)
from ttrace.lineage_membership import (  # noqa: E402
    build_selective_lineage_disclosure,
    verify_selective_lineage_disclosure,
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
    records = []
    accumulator = None

    for cycle in range(1, 6):
        branches = _branches(common, cycle)
        reconciliation = reconcile_two_branches(
            common, branches, _votes(common, branches, cycle)
        )
        if not reconciliation.verified or reconciliation.reconciled_state_ref is None:
            raise ValueError(f"cycle_{cycle}_rejected:{reconciliation.reason}")
        if cycle == 1:
            accumulator = build_seed_lineage_accumulator(
                common,
                reconciliation,
                accumulator_contract_sha256=_sha("accumulator-contract"),
                authorization_contract_sha256=_sha("accumulator-authorization"),
            )
        else:
            if accumulator is None:
                raise ValueError("previous_accumulator_missing")
            advanced = advance_lineage_accumulator(
                previous_accumulator=accumulator,
                common_state_ref=common,
                branches=branches,
                votes=_votes(common, branches, cycle),
            )
            if (
                not advanced.verified
                or advanced.lineage_accumulator is None
                or advanced.reconciliation is None
                or advanced.reconciliation.reconciled_state_ref is None
            ):
                raise ValueError(f"cycle_{cycle}_compaction_rejected:{advanced.reason}")
            accumulator = advanced.lineage_accumulator
            reconciliation = advanced.reconciliation

        records.append(
            {
                "cycle_index": cycle,
                "common_state_ref": common,
                "reconciliation": reconciliation.to_dict(),
                "lineage_accumulator": accumulator,
            }
        )
        common = reconciliation.reconciled_state_ref

    if accumulator is None:
        raise ValueError("final_accumulator_missing")

    disclosure = build_selective_lineage_disclosure(
        records,
        accumulator,
        selected_cycle_index=2,
        membership_contract_sha256=_sha("membership-contract"),
        authorization_contract_sha256=_sha("membership-authorization"),
    )
    decision = verify_selective_lineage_disclosure(disclosure)
    if not decision.verified:
        raise ValueError(f"membership_rejected:{decision.reason}")

    anchor = disclosure["anchor"]
    proof = disclosure["membership_proof"]
    result = {
        "verified": True,
        "reason": decision.reason,
        "completed_reconciliation_cycles": accumulator[
            "completed_reconciliation_cycles"
        ],
        "current_causal_epoch": accumulator["current_causal_epoch"],
        "disclosed_cycle_index": decision.disclosed_cycle_index,
        "membership_anchor_sha256": decision.anchor_sha256,
        "membership_root_sha256": anchor[
            "cycle_commitment_merkle_root_sha256"
        ],
        "disclosed_cycle_commitment_sha256": decision.cycle_commitment_sha256,
        "selected_sibling_hash_count": (
            decision.selected_sibling_hash_count
        ),
        "current_sibling_hash_count": decision.current_sibling_hash_count,
        "sibling_hash_count": decision.sibling_hash_count,
        "tree_size": proof["tree_size"],
        "current_lineage_root_sha256": accumulator["lineage_root_sha256"],
        "raw_intervening_cycles_disclosed": False,
        "raw_provider_evidence_embedded": False,
    }
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
