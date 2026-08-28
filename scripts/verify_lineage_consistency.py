#!/usr/bin/env python3
"""Verify append-only membership-root consistency and presented equivocation evidence."""

from __future__ import annotations

import json
import sys
from copy import deepcopy
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from ttrace.lineage_compaction import (  # noqa: E402
    advance_lineage_accumulator,
    build_seed_lineage_accumulator,
)
from ttrace.lineage_consistency import (  # noqa: E402
    GLOBAL_NON_EQUIVOCATION_STATUS,
    build_lineage_anchor_statement,
    build_lineage_root_consistency_package,
    detect_lineage_anchor_equivocation,
    verify_authorized_lineage_root_consistency,
    verify_lineage_root_consistency,
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
            to_semantic_state_sha256=_sha(
                f"cycle-{cycle}-left-state"
            ),
            **shared,
        ),
        BranchEvidence(
            verified=True,
            provider_id=f"provider-{cycle}-right",
            authority_id=f"authority-{cycle}-right",
            provenance_sha256=_sha(f"branch-{cycle}-right-proof"),
            logical_branch_id=f"cycle-{cycle}-right",
            to_semantic_state_sha256=_sha(
                f"cycle-{cycle}-right-state"
            ),
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
                provenance_sha256=_sha(
                    f"vote-{cycle}-{side}-proof"
                ),
                trust_domain=branch.trust_domain,
                logical_reconciliation_id=(
                    f"cycle-{cycle}-reconcile"
                ),
                branch_ref_sha256=digest_json(tip["branch_ref"]),
                branch_state_ref_sha256=digest_json(tip["state_ref"]),
                branch_tip_sha256=digest_json(tip),
                target_semantic_state_sha256=target,
                reconciliation_contract_sha256=_sha(
                    "reconciliation-contract"
                ),
                authorization_contract_sha256=_sha(
                    "reconciliation-authorization"
                ),
            )
        )
    return tuple(votes)


def _records(cycle_count: int):
    common = make_state_ref(
        trust_domain="example.procurement",
        logical_state_id="authorization-state",
        causal_epoch=0,
        semantic_state_sha256=_sha("epoch-0"),
    )
    records = []
    accumulator = None
    for cycle in range(1, cycle_count + 1):
        branches = _branches(common, cycle)
        votes = _votes(common, branches, cycle)
        reconciliation = reconcile_two_branches(common, branches, votes)
        if (
            not reconciliation.verified
            or reconciliation.reconciled_state_ref is None
        ):
            raise ValueError(
                f"cycle_{cycle}_rejected:{reconciliation.reason}"
            )
        if cycle == 1:
            accumulator = build_seed_lineage_accumulator(
                common,
                reconciliation,
                accumulator_contract_sha256=_sha(
                    "accumulator-contract"
                ),
                authorization_contract_sha256=_sha(
                    "accumulator-authorization"
                ),
            )
        else:
            if accumulator is None:
                raise ValueError("previous_accumulator_missing")
            advanced = advance_lineage_accumulator(
                previous_accumulator=accumulator,
                common_state_ref=common,
                branches=branches,
                votes=votes,
            )
            if (
                not advanced.verified
                or advanced.lineage_accumulator is None
                or advanced.reconciliation is None
                or advanced.reconciliation.reconciled_state_ref
                is None
            ):
                raise ValueError(
                    f"cycle_{cycle}_compaction_rejected:"
                    f"{advanced.reason}"
                )
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
    return records, accumulator


def main() -> int:
    records, current_accumulator = _records(9)
    old_records = records[:3]
    old_accumulator = old_records[-1]["lineage_accumulator"]
    membership_contract = _sha("membership-contract")
    authorization_contract = _sha("membership-authorization")

    package = build_lineage_root_consistency_package(
        old_records,
        old_accumulator,
        records,
        current_accumulator,
        membership_contract_sha256=membership_contract,
        authorization_contract_sha256=authorization_contract,
    )
    consistency = verify_lineage_root_consistency(package)
    if not consistency.verified:
        raise ValueError(
            f"consistency_rejected:{consistency.reason}"
        )

    old_endpoint = package["old_endpoint"]
    new_endpoint = package["new_endpoint"]
    authority_id = "ed25519-sha256:example-lineage-authority"
    old_statement = build_lineage_anchor_statement(
        old_endpoint["membership_anchor"],
        old_endpoint["current_accumulator"],
        verified=True,
        authority_id=authority_id,
        statement_sequence=1,
        previous_statement_sha256="0" * 64,
        statement_provenance_sha256=_sha(
            "old-anchor-signature-evidence"
        ),
    )
    new_statement = build_lineage_anchor_statement(
        new_endpoint["membership_anchor"],
        new_endpoint["current_accumulator"],
        verified=True,
        authority_id=authority_id,
        statement_sequence=2,
        previous_statement_sha256=digest_json(old_statement),
        statement_provenance_sha256=_sha(
            "new-anchor-signature-evidence"
        ),
    )
    authorized = verify_authorized_lineage_root_consistency(
        package, old_statement, new_statement
    )
    if not authorized.verified:
        raise ValueError(
            f"authorized_consistency_rejected:{authorized.reason}"
        )

    split_anchor = deepcopy(new_endpoint["membership_anchor"])
    split_anchor["cycle_commitment_merkle_root_sha256"] = _sha(
        "conflicting-split-view-root"
    )
    split_statement = build_lineage_anchor_statement(
        split_anchor,
        new_endpoint["current_accumulator"],
        verified=True,
        authority_id=authority_id,
        statement_sequence=2,
        previous_statement_sha256=digest_json(old_statement),
        statement_provenance_sha256=_sha(
            "split-view-signature-evidence"
        ),
    )
    equivocation = detect_lineage_anchor_equivocation(
        new_endpoint["membership_anchor"],
        new_endpoint["current_accumulator"],
        new_statement,
        split_anchor,
        new_endpoint["current_accumulator"],
        split_statement,
    )
    if not equivocation.verified or not equivocation.equivocation_detected:
        raise ValueError(
            f"equivocation_fixture_rejected:{equivocation.reason}"
        )

    proof = package["consistency_proof"]
    result = {
        "verified": True,
        "reason": consistency.reason,
        "old_tree_size": consistency.old_tree_size,
        "new_tree_size": consistency.new_tree_size,
        "old_membership_root_sha256": old_endpoint[
            "membership_anchor"
        ]["cycle_commitment_merkle_root_sha256"],
        "new_membership_root_sha256": new_endpoint[
            "membership_anchor"
        ]["cycle_commitment_merkle_root_sha256"],
        "old_anchor_sha256": consistency.old_anchor_sha256,
        "new_anchor_sha256": consistency.new_anchor_sha256,
        "old_frontier_node_count": (
            consistency.old_frontier_node_count
        ),
        "append_block_count": consistency.append_block_count,
        "old_current_path_hash_count": (
            consistency.old_current_path_hash_count
        ),
        "new_current_path_hash_count": (
            consistency.new_current_path_hash_count
        ),
        "authority_chain_continuous": (
            authorized.authority_chain_continuous
        ),
        "presented_equivocation_detected": (
            equivocation.equivocation_detected
        ),
        "equivocation_detection_mode": equivocation.evidence[
            "detection_mode"
        ],
        "global_non_equivocation_status": (
            GLOBAL_NON_EQUIVOCATION_STATUS
        ),
        "raw_cycle_records_disclosed": False,
        "proof_hash_count": (
            len(proof["old_frontier"])
            + len(proof["append_blocks"])
            + len(proof["old_current_cycle_sibling_path"])
            + len(proof["new_current_cycle_sibling_path"])
        ),
    }
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
