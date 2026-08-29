#!/usr/bin/env python3
"""Verify witness-quorum continuity and attributable split-view evidence."""

from __future__ import annotations

import json
import sys
from copy import deepcopy
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from ttrace.lineage_compaction import (  # noqa: E402
    ZERO_SHA256,
    advance_lineage_accumulator,
    build_seed_lineage_accumulator,
)
from ttrace.lineage_consistency import (  # noqa: E402
    GLOBAL_NON_EQUIVOCATION_STATUS,
    build_lineage_anchor_statement,
    build_lineage_root_consistency_package,
)
from ttrace.lineage_witness import (  # noqa: E402
    CONDITIONAL_NON_EQUIVOCATION_STATUS,
    build_lineage_witness_observation,
    build_lineage_witness_policy,
    build_lineage_witness_quorum_package,
    detect_witness_quorum_equivocation,
    verify_witnessed_lineage_root_consistency,
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
    """Return a deterministic fixture digest."""

    return digest_json({"label": label})


def _branches(common: dict, cycle: int):
    """Build two independently evidenced branch observations for one cycle."""

    shared = {
        "from_state_ref_sha256": digest_json(common),
        "branch_contract_sha256": _sha("branch-contract"),
        "authorization_contract_sha256": _sha("branch-authorization"),
        "trust_domain": common["trust_domain"],
    }
    return (
        BranchEvidence(
            True,
            f"provider-{cycle}-left",
            f"authority-{cycle}-left",
            _sha(f"branch-{cycle}-left-proof"),
            logical_branch_id=f"cycle-{cycle}-left",
            to_semantic_state_sha256=_sha(f"cycle-{cycle}-left-state"),
            **shared,
        ),
        BranchEvidence(
            True,
            f"provider-{cycle}-right",
            f"authority-{cycle}-right",
            _sha(f"branch-{cycle}-right-proof"),
            logical_branch_id=f"cycle-{cycle}-right",
            to_semantic_state_sha256=_sha(f"cycle-{cycle}-right-state"),
            **shared,
        ),
    )


def _votes(common: dict, branches, cycle: int):
    """Build exact branch-bound reconciliation votes."""

    votes = []
    target = _sha(f"cycle-{cycle}-reconciled-state")
    for side, branch in zip(("left", "right"), branches):
        tip = build_branch_tip(common, branch)
        votes.append(
            ReconciliationVote(
                True,
                branch.provider_id,
                branch.authority_id,
                _sha(f"vote-{cycle}-{side}-proof"),
                branch.trust_domain,
                f"cycle-{cycle}-reconcile",
                digest_json(tip["branch_ref"]),
                digest_json(tip["state_ref"]),
                digest_json(tip),
                target,
                _sha("reconciliation-contract"),
                _sha("reconciliation-authorization"),
            )
        )
    return tuple(votes)


def _records(cycle_count: int):
    """Build a deterministic retained lineage ending at ``cycle_count``."""

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
                votes=votes,
            )
            if (
                not advanced.verified
                or advanced.lineage_accumulator is None
                or advanced.reconciliation is None
                or advanced.reconciliation.reconciled_state_ref is None
            ):
                raise ValueError(f"cycle_{cycle}_advance_rejected:{advanced.reason}")
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


def _observation(endpoint, statement, policy, witness_id, sequence, previous, salt):
    """Build one externally verified witness-observation fixture."""

    return build_lineage_witness_observation(
        endpoint["membership_anchor"],
        endpoint["current_accumulator"],
        statement,
        policy,
        verified=True,
        witness_id=witness_id,
        witness_sequence=sequence,
        previous_observation_sha256=previous,
        observation_provenance_sha256=_sha(
            f"{salt}-{witness_id}-observation-proof"
        ),
    )


def main() -> int:
    """Run the canonical five-witness, three-of-five quorum scenario."""

    records, current_accumulator = _records(9)
    old_records = records[:3]
    old_accumulator = old_records[-1]["lineage_accumulator"]
    consistency_package = build_lineage_root_consistency_package(
        old_records,
        old_accumulator,
        records,
        current_accumulator,
        membership_contract_sha256=_sha("membership-contract"),
        authorization_contract_sha256=_sha("membership-authorization"),
    )
    old_endpoint = consistency_package["old_endpoint"]
    new_endpoint = consistency_package["new_endpoint"]
    authority_id = "ed25519-sha256:example-lineage-authority"
    old_statement = build_lineage_anchor_statement(
        old_endpoint["membership_anchor"],
        old_endpoint["current_accumulator"],
        verified=True,
        authority_id=authority_id,
        statement_sequence=1,
        previous_statement_sha256=ZERO_SHA256,
        statement_provenance_sha256=_sha("old-producer-signature"),
    )
    new_statement = build_lineage_anchor_statement(
        new_endpoint["membership_anchor"],
        new_endpoint["current_accumulator"],
        verified=True,
        authority_id=authority_id,
        statement_sequence=2,
        previous_statement_sha256=digest_json(old_statement),
        statement_provenance_sha256=_sha("new-producer-signature"),
    )
    policy = build_lineage_witness_policy(
        policy_id="lineage-witness-set-1",
        policy_epoch=1,
        authorized_witness_ids=["w1", "w2", "w3", "w4", "w5"],
        threshold=3,
        witness_contract_sha256=_sha("witness-contract"),
        authorization_contract_sha256=_sha("witness-authorization"),
    )

    old_by_id = {
        witness_id: _observation(
            old_endpoint,
            old_statement,
            policy,
            witness_id,
            1,
            ZERO_SHA256,
            "old",
        )
        for witness_id in ("w1", "w2", "w3")
    }
    old_package = build_lineage_witness_quorum_package(
        old_endpoint["membership_anchor"],
        old_endpoint["current_accumulator"],
        old_statement,
        policy,
        list(old_by_id.values()),
    )
    new_observations = [
        _observation(
            new_endpoint,
            new_statement,
            policy,
            "w3",
            2,
            digest_json(old_by_id["w3"]),
            "new",
        ),
        _observation(
            new_endpoint,
            new_statement,
            policy,
            "w4",
            1,
            ZERO_SHA256,
            "new",
        ),
        _observation(
            new_endpoint,
            new_statement,
            policy,
            "w5",
            1,
            ZERO_SHA256,
            "new",
        ),
    ]
    new_package = build_lineage_witness_quorum_package(
        new_endpoint["membership_anchor"],
        new_endpoint["current_accumulator"],
        new_statement,
        policy,
        new_observations,
    )
    witnessed = verify_witnessed_lineage_root_consistency(
        consistency_package, old_package, new_package
    )
    if not witnessed.verified:
        raise ValueError(f"witnessed_consistency_rejected:{witnessed.reason}")

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
        statement_provenance_sha256=_sha("split-producer-signature"),
    )
    split_observations = [
        build_lineage_witness_observation(
            split_anchor,
            new_endpoint["current_accumulator"],
            split_statement,
            policy,
            verified=True,
            witness_id=witness_id,
            witness_sequence=(2 if witness_id == "w3" else 1),
            previous_observation_sha256=(
                digest_json(old_by_id["w3"])
                if witness_id == "w3"
                else ZERO_SHA256
            ),
            observation_provenance_sha256=_sha(
                f"split-{witness_id}-observation-proof"
            ),
        )
        for witness_id in ("w3", "w4", "w5")
    ]
    split_package = build_lineage_witness_quorum_package(
        split_anchor,
        new_endpoint["current_accumulator"],
        split_statement,
        policy,
        split_observations,
    )
    conflict = detect_witness_quorum_equivocation(new_package, split_package)
    if not conflict.verified or not conflict.equivocation_detected:
        raise ValueError(f"witness_equivocation_rejected:{conflict.reason}")

    result = {
        "verified": True,
        "reason": witnessed.reason,
        "producer_authority_id": witnessed.authority_id,
        "witness_policy_sha256": witnessed.witness_policy_sha256,
        "authorized_witness_count": len(policy["authorized_witness_ids"]),
        "threshold": policy["threshold"],
        "minimum_quorum_intersection": witnessed.minimum_quorum_intersection,
        "old_witness_ids": old_package["quorum_certificate"]["witness_ids"],
        "new_witness_ids": new_package["quorum_certificate"]["witness_ids"],
        "overlapping_witness_ids": list(witnessed.overlapping_witness_ids),
        "old_certificate_sha256": witnessed.old_certificate_sha256,
        "new_certificate_sha256": witnessed.new_certificate_sha256,
        "append_only_consistent": witnessed.append_only_consistent,
        "authority_chain_continuous": witnessed.authority_chain_continuous,
        "witness_chains_continuous": witnessed.witness_chains_continuous,
        "presented_split_view_detected": conflict.equivocation_detected,
        "double_signing_witness_ids": list(
            conflict.double_signing_witness_ids
        ),
        "conditional_non_equivocation_status": (
            CONDITIONAL_NON_EQUIVOCATION_STATUS
        ),
        "global_non_equivocation_status": GLOBAL_NON_EQUIVOCATION_STATUS,
        "raw_cycle_records_disclosed": False,
    }
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
