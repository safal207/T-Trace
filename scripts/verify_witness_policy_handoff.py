#!/usr/bin/env python3
"""Verify a canonical dual-quorum witness-policy handoff and conflict case."""

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
    build_lineage_witness_observation,
    build_lineage_witness_policy,
    build_lineage_witness_quorum_package,
)
from ttrace.lineage_witness_handoff import (  # noqa: E402
    CONDITIONAL_HANDOFF_STATUS,
    build_witness_policy_handoff_observation,
    build_witness_policy_handoff_package,
    build_witness_policy_handoff_statement,
    detect_witness_policy_handoff_equivocation,
    verify_witness_policy_handoff_package,
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
    target = _sha(f"cycle-{cycle}-reconciled-state")
    votes = []
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


def _normal_observation(
    endpoint,
    statement,
    policy,
    witness_id,
    sequence,
    previous,
    salt,
):
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


def _policy(epoch: int, witness_ids, suffix: str):
    return build_lineage_witness_policy(
        policy_id="lineage-witness-set",
        policy_epoch=epoch,
        authorized_witness_ids=witness_ids,
        threshold=3,
        witness_contract_sha256=_sha(f"{suffix}-witness-contract"),
        authorization_contract_sha256=_sha(
            f"{suffix}-witness-authorization"
        ),
    )


def _handoff(
    endpoint,
    statement,
    old_policy,
    new_policy,
    *,
    suffix: str,
    old_active_ids,
    old_handoff_ids,
    new_handoff_ids,
    new_activation_ids,
):
    old_active_observations = {
        witness_id: _normal_observation(
            endpoint,
            statement,
            old_policy,
            witness_id,
            1,
            ZERO_SHA256,
            f"{suffix}-old-active",
        )
        for witness_id in old_active_ids
    }
    old_active_package = build_lineage_witness_quorum_package(
        endpoint["membership_anchor"],
        endpoint["current_accumulator"],
        statement,
        old_policy,
        list(old_active_observations.values()),
    )
    handoff_statement = build_witness_policy_handoff_statement(
        endpoint["membership_anchor"],
        endpoint["current_accumulator"],
        statement,
        old_policy,
        new_policy,
        verified=True,
        handoff_contract_sha256=_sha("policy-handoff-contract"),
        authorization_contract_sha256=_sha(
            "policy-handoff-authorization"
        ),
        handoff_provenance_sha256=_sha(f"{suffix}-handoff-authority-proof"),
    )
    selected = sorted(set(old_handoff_ids) | set(new_handoff_ids))
    handoff_observations = {}
    for witness_id in selected:
        if witness_id in old_active_observations:
            sequence = 2
            previous = digest_json(old_active_observations[witness_id])
        else:
            sequence = 1
            previous = ZERO_SHA256
        handoff_observations[witness_id] = (
            build_witness_policy_handoff_observation(
                handoff_statement,
                old_policy,
                new_policy,
                verified=True,
                witness_id=witness_id,
                witness_sequence=sequence,
                previous_observation_sha256=previous,
                observation_provenance_sha256=_sha(
                    f"{suffix}-{witness_id}-handoff-proof"
                ),
            )
        )
    new_activation_observations = []
    for witness_id in new_activation_ids:
        if witness_id in handoff_observations:
            handoff_observation = handoff_observations[witness_id]
            sequence = int(handoff_observation["witness_sequence"]) + 1
            previous = digest_json(handoff_observation)
        else:
            sequence = 1
            previous = ZERO_SHA256
        new_activation_observations.append(
            _normal_observation(
                endpoint,
                statement,
                new_policy,
                witness_id,
                sequence,
                previous,
                f"{suffix}-new-activation",
            )
        )
    new_activation_package = build_lineage_witness_quorum_package(
        endpoint["membership_anchor"],
        endpoint["current_accumulator"],
        statement,
        new_policy,
        new_activation_observations,
    )
    return build_witness_policy_handoff_package(
        old_active_package,
        new_activation_package,
        handoff_statement,
        list(handoff_observations.values()),
        old_handoff_witness_ids=old_handoff_ids,
        new_handoff_witness_ids=new_handoff_ids,
    )


def main() -> int:
    records, accumulator = _records(9)
    consistency = build_lineage_root_consistency_package(
        records[:3],
        records[2]["lineage_accumulator"],
        records,
        accumulator,
        membership_contract_sha256=_sha("membership-contract"),
        authorization_contract_sha256=_sha("membership-authorization"),
    )
    endpoint = consistency["new_endpoint"]
    statement = build_lineage_anchor_statement(
        endpoint["membership_anchor"],
        endpoint["current_accumulator"],
        verified=True,
        authority_id="ed25519-sha256:example-lineage-authority",
        statement_sequence=9,
        previous_statement_sha256=_sha("statement-8"),
        statement_provenance_sha256=_sha("statement-9-proof"),
    )
    old_policy = _policy(1, ["w1", "w2", "w3", "w4", "w5"], "old")
    new_policy = _policy(2, ["w4", "w5", "w6", "w7", "w8"], "new")
    package = _handoff(
        endpoint,
        statement,
        old_policy,
        new_policy,
        suffix="canonical",
        old_active_ids=("w1", "w2", "w3"),
        old_handoff_ids=("w3", "w4", "w5"),
        new_handoff_ids=("w4", "w5", "w6"),
        new_activation_ids=("w6", "w7", "w8"),
    )
    decision = verify_witness_policy_handoff_package(package)
    if not decision.verified:
        raise ValueError(f"policy_handoff_rejected:{decision.reason}")

    conflicting_policy = _policy(
        2,
        ["w3", "w6", "w9", "w10", "w11"],
        "conflicting-new",
    )
    conflicting = _handoff(
        endpoint,
        statement,
        old_policy,
        conflicting_policy,
        suffix="conflicting",
        old_active_ids=("w1", "w2", "w3"),
        old_handoff_ids=("w1", "w2", "w3"),
        new_handoff_ids=("w3", "w6", "w9"),
        new_activation_ids=("w6", "w9", "w11"),
    )
    conflict = detect_witness_policy_handoff_equivocation(package, conflicting)
    if not conflict.verified or not conflict.equivocation_detected:
        raise ValueError(f"handoff_equivocation_rejected:{conflict.reason}")

    result = {
        "verified": True,
        "reason": decision.reason,
        "policy_id": package["handoff_statement"]["policy_id"],
        "old_policy_epoch": package["handoff_statement"]["old_policy_epoch"],
        "new_policy_epoch": package["handoff_statement"]["new_policy_epoch"],
        "old_policy_sha256": decision.old_policy_sha256,
        "new_policy_sha256": decision.new_policy_sha256,
        "old_active_certificate_sha256": (
            decision.old_active_certificate_sha256
        ),
        "old_handoff_certificate_sha256": (
            decision.old_handoff_certificate_sha256
        ),
        "new_handoff_certificate_sha256": (
            decision.new_handoff_certificate_sha256
        ),
        "new_activation_certificate_sha256": (
            decision.new_activation_certificate_sha256
        ),
        "old_continuity_witness_ids": list(
            decision.old_continuity_witness_ids
        ),
        "new_continuity_witness_ids": list(
            decision.new_continuity_witness_ids
        ),
        "cross_policy_handoff_witness_ids": list(
            decision.cross_policy_handoff_witness_ids
        ),
        "old_minimum_quorum_intersection": (
            decision.old_minimum_quorum_intersection
        ),
        "new_minimum_quorum_intersection": (
            decision.new_minimum_quorum_intersection
        ),
        "handoff_certificate_sha256": decision.handoff_certificate_sha256,
        "no_unprotected_acceptance_gap": (
            decision.no_unprotected_acceptance_gap
        ),
        "conflicting_handoff_detected": conflict.equivocation_detected,
        "double_signing_old_witness_ids": list(
            conflict.double_signing_old_witness_ids
        ),
        "conditional_handoff_status": CONDITIONAL_HANDOFF_STATUS,
        "conditional_non_equivocation_status": (
            decision.conditional_non_equivocation_status
        ),
        "global_non_equivocation_status": GLOBAL_NON_EQUIVOCATION_STATUS,
        "raw_cycle_records_disclosed": False,
    }
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
