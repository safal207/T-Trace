#!/usr/bin/env python3
"""Verify a deterministic three-step witness-policy handoff chain."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Dict, Mapping, Sequence, Tuple

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from ttrace.lineage_compaction import (  # noqa: E402
    ZERO_SHA256,
    advance_lineage_accumulator,
    build_seed_lineage_accumulator,
)
from ttrace.lineage_consistency import (  # noqa: E402
    build_lineage_anchor_statement,
    build_lineage_root_consistency_package,
)
from ttrace.lineage_witness import (  # noqa: E402
    build_lineage_witness_observation,
    build_lineage_witness_policy,
    build_lineage_witness_quorum_package,
)
from ttrace.lineage_witness_handoff import (  # noqa: E402
    build_witness_policy_handoff_observation,
    build_witness_policy_handoff_package,
    build_witness_policy_handoff_statement,
)
from ttrace.lineage_witness_handoff_chain import (  # noqa: E402
    CHAIN_FORK_REASON,
    CHAIN_REASON,
    CONDITIONAL_HANDOFF_CHAIN_STATUS,
    advance_witness_policy_handoff_chain,
    build_seed_witness_policy_handoff_chain,
    detect_witness_policy_handoff_chain_fork,
    verify_witness_policy_handoff_chain,
)
from ttrace.portable_causality import (  # noqa: E402
    BranchEvidence,
    ReconciliationVote,
    build_branch_tip,
    digest_json,
    make_state_ref,
    reconcile_two_branches,
)

CHAIN_ID = "example.procurement.witness-policy-chain"
CHAIN_CONTRACT = digest_json({"contract": "handoff-chain/v0.1"})
CHAIN_AUTHORIZATION = digest_json({"contract": "handoff-chain-authorization/v0.1"})


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


def _view():
    records, accumulator = _records(9)
    consistency = build_lineage_root_consistency_package(
        records[:3],
        records[2]["lineage_accumulator"],
        records,
        accumulator,
        membership_contract_sha256=_sha("membership"),
        authorization_contract_sha256=_sha("authorization"),
    )
    endpoint = consistency["new_endpoint"]
    anchor = endpoint["membership_anchor"]
    current_accumulator = endpoint["current_accumulator"]
    statement = build_lineage_anchor_statement(
        anchor,
        current_accumulator,
        verified=True,
        authority_id="producer-1",
        statement_sequence=7,
        previous_statement_sha256=_sha("statement-6"),
        statement_provenance_sha256=_sha("producer-statement-7-proof"),
    )
    return anchor, current_accumulator, statement


def _policy(epoch: int, witnesses: Sequence[str], label: str):
    return build_lineage_witness_policy(
        policy_id="lineage-witness-set",
        policy_epoch=epoch,
        authorized_witness_ids=list(witnesses),
        threshold=3,
        witness_contract_sha256=_sha(f"{label}-witness-contract"),
        authorization_contract_sha256=_sha(f"{label}-witness-authorization"),
    )


def _normal_observation(
    anchor,
    accumulator,
    statement,
    policy,
    witness_id: str,
    sequence: int,
    previous: str,
    salt: str,
):
    return build_lineage_witness_observation(
        anchor,
        accumulator,
        statement,
        policy,
        verified=True,
        witness_id=witness_id,
        witness_sequence=sequence,
        previous_observation_sha256=previous,
        observation_provenance_sha256=_sha(f"{salt}-{witness_id}-proof"),
    )


def _initial_active(anchor, accumulator, statement, policy, witness_ids):
    observations = [
        _normal_observation(
            anchor,
            accumulator,
            statement,
            policy,
            witness_id,
            1,
            ZERO_SHA256,
            "initial-active",
        )
        for witness_id in witness_ids
    ]
    return build_lineage_witness_quorum_package(
        anchor, accumulator, statement, policy, observations
    )


def _handoff(
    old_active_package: Mapping[str, object],
    new_policy: Mapping[str, object],
    *,
    old_handoff_ids: Sequence[str],
    new_handoff_ids: Sequence[str],
    activation_ids: Sequence[str],
    salt: str,
):
    anchor = old_active_package["membership_anchor"]
    accumulator = old_active_package["current_accumulator"]
    statement = old_active_package["producer_statement"]
    old_policy = old_active_package["witness_policy"]
    old_active = {
        item["witness_id"]: item
        for item in old_active_package["witness_observations"]
    }
    handoff_statement = build_witness_policy_handoff_statement(
        anchor,
        accumulator,
        statement,
        old_policy,
        new_policy,
        verified=True,
        handoff_contract_sha256=_sha("handoff-contract"),
        authorization_contract_sha256=_sha("handoff-authorization"),
        handoff_provenance_sha256=_sha(f"{salt}-producer-proof"),
    )
    handoff_observations: Dict[str, dict] = {}
    for witness_id in sorted(set(old_handoff_ids) | set(new_handoff_ids)):
        previous = old_active.get(witness_id)
        sequence = int(previous["witness_sequence"]) + 1 if previous else 1
        predecessor = digest_json(previous) if previous else ZERO_SHA256
        handoff_observations[witness_id] = (
            build_witness_policy_handoff_observation(
                handoff_statement,
                old_policy,
                new_policy,
                verified=True,
                witness_id=witness_id,
                witness_sequence=sequence,
                previous_observation_sha256=predecessor,
                observation_provenance_sha256=_sha(
                    f"{salt}-handoff-{witness_id}-proof"
                ),
            )
        )
    activation_observations = []
    for witness_id in activation_ids:
        previous = handoff_observations.get(witness_id)
        sequence = int(previous["witness_sequence"]) + 1 if previous else 1
        predecessor = digest_json(previous) if previous else ZERO_SHA256
        activation_observations.append(
            _normal_observation(
                anchor,
                accumulator,
                statement,
                new_policy,
                witness_id,
                sequence,
                predecessor,
                f"{salt}-activation",
            )
        )
    new_activation = build_lineage_witness_quorum_package(
        anchor,
        accumulator,
        statement,
        new_policy,
        activation_observations,
    )
    return build_witness_policy_handoff_package(
        old_active_package,
        new_activation,
        handoff_statement,
        list(handoff_observations.values()),
        old_handoff_witness_ids=old_handoff_ids,
        new_handoff_witness_ids=new_handoff_ids,
    )


def build_canonical_handoff_chain_fixture():
    anchor, accumulator, statement = _view()
    policies = (
        _policy(1, ("w1", "w2", "w3", "w4", "w5"), "policy-1"),
        _policy(2, ("w4", "w5", "w6", "w7", "w8"), "policy-2"),
        _policy(3, ("w7", "w8", "w9", "w10", "w11"), "policy-3"),
        _policy(4, ("w10", "w11", "w12", "w13", "w14"), "policy-4"),
    )
    active_1 = _initial_active(
        anchor, accumulator, statement, policies[0], ("w1", "w2", "w3")
    )
    handoff_1 = _handoff(
        active_1,
        policies[1],
        old_handoff_ids=("w3", "w4", "w5"),
        new_handoff_ids=("w4", "w5", "w6"),
        activation_ids=("w6", "w7", "w8"),
        salt="handoff-1",
    )
    handoff_2 = _handoff(
        handoff_1["new_activation_quorum_package"],
        policies[2],
        old_handoff_ids=("w6", "w7", "w8"),
        new_handoff_ids=("w7", "w8", "w9"),
        activation_ids=("w9", "w10", "w11"),
        salt="handoff-2",
    )
    handoff_3 = _handoff(
        handoff_2["new_activation_quorum_package"],
        policies[3],
        old_handoff_ids=("w9", "w10", "w11"),
        new_handoff_ids=("w10", "w11", "w12"),
        activation_ids=("w12", "w13", "w14"),
        salt="handoff-3",
    )
    alternate_policy_3 = _policy(
        3,
        ("w7", "w8", "w15", "w16", "w17"),
        "policy-3-alternate",
    )
    alternate_handoff_2 = _handoff(
        handoff_1["new_activation_quorum_package"],
        alternate_policy_3,
        old_handoff_ids=("w6", "w7", "w8"),
        new_handoff_ids=("w7", "w8", "w15"),
        activation_ids=("w15", "w16", "w17"),
        salt="handoff-2-alternate",
    )
    return {
        "policies": policies,
        "packages": (handoff_1, handoff_2, handoff_3),
        "alternate_second_package": alternate_handoff_2,
    }


def main() -> int:
    fixture = build_canonical_handoff_chain_fixture()
    policies = fixture["policies"]
    packages = fixture["packages"]
    seed = build_seed_witness_policy_handoff_chain(
        packages[0],
        chain_id=CHAIN_ID,
        expected_genesis_policy_epoch=1,
        expected_genesis_policy_sha256=digest_json(policies[0]),
        chain_contract_sha256=CHAIN_CONTRACT,
        authorization_contract_sha256=CHAIN_AUTHORIZATION,
    )
    if not seed.verified or seed.chain_ref is None:
        raise ValueError(f"seed_rejected:{seed.reason}")
    second = advance_witness_policy_handoff_chain(seed.chain_ref, packages[1])
    if not second.verified or second.chain_ref is None:
        raise ValueError(f"second_handoff_rejected:{second.reason}")
    third = advance_witness_policy_handoff_chain(second.chain_ref, packages[2])
    if not third.verified or third.chain_ref is None:
        raise ValueError(f"third_handoff_rejected:{third.reason}")
    decision = verify_witness_policy_handoff_chain(
        packages,
        third.chain_ref,
        chain_id=CHAIN_ID,
        expected_genesis_policy_epoch=1,
        expected_genesis_policy_sha256=digest_json(policies[0]),
        chain_contract_sha256=CHAIN_CONTRACT,
        authorization_contract_sha256=CHAIN_AUTHORIZATION,
    )
    if not decision.verified:
        raise ValueError(f"chain_rebuild_rejected:{decision.reason}")
    fork = detect_witness_policy_handoff_chain_fork(
        seed.chain_ref,
        packages[1],
        fixture["alternate_second_package"],
    )
    if not fork.verified or not fork.fork_detected:
        raise ValueError(f"parallel_fork_not_detected:{fork.reason}")
    print(
        json.dumps(
            {
                "verified": True,
                "reason": CHAIN_REASON,
                "chain_id": CHAIN_ID,
                "completed_handoffs": decision.completed_handoffs,
                "genesis_policy_epoch": 1,
                "current_policy_epoch": decision.current_policy_epoch,
                "current_policy_sha256": decision.current_policy_sha256,
                "chain_ref_sha256": decision.chain_ref_sha256,
                "chain_root_sha256": decision.chain_root_sha256,
                "parallel_direct_successor_fork_detected": True,
                "fork_reason": CHAIN_FORK_REASON,
                "active_chain_ref_field_count": len(third.chain_ref),
                "conditional_handoff_chain_status": (
                    CONDITIONAL_HANDOFF_CHAIN_STATUS
                ),
                "global_non_equivocation_status": "unproven",
                "raw_handoff_history_embedded_in_active_ref": False,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
