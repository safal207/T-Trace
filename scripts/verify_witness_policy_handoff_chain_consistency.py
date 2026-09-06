#!/usr/bin/env python3
"""Verify append-only consistency between handoff-chain membership roots."""

from __future__ import annotations

from copy import deepcopy
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.verify_witness_policy_handoff_chain import (  # noqa: E402
    CHAIN_AUTHORIZATION,
    CHAIN_CONTRACT,
    CHAIN_ID,
    build_canonical_handoff_chain_fixture,
)
from ttrace.lineage_compaction import ZERO_SHA256  # noqa: E402
from ttrace.lineage_witness_handoff_chain import (  # noqa: E402
    advance_witness_policy_handoff_chain,
    build_seed_witness_policy_handoff_chain,
)
from ttrace.lineage_witness_handoff_chain_consistency import (  # noqa: E402
    HANDOFF_CHAIN_MEMBERSHIP_ROOT_CONSISTENCY_REASON,
    build_witness_policy_handoff_chain_membership_anchor_statement,
    build_witness_policy_handoff_chain_membership_root_consistency_package,
    detect_witness_policy_handoff_chain_membership_anchor_equivocation,
    validate_witness_policy_handoff_chain_membership_equivocation_evidence,
    verify_authorized_witness_policy_handoff_chain_membership_root_consistency,
    verify_witness_policy_handoff_chain_membership_root_consistency,
)
from ttrace.lineage_witness_handoff_chain_membership import (  # noqa: E402
    build_witness_policy_handoff_chain_membership_anchor,
)
from ttrace.portable_causality import digest_json  # noqa: E402


MEMBERSHIP_CONTRACT = digest_json(
    {"contract": "witness-policy-handoff-chain-membership/v0.1"}
)
MEMBERSHIP_AUTHORIZATION = digest_json(
    {"contract": "witness-policy-handoff-chain-membership-authorization/v0.1"}
)


def _refs(packages, genesis_policy_sha256: str):
    seed = build_seed_witness_policy_handoff_chain(
        packages[0],
        chain_id=CHAIN_ID,
        expected_genesis_policy_epoch=1,
        expected_genesis_policy_sha256=genesis_policy_sha256,
        chain_contract_sha256=CHAIN_CONTRACT,
        authorization_contract_sha256=CHAIN_AUTHORIZATION,
    )
    if not seed.verified or seed.chain_ref is None:
        raise ValueError(f"seed_rejected:{seed.reason}")
    refs = [seed.chain_ref]
    for package in packages[1:]:
        advanced = advance_witness_policy_handoff_chain(refs[-1], package)
        if not advanced.verified or advanced.chain_ref is None:
            raise ValueError(f"advance_rejected:{advanced.reason}")
        refs.append(advanced.chain_ref)
    return tuple(refs)


def main() -> int:
    fixture = build_canonical_handoff_chain_fixture()
    packages = fixture["packages"]
    genesis = digest_json(fixture["policies"][0])
    refs = _refs(packages, genesis)

    consistency_package = (
        build_witness_policy_handoff_chain_membership_root_consistency_package(
            packages[:1],
            refs[0],
            packages,
            refs[2],
            membership_contract_sha256=MEMBERSHIP_CONTRACT,
            authorization_contract_sha256=MEMBERSHIP_AUTHORIZATION,
        )
    )
    decision = verify_witness_policy_handoff_chain_membership_root_consistency(
        consistency_package
    )
    if not decision.verified:
        raise ValueError(f"consistency_rejected:{decision.reason}")

    old_endpoint = consistency_package["old_endpoint"]
    new_endpoint = consistency_package["new_endpoint"]
    old_statement = build_witness_policy_handoff_chain_membership_anchor_statement(
        old_endpoint["membership_anchor"],
        old_endpoint["current_chain_ref"],
        verified=True,
        authority_id="example.handoff-membership-anchor-authority",
        statement_sequence=1,
        previous_statement_sha256=ZERO_SHA256,
        statement_provenance_sha256=digest_json({"statement": "old"}),
    )
    new_statement = build_witness_policy_handoff_chain_membership_anchor_statement(
        new_endpoint["membership_anchor"],
        new_endpoint["current_chain_ref"],
        verified=True,
        authority_id="example.handoff-membership-anchor-authority",
        statement_sequence=2,
        previous_statement_sha256=digest_json(old_statement),
        statement_provenance_sha256=digest_json({"statement": "new"}),
    )
    authorized = (
        verify_authorized_witness_policy_handoff_chain_membership_root_consistency(
            consistency_package, old_statement, new_statement
        )
    )
    if not authorized.verified:
        raise ValueError(f"authorized_consistency_rejected:{authorized.reason}")

    canonical_two_anchor = (
        build_witness_policy_handoff_chain_membership_anchor(
            packages[:2],
            refs[1],
            membership_contract_sha256=MEMBERSHIP_CONTRACT,
            authorization_contract_sha256=MEMBERSHIP_AUTHORIZATION,
        )
    )
    alternate_packages = (packages[0], fixture["alternate_second_package"])
    alternate_refs = _refs(alternate_packages, genesis)
    alternate_two_anchor = (
        build_witness_policy_handoff_chain_membership_anchor(
            alternate_packages,
            alternate_refs[1],
            membership_contract_sha256=MEMBERSHIP_CONTRACT,
            authorization_contract_sha256=MEMBERSHIP_AUTHORIZATION,
        )
    )
    common_predecessor = digest_json(old_statement)
    canonical_two_statement = (
        build_witness_policy_handoff_chain_membership_anchor_statement(
            canonical_two_anchor,
            refs[1],
            verified=True,
            authority_id="example.handoff-membership-anchor-authority",
            statement_sequence=2,
            previous_statement_sha256=common_predecessor,
            statement_provenance_sha256=digest_json({"statement": "canonical-two"}),
        )
    )
    alternate_two_statement = (
        build_witness_policy_handoff_chain_membership_anchor_statement(
            alternate_two_anchor,
            alternate_refs[1],
            verified=True,
            authority_id="example.handoff-membership-anchor-authority",
            statement_sequence=2,
            previous_statement_sha256=common_predecessor,
            statement_provenance_sha256=digest_json({"statement": "alternate-two"}),
        )
    )
    equivocation = detect_witness_policy_handoff_chain_membership_anchor_equivocation(
        canonical_two_anchor,
        refs[1],
        canonical_two_statement,
        alternate_two_anchor,
        alternate_refs[1],
        alternate_two_statement,
    )
    if (
        not equivocation.verified
        or not equivocation.equivocation_detected
        or equivocation.evidence is None
        or not validate_witness_policy_handoff_chain_membership_equivocation_evidence(
            equivocation.evidence,
            canonical_two_anchor,
            refs[1],
            canonical_two_statement,
            alternate_two_anchor,
            alternate_refs[1],
            alternate_two_statement,
        )
    ):
        raise ValueError("equivocation_evidence_not_verified")

    tampered = deepcopy(consistency_package)
    tampered["consistency_proof"]["append_blocks"][0]["sha256"] = digest_json(
        {"tampered": "append-block"}
    )
    if verify_witness_policy_handoff_chain_membership_root_consistency(
        tampered
    ).verified:
        raise ValueError("tampered_append_block_accepted")

    print(
        json.dumps(
            {
                "verified": True,
                "reason": HANDOFF_CHAIN_MEMBERSHIP_ROOT_CONSISTENCY_REASON,
                "old_tree_size": decision.old_tree_size,
                "new_tree_size": decision.new_tree_size,
                "old_anchor_sha256": decision.old_anchor_sha256,
                "new_anchor_sha256": decision.new_anchor_sha256,
                "old_frontier_node_count": decision.old_frontier_node_count,
                "append_block_count": decision.append_block_count,
                "old_current_path_hash_count": (
                    decision.old_current_path_hash_count
                ),
                "new_current_path_hash_count": (
                    decision.new_current_path_hash_count
                ),
                "append_only_consistent": decision.append_only_consistent,
                "current_steps_membership_bound": (
                    decision.current_steps_membership_bound
                ),
                "raw_handoff_packages_disclosed": (
                    decision.raw_handoff_packages_disclosed
                ),
                "membership_anchor_authorization_status": (
                    decision.membership_anchor_authorization_status
                ),
                "current_tip_freshness_status": decision.current_tip_freshness_status,
                "rolling_chain_descendance_status": (
                    decision.rolling_chain_descendance_status
                ),
                "authorized_transition_verified": authorized.verified,
                "presented_equivocation_detected": (
                    equivocation.equivocation_detected
                ),
                "equivocation_evidence_verified": True,
                "global_non_equivocation_status": (
                    decision.global_non_equivocation_status
                ),
            },
            sort_keys=True,
            separators=(",", ":"),
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
