#!/usr/bin/env python3
"""Verify deterministic selective disclosure from a witness-policy handoff chain."""

from __future__ import annotations

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
from ttrace.lineage_witness_handoff_chain import (  # noqa: E402
    advance_witness_policy_handoff_chain,
    build_seed_witness_policy_handoff_chain,
)
from ttrace.lineage_witness_handoff import (  # noqa: E402
    LINEAGE_WITNESS_POLICY_HANDOFF_PACKAGE_SCHEMA,
)
from ttrace.lineage_witness_handoff_chain_membership import (  # noqa: E402
    HANDOFF_CHAIN_MEMBERSHIP_ANCHOR_AUTHORIZATION_STATUS,
    HANDOFF_CHAIN_MEMBERSHIP_CURRENT_TIP_FRESHNESS_STATUS,
    HANDOFF_CHAIN_MEMBERSHIP_REASON,
    HANDOFF_CHAIN_MEMBERSHIP_TREE_ALGORITHM,
    build_selective_witness_policy_handoff_chain_disclosure,
    verify_selective_witness_policy_handoff_chain_disclosure,
)
from ttrace.portable_causality import digest_json  # noqa: E402

MEMBERSHIP_CONTRACT = digest_json(
    {"contract": "witness-policy-handoff-chain-membership/v0.1"}
)
MEMBERSHIP_AUTHORIZATION = digest_json(
    {"contract": "witness-policy-handoff-chain-membership-authorization/v0.1"}
)


def _count_schema(value, schema: str) -> int:
    if isinstance(value, dict):
        own = 1 if value.get("schema") == schema else 0
        return own + sum(_count_schema(item, schema) for item in value.values())
    if isinstance(value, (list, tuple)):
        return sum(_count_schema(item, schema) for item in value)
    return 0


def _active_tip(packages, genesis_policy_sha256: str):
    result = build_seed_witness_policy_handoff_chain(
        packages[0],
        chain_id=CHAIN_ID,
        expected_genesis_policy_epoch=1,
        expected_genesis_policy_sha256=genesis_policy_sha256,
        chain_contract_sha256=CHAIN_CONTRACT,
        authorization_contract_sha256=CHAIN_AUTHORIZATION,
    )
    if not result.verified or result.chain_ref is None:
        raise ValueError(f"seed_rejected:{result.reason}")
    current = result.chain_ref
    for package in packages[1:]:
        result = advance_witness_policy_handoff_chain(current, package)
        if not result.verified or result.chain_ref is None:
            raise ValueError(f"handoff_rejected:{result.reason}")
        current = result.chain_ref
    return current


def main() -> int:
    fixture = build_canonical_handoff_chain_fixture()
    packages = fixture["packages"]
    current_ref = _active_tip(packages, digest_json(fixture["policies"][0]))
    disclosure = build_selective_witness_policy_handoff_chain_disclosure(
        packages,
        current_ref,
        selected_handoff_index=2,
        membership_contract_sha256=MEMBERSHIP_CONTRACT,
        authorization_contract_sha256=MEMBERSHIP_AUTHORIZATION,
    )
    decision = verify_selective_witness_policy_handoff_chain_disclosure(
        disclosure
    )
    if not decision.verified:
        raise ValueError(f"membership_rejected:{decision.reason}")

    proof = disclosure["membership_proof"]
    disclosed = disclosure["disclosed_handoff"]
    disclosed_package_count = _count_schema(
        disclosure, LINEAGE_WITNESS_POLICY_HANDOFF_PACKAGE_SCHEMA
    )
    if disclosed_package_count != 1:
        raise ValueError("selective_disclosure_package_count_invalid")
    print(
        json.dumps(
            {
                "verified": True,
                "reason": HANDOFF_CHAIN_MEMBERSHIP_REASON,
                "chain_id": CHAIN_ID,
                "completed_handoffs": current_ref["completed_handoffs"],
                "current_policy_epoch": current_ref["current_policy_epoch"],
                "disclosed_handoff_index": decision.disclosed_handoff_index,
                "anchor_sha256": decision.anchor_sha256,
                "step_commitment_sha256": decision.step_commitment_sha256,
                "selected_sibling_hash_count": (
                    decision.selected_sibling_hash_count
                ),
                "current_sibling_hash_count": (
                    decision.current_sibling_hash_count
                ),
                "sibling_hash_count": decision.sibling_hash_count,
                "tree_algorithm": HANDOFF_CHAIN_MEMBERSHIP_TREE_ALGORITHM,
                "selected_handoff_package_disclosed": (
                    isinstance(disclosed.get("handoff_package"), dict)
                ),
                "intermediate_handoff_packages_disclosed": (
                    disclosed_package_count - 1
                ),
                "current_tip_membership_path_present": bool(
                    proof["current_step_sibling_path"]
                ),
                "membership_anchor_authorization_status": (
                    HANDOFF_CHAIN_MEMBERSHIP_ANCHOR_AUTHORIZATION_STATUS
                ),
                "current_tip_freshness_status": (
                    HANDOFF_CHAIN_MEMBERSHIP_CURRENT_TIP_FRESHNESS_STATUS
                ),
                "global_non_equivocation_status": "unproven",
            },
            sort_keys=True,
            separators=(",", ":"),
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
