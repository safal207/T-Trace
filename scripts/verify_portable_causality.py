#!/usr/bin/env python3
"""Verify a T-Trace Portable Causality Profile fixture."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from ttrace.portable_causality import (
    BranchEvidence,
    ReconciliationVote,
    digest_json,
    reconcile_two_branches,
    validate_reconciliation_agreement,
    validate_state_ref,
)


def _load_object(path: Path) -> Dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("fixture_object_required")
    return value


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("fixture", type=Path)
    args = parser.parse_args()

    try:
        fixture = _load_object(args.fixture)
        common = fixture.get("common_state_ref")
        if not validate_state_ref(common):
            raise ValueError("common_state_ref_invalid")
        branch_values = fixture.get("branch_evidence")
        vote_values = fixture.get("reconciliation_votes")
        if not isinstance(branch_values, list) or not isinstance(vote_values, list):
            raise ValueError("branch_and_vote_arrays_required")
        branches = tuple(BranchEvidence(**item) for item in branch_values)
        votes = tuple(ReconciliationVote(**item) for item in vote_values)
        agreement = reconcile_two_branches(common, branches, votes)
        if not agreement.verified:
            raise ValueError(agreement.reason)
        if not validate_reconciliation_agreement(agreement, common):
            raise ValueError("reconciliation_agreement_invalid")

        expected = fixture.get("expected")
        if not isinstance(expected, dict):
            raise ValueError("expected_digests_required")
        actual = {
            "parent_set_sha256": digest_json(agreement.parent_set),
            "reconciled_state_ref_sha256": digest_json(
                agreement.reconciled_state_ref
            ),
            "reconciliation_ref_sha256": digest_json(agreement.reconciliation_ref),
            "receipt_sha256": digest_json(agreement.receipt),
        }
        mismatched = sorted(
            key
            for key in set(actual) | set(expected)
            if actual.get(key) != expected.get(key)
        )
        if mismatched:
            details = ", ".join(
                "%s: expected=%r actual=%r"
                % (key, expected.get(key), actual.get(key))
                for key in mismatched
            )
            raise ValueError("expected_digest_mismatch: %s" % details)
        print(
            "PASS %s (fork epoch %s -> reconciled epoch %s; receipt %s)"
            % (
                args.fixture,
                agreement.receipt["fork_causal_epoch"],
                agreement.receipt["reconciled_causal_epoch"],
                actual["receipt_sha256"],
            )
        )
        return 0
    except (KeyError, OSError, TypeError, ValueError) as error:
        print("FAIL %s: %s" % (args.fixture, error))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
