from __future__ import annotations

from dataclasses import replace

import pytest

from ttrace.portable_causality import (
    BranchEvidence,
    CausalValidationError,
    ReconciliationVote,
    build_branch_tip,
    build_transition_ref,
    canonical_json_bytes,
    digest_json,
    make_state_ref,
    reconcile_two_branches,
    validate_reconciliation_agreement,
    validate_transition_ref,
)


def _sha(label: str) -> str:
    return digest_json({"label": label})


def _common_state():
    return make_state_ref(
        trust_domain="example.procurement",
        logical_state_id="authorization-state",
        causal_epoch=2,
        semantic_state_sha256=_sha("common-state"),
    )


def _branches(common):
    shared = {
        "from_state_ref_sha256": digest_json(common),
        "branch_contract_sha256": _sha("branch-contract"),
        "authorization_contract_sha256": _sha("branch-authorization"),
        "trust_domain": common["trust_domain"],
    }
    a = BranchEvidence(
        verified=True,
        provider_id="github-oidc-branch-a",
        authority_id="oidc:branch-a",
        provenance_sha256=_sha("branch-a-provenance"),
        logical_branch_id="policy-fork-a",
        to_semantic_state_sha256=_sha("branch-a-state"),
        **shared,
    )
    b = BranchEvidence(
        verified=True,
        provider_id="offline-ed25519-branch-b",
        authority_id="ed25519:branch-b",
        provenance_sha256=_sha("branch-b-provenance"),
        logical_branch_id="policy-fork-b",
        to_semantic_state_sha256=_sha("branch-b-state"),
        **shared,
    )
    return a, b


def _votes(common, branches):
    target = _sha("reconciled-state")
    contract = _sha("reconciliation-contract")
    authorization = _sha("reconciliation-authorization")
    result = []
    for index, branch in enumerate(branches):
        tip = build_branch_tip(common, branch)
        result.append(
            ReconciliationVote(
                verified=True,
                provider_id=branch.provider_id,
                authority_id=branch.authority_id,
                provenance_sha256=_sha("vote-%s" % index),
                trust_domain=branch.trust_domain,
                logical_reconciliation_id="policy-fork-reconcile-v0.1",
                branch_ref_sha256=digest_json(tip["branch_ref"]),
                branch_state_ref_sha256=digest_json(tip["state_ref"]),
                branch_tip_sha256=digest_json(tip),
                target_semantic_state_sha256=target,
                reconciliation_contract_sha256=contract,
                authorization_contract_sha256=authorization,
            )
        )
    return tuple(result)


def _agreement():
    common = _common_state()
    branches = _branches(common)
    votes = _votes(common, branches)
    agreement = reconcile_two_branches(common, branches, votes)
    return common, branches, votes, agreement


def test_canonical_json_is_key_order_independent() -> None:
    assert canonical_json_bytes({"b": 2, "a": 1}) == canonical_json_bytes(
        {"a": 1, "b": 2}
    )


def test_linear_transition_advances_portable_epoch() -> None:
    common = _common_state()
    next_state, transition = build_transition_ref(
        common,
        logical_transition_id="policy-update",
        next_semantic_state_sha256=_sha("next-state"),
        transition_contract_sha256=_sha("transition-contract"),
        authorization_contract_sha256=_sha("transition-authorization"),
    )
    assert next_state["causal_epoch"] == 3
    assert transition["from_causal_epoch"] == 2
    assert transition["to_causal_epoch"] == 3
    assert validate_transition_ref(
        transition,
        previous_state_ref=common,
        next_state_ref=next_state,
    )


def test_causal_transition_rejects_semantic_noop() -> None:
    common = _common_state()
    with pytest.raises(CausalValidationError, match="causal_transition_semantic_noop"):
        build_transition_ref(
            common,
            logical_transition_id="noop",
            next_semantic_state_sha256=common["semantic_state_sha256"],
            transition_contract_sha256=_sha("transition-contract"),
            authorization_contract_sha256=_sha("transition-authorization"),
        )


def test_two_divergent_branches_reconcile_and_preserve_both_parents() -> None:
    common, _, _, agreement = _agreement()
    assert agreement.verified is True
    assert agreement.reason == "portable_causal_reconciliation_verified"
    assert agreement.receipt is not None
    assert agreement.receipt["fork_causal_epoch"] == 3
    assert agreement.receipt["reconciled_causal_epoch"] == 4
    assert agreement.receipt["lineage_parent_count"] == 2
    assert agreement.receipt["both_lineages_preserved"] is True
    assert agreement.receipt["fork_semantics_divergent"] is True
    assert agreement.receipt["branch_order_canonical"] is True
    assert agreement.receipt["raw_evidence_embedded"] is False
    assert validate_reconciliation_agreement(agreement, common)


def test_branch_input_order_does_not_change_portable_bytes() -> None:
    common = _common_state()
    branches = _branches(common)
    votes = _votes(common, branches)
    forward = reconcile_two_branches(common, branches, votes)
    reverse = reconcile_two_branches(
        common,
        tuple(reversed(branches)),
        tuple(reversed(votes)),
    )
    assert forward.verified and reverse.verified
    assert canonical_json_bytes(forward.to_dict()) == canonical_json_bytes(
        reverse.to_dict()
    )


def test_provider_authority_and_provenance_are_not_portable_identity() -> None:
    _, branches, votes, agreement = _agreement()
    portable = canonical_json_bytes(agreement.to_dict()).decode("utf-8")
    forbidden = {
        *(branch.provider_id for branch in branches),
        *(branch.authority_id for branch in branches),
        *(branch.provenance_sha256 for branch in branches),
        *(vote.provenance_sha256 for vote in votes),
    }
    assert all(value not in portable for value in forbidden)


@pytest.mark.parametrize(
    ("mutate", "reason"),
    [
        (
            lambda common, a, b, va, vb: (
                common,
                replace(a, verified=False),
                b,
                va,
                vb,
            ),
            "branch_evidence_invalid",
        ),
        (
            lambda common, a, b, va, vb: (
                common,
                a,
                replace(b, provider_id=a.provider_id),
                va,
                replace(vb, provider_id=a.provider_id),
            ),
            "branch_provider_not_independent",
        ),
        (
            lambda common, a, b, va, vb: (
                common,
                a,
                replace(b, authority_id=a.authority_id),
                va,
                replace(vb, authority_id=a.authority_id),
            ),
            "branch_authority_not_independent",
        ),
        (
            lambda common, a, b, va, vb: (
                common,
                a,
                replace(b, provenance_sha256=a.provenance_sha256),
                va,
                vb,
            ),
            "branch_provenance_not_independent",
        ),
        (
            lambda common, a, b, va, vb: (
                common,
                a,
                replace(b, logical_branch_id=a.logical_branch_id),
                va,
                vb,
            ),
            "logical_branch_id_duplicate",
        ),
        (
            lambda common, a, b, va, vb: (
                common,
                a,
                replace(b, to_semantic_state_sha256=a.to_semantic_state_sha256),
                va,
                vb,
            ),
            "fork_semantics_not_divergent",
        ),
        (
            lambda common, a, b, va, vb: (
                common,
                a,
                replace(b, branch_contract_sha256=_sha("other-contract")),
                va,
                vb,
            ),
            "branch_contract_mismatch",
        ),
        (
            lambda common, a, b, va, vb: (
                common,
                a,
                b,
                va,
                replace(vb, target_semantic_state_sha256=_sha("other-target")),
            ),
            "reconciliation_target_mismatch",
        ),
        (
            lambda common, a, b, va, vb: (
                common,
                a,
                b,
                va,
                replace(vb, branch_tip_sha256=_sha("wrong-tip")),
            ),
            "vote_branch_tip_binding_mismatch",
        ),
    ],
)
def test_fork_reconciliation_fails_closed(mutate, reason: str) -> None:
    common = _common_state()
    a, b = _branches(common)
    va, vb = _votes(common, (a, b))
    common, a, b, va, vb = mutate(common, a, b, va, vb)
    agreement = reconcile_two_branches(common, (a, b), (va, vb))
    assert agreement.verified is False
    assert agreement.reason == reason


def test_wrong_common_state_binding_fails_closed() -> None:
    common = _common_state()
    a, b = _branches(common)
    votes = _votes(common, (a, b))
    a = replace(a, from_state_ref_sha256=_sha("wrong-common"))
    agreement = reconcile_two_branches(common, (a, b), votes)
    assert agreement.verified is False
    assert agreement.reason == "branch_common_state_mismatch"


def test_missing_vote_fails_closed() -> None:
    common = _common_state()
    branches = _branches(common)
    votes = _votes(common, branches)
    agreement = reconcile_two_branches(common, branches, votes[:1])
    assert agreement.verified is False
    assert agreement.reason == "vote_cardinality_invalid"


def test_reconciliation_target_must_be_new() -> None:
    common = _common_state()
    branches = _branches(common)
    votes = _votes(common, branches)
    bad = tuple(
        replace(vote, target_semantic_state_sha256=branches[0].to_semantic_state_sha256)
        for vote in votes
    )
    agreement = reconcile_two_branches(common, branches, bad)
    assert agreement.verified is False
    assert agreement.reason == "reconciliation_target_not_new"
