from __future__ import annotations

from copy import deepcopy
from dataclasses import replace

import pytest

from ttrace import (
    BranchObservation,
    CausalStateRef,
    advance_state,
    build_fork_branch,
    build_reconciliation_vote,
    build_transition_ref,
    canonical_json_bytes,
    digest_object,
    reconcile_two_branches,
    validate_reconciliation_result,
)
from ttrace.reconciliation import ReconciliationResult


def _sha(label: str) -> str:
    return digest_object({"fixture": label})


def _common() -> tuple[CausalStateRef, str, str]:
    state = CausalStateRef(
        trust_domain="ttrace.authorization",
        logical_state_id="purchase-42",
        causal_epoch=2,
        semantic_state_sha256=_sha("common-state"),
    )
    return state, _sha("common-checkpoint"), _sha("common-witness")


def _fork_pair():
    common, common_checkpoint, common_witness = _common()
    branch_contract = _sha("branch-contract")
    branch_auth = _sha("branch-authorization")
    branch_a = build_fork_branch(
        common,
        common_checkpoint_sha256=common_checkpoint,
        common_witness_sha256=common_witness,
        logical_branch_id="approve-with-provider-a",
        semantic_state_sha256=_sha("branch-a-state"),
        branch_contract_sha256=branch_contract,
        authorization_contract_sha256=branch_auth,
    )
    branch_b = build_fork_branch(
        common,
        common_checkpoint_sha256=common_checkpoint,
        common_witness_sha256=common_witness,
        logical_branch_id="approve-with-provider-b",
        semantic_state_sha256=_sha("branch-b-state"),
        branch_contract_sha256=branch_contract,
        authorization_contract_sha256=branch_auth,
    )
    observation_a = BranchObservation(
        verified=True,
        provider_id="github-oidc-a",
        authority_id="authority-a",
        evidence_sha256=_sha("branch-a-evidence"),
        branch=branch_a,
    )
    observation_b = BranchObservation(
        verified=True,
        provider_id="offline-ed25519-b",
        authority_id="authority-b",
        evidence_sha256=_sha("branch-b-evidence"),
        branch=branch_b,
    )
    target = _sha("reconciled-state")
    reconciliation_contract = _sha("reconciliation-contract")
    reconciliation_auth = _sha("reconciliation-authorization")
    vote_a = build_reconciliation_vote(
        observation_a,
        vote_evidence_sha256=_sha("vote-a"),
        target_semantic_state_sha256=target,
        reconciliation_contract_sha256=reconciliation_contract,
        authorization_contract_sha256=reconciliation_auth,
    )
    vote_b = build_reconciliation_vote(
        observation_b,
        vote_evidence_sha256=_sha("vote-b"),
        target_semantic_state_sha256=target,
        reconciliation_contract_sha256=reconciliation_contract,
        authorization_contract_sha256=reconciliation_auth,
    )
    return (
        common,
        common_checkpoint,
        common_witness,
        observation_a,
        observation_b,
        vote_a,
        vote_b,
    )


def _reconcile(reverse: bool = False):
    (
        common,
        checkpoint,
        witness,
        observation_a,
        observation_b,
        vote_a,
        vote_b,
    ) = _fork_pair()
    if reverse:
        observation_a, observation_b = observation_b, observation_a
        vote_a, vote_b = vote_b, vote_a
    result = reconcile_two_branches(
        common,
        common_checkpoint_sha256=checkpoint,
        common_witness_sha256=witness,
        logical_reconciliation_id="resolve-provider-fork",
        primary=observation_a,
        secondary=observation_b,
        primary_vote=vote_a,
        secondary_vote=vote_b,
    )
    return result, common, checkpoint, witness


def test_state_and_transition_are_history_free_and_deterministic() -> None:
    state, _, _ = _common()
    next_state = advance_state(state, semantic_state_sha256=_sha("next-state"))
    transition = build_transition_ref(
        state,
        next_state,
        logical_transition_id="authorize-next-policy",
        transition_contract_sha256=_sha("transition-contract"),
        authorization_contract_sha256=_sha("transition-auth"),
    )

    assert next_state.causal_epoch == 3
    assert transition.from_state_ref_sha256 == state.digest()
    assert transition.to_state_ref_sha256 == next_state.digest()
    encoded = canonical_json_bytes(transition.to_dict())
    assert b"provider" not in encoded
    assert b"registry" not in encoded
    assert b"manifest" not in encoded


def test_epoch_gap_and_semantic_noop_fail_closed() -> None:
    state, _, _ = _common()
    with pytest.raises(ValueError, match="semantic_state_did_not_change"):
        advance_state(state, semantic_state_sha256=state.semantic_state_sha256)

    wrong_epoch = CausalStateRef(
        trust_domain=state.trust_domain,
        logical_state_id=state.logical_state_id,
        causal_epoch=state.causal_epoch + 2,
        semantic_state_sha256=_sha("wrong-epoch"),
    )
    with pytest.raises(ValueError, match="causal_epoch_gap"):
        build_transition_ref(
            state,
            wrong_epoch,
            logical_transition_id="skip",
            transition_contract_sha256=_sha("contract"),
            authorization_contract_sha256=_sha("auth"),
        )


def test_two_divergent_branches_reconcile_and_preserve_both_lineages() -> None:
    result, common, checkpoint, witness = _reconcile()

    assert result.state_ref.causal_epoch == 4
    assert result.receipt["verified"] is True
    assert result.receipt["lineage_parent_count"] == 2
    assert result.receipt["both_lineages_preserved"] is True
    assert result.receipt["fork_semantics_divergent"] is True
    assert result.receipt["raw_evidence_embedded"] is False
    assert len(result.reconciliation_ref["parents"]) == 2
    assert validate_reconciliation_result(
        result,
        common_state=common,
        common_checkpoint_sha256=checkpoint,
        common_witness_sha256=witness,
    )


def test_branch_input_order_does_not_change_portable_bytes() -> None:
    forward, _, _, _ = _reconcile(False)
    reverse, _, _, _ = _reconcile(True)
    assert canonical_json_bytes(forward.to_dict()) == canonical_json_bytes(
        reverse.to_dict()
    )
    assert forward.digest() == reverse.digest()


def test_provider_authority_and_evidence_are_not_portable_identity() -> None:
    result, _, _, _ = _reconcile()
    portable = canonical_json_bytes(result.to_dict())
    for forbidden in (
        b"github-oidc-a",
        b"offline-ed25519-b",
        b"authority-a",
        b"authority-b",
        _sha("branch-a-evidence").encode(),
        _sha("branch-b-evidence").encode(),
        _sha("vote-a").encode(),
        _sha("vote-b").encode(),
    ):
        assert forbidden not in portable


def test_same_provider_authority_or_evidence_fails_closed() -> None:
    common, cp, witness, a, b, va, vb = _fork_pair()
    cases = [
        (b.__class__(True, a.provider_id, b.authority_id, b.evidence_sha256, b.branch), "branch_provider_not_independent"),
        (b.__class__(True, b.provider_id, a.authority_id, b.evidence_sha256, b.branch), "branch_authority_not_independent"),
        (b.__class__(True, b.provider_id, b.authority_id, a.evidence_sha256, b.branch), "branch_evidence_not_independent"),
    ]
    for changed_b, reason in cases:
        with pytest.raises(ValueError, match=reason):
            reconcile_two_branches(
                common,
                common_checkpoint_sha256=cp,
                common_witness_sha256=witness,
                logical_reconciliation_id="resolve-provider-fork",
                primary=a,
                secondary=changed_b,
                primary_vote=va,
                secondary_vote=vb,
            )


def test_vote_bound_to_wrong_branch_fails_closed() -> None:
    common, cp, witness, a, b, va, vb = _fork_pair()
    bad_vote = replace(vb, branch_checkpoint_sha256=_sha("wrong-checkpoint"))
    with pytest.raises(ValueError, match="reconciliation_vote_branch_binding_mismatch"):
        reconcile_two_branches(
            common,
            common_checkpoint_sha256=cp,
            common_witness_sha256=witness,
            logical_reconciliation_id="resolve-provider-fork",
            primary=a,
            secondary=b,
            primary_vote=va,
            secondary_vote=bad_vote,
        )


def test_non_divergent_fork_fails_closed() -> None:
    common, cp, witness, a, b, va, vb = _fork_pair()
    same_branch = build_fork_branch(
        common,
        common_checkpoint_sha256=cp,
        common_witness_sha256=witness,
        logical_branch_id="different-logical-id",
        semantic_state_sha256=a.branch.state_ref.semantic_state_sha256,
        branch_contract_sha256=_sha("branch-contract"),
        authorization_contract_sha256=_sha("branch-authorization"),
    )
    changed_b = BranchObservation(
        True,
        b.provider_id,
        b.authority_id,
        b.evidence_sha256,
        same_branch,
    )
    changed_vote = build_reconciliation_vote(
        changed_b,
        vote_evidence_sha256=vb.evidence_sha256,
        target_semantic_state_sha256=vb.target_semantic_state_sha256,
        reconciliation_contract_sha256=vb.reconciliation_contract_sha256,
        authorization_contract_sha256=vb.authorization_contract_sha256,
    )
    with pytest.raises(ValueError, match="fork_semantics_not_divergent"):
        reconcile_two_branches(
            common,
            common_checkpoint_sha256=cp,
            common_witness_sha256=witness,
            logical_reconciliation_id="resolve-provider-fork",
            primary=a,
            secondary=changed_b,
            primary_vote=va,
            secondary_vote=changed_vote,
        )


def test_tampered_parent_set_is_rejected() -> None:
    result, common, checkpoint, witness = _reconcile()
    tampered_ref = deepcopy(result.reconciliation_ref)
    tampered_ref["parents"] = tampered_ref["parents"][:1]
    tampered = ReconciliationResult(
        state_ref=result.state_ref,
        reconciliation_ref=tampered_ref,
        checkpoint=result.checkpoint,
        witness=result.witness,
        receipt=result.receipt,
    )
    assert not validate_reconciliation_result(
        tampered,
        common_state=common,
        common_checkpoint_sha256=checkpoint,
        common_witness_sha256=witness,
    )
