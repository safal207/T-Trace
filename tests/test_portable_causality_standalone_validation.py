from __future__ import annotations

from copy import deepcopy

from ttrace.portable_causality import (
    BranchEvidence,
    ReconciliationAgreement,
    ReconciliationVote,
    build_branch_tip,
    digest_json,
    make_state_ref,
    reconcile_two_branches,
    validate_reconciliation_agreement,
)


def _sha(label: str) -> str:
    return digest_json({"label": label})


def _fixture():
    common = make_state_ref(
        trust_domain="example.procurement",
        logical_state_id="authorization-state",
        causal_epoch=2,
        semantic_state_sha256=_sha("common-state"),
    )
    shared = {
        "from_state_ref_sha256": digest_json(common),
        "branch_contract_sha256": _sha("branch-contract"),
        "authorization_contract_sha256": _sha("branch-authorization"),
        "trust_domain": common["trust_domain"],
    }
    branches = (
        BranchEvidence(
            verified=True,
            provider_id="provider-a",
            authority_id="authority-a",
            provenance_sha256=_sha("branch-a-proof"),
            logical_branch_id="branch-a",
            to_semantic_state_sha256=_sha("state-a"),
            **shared,
        ),
        BranchEvidence(
            verified=True,
            provider_id="provider-b",
            authority_id="authority-b",
            provenance_sha256=_sha("branch-b-proof"),
            logical_branch_id="branch-b",
            to_semantic_state_sha256=_sha("state-b"),
            **shared,
        ),
    )
    votes = []
    for index, branch in enumerate(branches):
        tip = build_branch_tip(common, branch)
        votes.append(
            ReconciliationVote(
                verified=True,
                provider_id=branch.provider_id,
                authority_id=branch.authority_id,
                provenance_sha256=_sha("vote-%d" % index),
                trust_domain=branch.trust_domain,
                logical_reconciliation_id="reconcile-v0.1",
                branch_ref_sha256=digest_json(tip["branch_ref"]),
                branch_state_ref_sha256=digest_json(tip["state_ref"]),
                branch_tip_sha256=digest_json(tip),
                target_semantic_state_sha256=_sha("reconciled-state"),
                reconciliation_contract_sha256=_sha("reconciliation-contract"),
                authorization_contract_sha256=_sha("reconciliation-authorization"),
            )
        )
    agreement = reconcile_two_branches(common, branches, tuple(votes))
    assert agreement.verified is True
    return common, agreement


def _rebind_parent_material(agreement: ReconciliationAgreement) -> None:
    assert agreement.parent_set is not None
    assert agreement.reconciliation_ref is not None
    assert agreement.receipt is not None
    parents = [
        {
            "branch_tip_sha256": digest_json(tip),
            "branch_ref_sha256": digest_json(tip["branch_ref"]),
            "state_ref_sha256": digest_json(tip["state_ref"]),
        }
        for tip in agreement.branch_tips
    ]
    agreement.parent_set["parents"] = parents
    agreement.reconciliation_ref["parent_set_sha256"] = digest_json(
        agreement.parent_set
    )
    agreement.reconciliation_ref["parent_tip_sha256"] = [
        item["branch_tip_sha256"] for item in parents
    ]
    agreement.receipt["parent_set_sha256"] = digest_json(agreement.parent_set)
    agreement.receipt["reconciliation_ref_sha256"] = digest_json(
        agreement.reconciliation_ref
    )


def test_standalone_validator_rejects_duplicate_parent_tip() -> None:
    common, source = _fixture()
    tip = deepcopy(source.branch_tips[0])
    forged = ReconciliationAgreement(
        True,
        source.reason,
        (deepcopy(tip), deepcopy(tip)),
        deepcopy(source.parent_set),
        deepcopy(source.reconciled_state_ref),
        deepcopy(source.reconciliation_ref),
        deepcopy(source.receipt),
    )
    _rebind_parent_material(forged)
    assert validate_reconciliation_agreement(forged, common) is False


def test_standalone_validator_rejects_non_divergent_semantics() -> None:
    common, source = _fixture()
    tips = [deepcopy(item) for item in source.branch_tips]
    tips[1]["state_ref"]["semantic_state_sha256"] = tips[0]["state_ref"][
        "semantic_state_sha256"
    ]
    tips[1]["branch_ref"]["to_state_ref_sha256"] = digest_json(
        tips[1]["state_ref"]
    )
    tips = sorted(tips, key=digest_json)
    forged = ReconciliationAgreement(
        True,
        source.reason,
        tuple(tips),
        deepcopy(source.parent_set),
        deepcopy(source.reconciled_state_ref),
        deepcopy(source.reconciliation_ref),
        deepcopy(source.receipt),
    )
    _rebind_parent_material(forged)
    assert validate_reconciliation_agreement(forged, common) is False


def test_standalone_validator_rejects_contract_disagreement() -> None:
    common, source = _fixture()
    tips = [deepcopy(item) for item in source.branch_tips]
    tips[1]["branch_ref"]["branch_contract_sha256"] = _sha("other-contract")
    tips = sorted(tips, key=digest_json)
    forged = ReconciliationAgreement(
        True,
        source.reason,
        tuple(tips),
        deepcopy(source.parent_set),
        deepcopy(source.reconciled_state_ref),
        deepcopy(source.reconciliation_ref),
        deepcopy(source.receipt),
    )
    _rebind_parent_material(forged)
    assert validate_reconciliation_agreement(forged, common) is False


def test_standalone_validator_rejects_reused_branch_target() -> None:
    common, source = _fixture()
    assert source.reconciled_state_ref is not None
    assert source.reconciliation_ref is not None
    assert source.receipt is not None
    forged = ReconciliationAgreement(
        True,
        source.reason,
        tuple(deepcopy(item) for item in source.branch_tips),
        deepcopy(source.parent_set),
        deepcopy(source.reconciled_state_ref),
        deepcopy(source.reconciliation_ref),
        deepcopy(source.receipt),
    )
    forged.reconciled_state_ref["semantic_state_sha256"] = forged.branch_tips[0][
        "state_ref"
    ]["semantic_state_sha256"]
    forged.reconciliation_ref["result_state_ref_sha256"] = digest_json(
        forged.reconciled_state_ref
    )
    forged.receipt["result_state_ref_sha256"] = digest_json(
        forged.reconciled_state_ref
    )
    forged.receipt["reconciliation_ref_sha256"] = digest_json(
        forged.reconciliation_ref
    )
    assert validate_reconciliation_agreement(forged, common) is False
