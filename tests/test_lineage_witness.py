from __future__ import annotations

from copy import deepcopy

import pytest

from ttrace.lineage_compaction import (
    ZERO_SHA256,
    advance_lineage_accumulator,
    build_seed_lineage_accumulator,
)
from ttrace.lineage_consistency import (
    build_lineage_anchor_statement,
    build_lineage_root_consistency_package,
)
from ttrace.lineage_witness import (
    CONDITIONAL_NON_EQUIVOCATION_STATUS,
    LINEAGE_WITNESS_EQUIVOCATION_DETECTED_REASON,
    LINEAGE_WITNESSED_CONSISTENCY_REASON,
    build_lineage_witness_observation,
    build_lineage_witness_policy,
    build_lineage_witness_quorum_package,
    detect_witness_quorum_equivocation,
    minimum_quorum_intersection,
    validate_lineage_witness_policy,
    verify_lineage_witness_quorum_package,
    verify_witnessed_lineage_root_consistency,
)
from ttrace.portable_causality import (
    BranchEvidence,
    ReconciliationVote,
    build_branch_tip,
    digest_json,
    make_state_ref,
    reconcile_two_branches,
)

MEMBERSHIP_CONTRACT = digest_json({"contract": "membership/v0.1"})
AUTHORIZATION_CONTRACT = digest_json({"contract": "authorization/v0.1"})


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
            to_semantic_state_sha256=_sha(f"cycle-{cycle}-left-state"),
            **shared,
        ),
        BranchEvidence(
            verified=True,
            provider_id=f"provider-{cycle}-right",
            authority_id=f"authority-{cycle}-right",
            provenance_sha256=_sha(f"branch-{cycle}-right-proof"),
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
                verified=True,
                provider_id=branch.provider_id,
                authority_id=branch.authority_id,
                provenance_sha256=_sha(f"vote-{cycle}-{side}-proof"),
                trust_domain=branch.trust_domain,
                logical_reconciliation_id=f"cycle-{cycle}-reconcile",
                branch_ref_sha256=digest_json(tip["branch_ref"]),
                branch_state_ref_sha256=digest_json(tip["state_ref"]),
                branch_tip_sha256=digest_json(tip),
                target_semantic_state_sha256=target,
                reconciliation_contract_sha256=_sha("reconciliation-contract"),
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
        assert reconciliation.verified is True
        assert reconciliation.reconciled_state_ref is not None
        if cycle == 1:
            accumulator = build_seed_lineage_accumulator(
                common,
                reconciliation,
                accumulator_contract_sha256=_sha("accumulator-contract"),
                authorization_contract_sha256=_sha(
                    "accumulator-authorization"
                ),
            )
        else:
            assert accumulator is not None
            advanced = advance_lineage_accumulator(
                previous_accumulator=accumulator,
                common_state_ref=common,
                branches=branches,
                votes=votes,
            )
            assert advanced.verified is True
            assert advanced.lineage_accumulator is not None
            assert advanced.reconciliation is not None
            assert advanced.reconciliation.reconciled_state_ref is not None
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
    assert accumulator is not None
    return records, accumulator


def _consistency_package():
    records, accumulator = _records(9)
    return build_lineage_root_consistency_package(
        records[:3],
        records[2]["lineage_accumulator"],
        records,
        accumulator,
        membership_contract_sha256=MEMBERSHIP_CONTRACT,
        authorization_contract_sha256=AUTHORIZATION_CONTRACT,
    )


def _producer_statements(package):
    old_endpoint = package["old_endpoint"]
    new_endpoint = package["new_endpoint"]
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
    return old_statement, new_statement


def _policy():
    return build_lineage_witness_policy(
        policy_id="lineage-witness-set-1",
        policy_epoch=1,
        authorized_witness_ids=["w1", "w2", "w3", "w4", "w5"],
        threshold=3,
        witness_contract_sha256=_sha("witness-contract"),
        authorization_contract_sha256=_sha("witness-authorization"),
    )


def _observation(
    endpoint,
    statement,
    policy,
    witness_id: str,
    sequence: int,
    previous: str,
    salt: str,
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


def _quorum_packages():
    consistency = _consistency_package()
    old_endpoint = consistency["old_endpoint"]
    new_endpoint = consistency["new_endpoint"]
    old_statement, new_statement = _producer_statements(consistency)
    policy = _policy()

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
    old_package = build_lineage_witness_quorum_package(
        old_endpoint["membership_anchor"],
        old_endpoint["current_accumulator"],
        old_statement,
        policy,
        list(old_by_id.values()),
    )
    new_package = build_lineage_witness_quorum_package(
        new_endpoint["membership_anchor"],
        new_endpoint["current_accumulator"],
        new_statement,
        policy,
        new_observations,
    )
    return consistency, old_package, new_package, old_by_id


def test_policy_requires_strict_intersection_and_json_integers() -> None:
    policy = _policy()
    assert validate_lineage_witness_policy(policy)
    assert minimum_quorum_intersection(policy) == 1

    insufficient = deepcopy(policy)
    insufficient["threshold"] = 2
    assert not validate_lineage_witness_policy(insufficient)

    boolean = deepcopy(policy)
    boolean["threshold"] = True
    assert not validate_lineage_witness_policy(boolean)

    unsorted = deepcopy(policy)
    unsorted["authorized_witness_ids"] = list(
        reversed(unsorted["authorized_witness_ids"])
    )
    assert not validate_lineage_witness_policy(unsorted)

    duplicate = deepcopy(policy)
    duplicate["authorized_witness_ids"][-1] = duplicate[
        "authorized_witness_ids"
    ][-2]
    assert not validate_lineage_witness_policy(duplicate)


def test_quorum_package_is_canonical_and_exact() -> None:
    _, old_package, _, _ = _quorum_packages()
    decision = verify_lineage_witness_quorum_package(old_package)
    assert decision.verified is True
    assert decision.witness_ids == ("w1", "w2", "w3")
    assert decision.witness_count == 3
    assert decision.threshold == 3
    assert decision.minimum_quorum_intersection == 1
    assert decision.global_non_equivocation_status == "unproven"


def test_witnessed_consistency_has_continuous_intersection() -> None:
    consistency, old_package, new_package, _ = _quorum_packages()
    decision = verify_witnessed_lineage_root_consistency(
        consistency, old_package, new_package
    )
    assert decision.verified is True
    assert decision.reason == LINEAGE_WITNESSED_CONSISTENCY_REASON
    assert decision.overlapping_witness_ids == ("w3",)
    assert decision.minimum_quorum_intersection == 1
    assert decision.append_only_consistent is True
    assert decision.authority_chain_continuous is True
    assert decision.witness_chains_continuous is True
    assert (
        decision.conditional_non_equivocation_status
        == CONDITIONAL_NON_EQUIVOCATION_STATUS
    )
    assert decision.global_non_equivocation_status == "unproven"


@pytest.mark.parametrize(
    "mutation",
    [
        lambda value: value.__setitem__("extra", True),
        lambda value: value["quorum_certificate"].__setitem__("extra", True),
        lambda value: value["witness_observations"][0].__setitem__(
            "extra", True
        ),
        lambda value: value["witness_observations"][0].__setitem__(
            "producer_statement_sha256", _sha("wrong-statement")
        ),
        lambda value: value["witness_observations"].reverse(),
        lambda value: value["quorum_certificate"].__setitem__(
            "threshold", 4
        ),
    ],
)
def test_package_tampering_fails_closed(mutation) -> None:
    _, old_package, _, _ = _quorum_packages()
    tampered = deepcopy(old_package)
    mutation(tampered)
    assert verify_lineage_witness_quorum_package(tampered).verified is False


def test_builder_rejects_insufficient_duplicate_and_unauthorized_witnesses() -> None:
    _, old_package, _, _ = _quorum_packages()
    anchor = old_package["membership_anchor"]
    accumulator = old_package["current_accumulator"]
    statement = old_package["producer_statement"]
    policy = old_package["witness_policy"]
    observations = old_package["witness_observations"]

    with pytest.raises(ValueError, match="witness_quorum_insufficient"):
        build_lineage_witness_quorum_package(
            anchor, accumulator, statement, policy, observations[:2]
        )
    with pytest.raises(ValueError, match="witness_observation_duplicate"):
        build_lineage_witness_quorum_package(
            anchor, accumulator, statement, policy, [observations[0]] * 3
        )
    with pytest.raises(ValueError, match="witness_observation_unauthorized"):
        build_lineage_witness_observation(
            anchor,
            accumulator,
            statement,
            policy,
            verified=True,
            witness_id="not-authorized",
            witness_sequence=1,
            previous_observation_sha256=ZERO_SHA256,
            observation_provenance_sha256=_sha("unauthorized-proof"),
        )


def test_transition_rejects_witness_predecessor_discontinuity() -> None:
    consistency, old_package, new_package, _ = _quorum_packages()
    tampered = deepcopy(new_package)
    observation = next(
        item
        for item in tampered["witness_observations"]
        if item["witness_id"] == "w3"
    )
    observation["previous_observation_sha256"] = _sha("wrong-predecessor")
    tampered["quorum_certificate"]["witness_observation_sha256"] = [
        digest_json(item) for item in tampered["witness_observations"]
    ]
    decision = verify_witnessed_lineage_root_consistency(
        consistency, old_package, tampered
    )
    assert decision.verified is False
    assert decision.reason == "witness_observation_predecessor_mismatch"


def test_transition_rejects_policy_drift() -> None:
    consistency, old_package, new_package, _ = _quorum_packages()
    tampered = deepcopy(new_package)
    tampered["witness_policy"]["policy_epoch"] = 2
    decision = verify_witnessed_lineage_root_consistency(
        consistency, old_package, tampered
    )
    assert decision.verified is False


def _split_quorum_package():
    consistency, _, new_package, old_by_id = _quorum_packages()
    new_endpoint = consistency["new_endpoint"]
    policy = new_package["witness_policy"]
    split_anchor = deepcopy(new_endpoint["membership_anchor"])
    split_anchor["cycle_commitment_merkle_root_sha256"] = _sha(
        "conflicting-split-view-root"
    )
    old_statement, _ = _producer_statements(consistency)
    split_statement = build_lineage_anchor_statement(
        split_anchor,
        new_endpoint["current_accumulator"],
        verified=True,
        authority_id=new_package["producer_statement"]["authority_id"],
        statement_sequence=2,
        previous_statement_sha256=digest_json(old_statement),
        statement_provenance_sha256=_sha("split-producer-signature"),
    )
    observations = [
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
        observations,
    )
    return new_package, split_package


def test_conflicting_quorum_certificates_expose_double_signing() -> None:
    canonical, split = _split_quorum_package()
    decision = detect_witness_quorum_equivocation(canonical, split)
    assert decision.verified is True
    assert decision.equivocation_detected is True
    assert decision.reason == LINEAGE_WITNESS_EQUIVOCATION_DETECTED_REASON
    assert decision.double_signing_witness_ids == ("w3", "w4", "w5")
    assert decision.evidence is not None
    assert decision.evidence["minimum_quorum_intersection"] == 1
    assert decision.evidence["global_non_equivocation_status"] == "unproven"


def test_identical_certificate_does_not_prove_equivocation() -> None:
    _, old_package, _, _ = _quorum_packages()
    decision = detect_witness_quorum_equivocation(old_package, old_package)
    assert decision.verified is True
    assert decision.equivocation_detected is False
    assert decision.reason == "lineage_witness_equivocation_not_proven"
