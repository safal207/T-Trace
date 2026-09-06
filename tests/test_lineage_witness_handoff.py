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
    build_lineage_witness_observation,
    build_lineage_witness_policy,
    build_lineage_witness_quorum_package,
)
from ttrace.lineage_witness_handoff import (
    CONDITIONAL_HANDOFF_STATUS,
    LINEAGE_WITNESS_POLICY_HANDOFF_EQUIVOCATION_DETECTED_REASON,
    LINEAGE_WITNESS_POLICY_HANDOFF_REASON,
    build_witness_policy_handoff_observation,
    build_witness_policy_handoff_package,
    build_witness_policy_handoff_statement,
    detect_witness_policy_handoff_equivocation,
    validate_witness_policy_handoff_statement,
    verify_witness_policy_handoff_package,
)
from ttrace.portable_causality import (
    BranchEvidence,
    ReconciliationVote,
    build_branch_tip,
    digest_json,
    make_state_ref,
    reconcile_two_branches,
)


def sha(label):
    return digest_json({"label": label})


def _branches(common: dict, cycle: int):
    shared = {
        "from_state_ref_sha256": digest_json(common),
        "branch_contract_sha256": sha("branch-contract"),
        "authorization_contract_sha256": sha("branch-authorization"),
        "trust_domain": common["trust_domain"],
    }
    return (
        BranchEvidence(
            True,
            f"provider-{cycle}-left",
            f"authority-{cycle}-left",
            sha(f"branch-{cycle}-left-proof"),
            logical_branch_id=f"cycle-{cycle}-left",
            to_semantic_state_sha256=sha(f"cycle-{cycle}-left-state"),
            **shared,
        ),
        BranchEvidence(
            True,
            f"provider-{cycle}-right",
            f"authority-{cycle}-right",
            sha(f"branch-{cycle}-right-proof"),
            logical_branch_id=f"cycle-{cycle}-right",
            to_semantic_state_sha256=sha(f"cycle-{cycle}-right-state"),
            **shared,
        ),
    )


def _votes(common: dict, branches, cycle: int):
    target = sha(f"cycle-{cycle}-reconciled-state")
    votes = []
    for side, branch in zip(("left", "right"), branches):
        tip = build_branch_tip(common, branch)
        votes.append(
            ReconciliationVote(
                True,
                branch.provider_id,
                branch.authority_id,
                sha(f"vote-{cycle}-{side}-proof"),
                branch.trust_domain,
                f"cycle-{cycle}-reconcile",
                digest_json(tip["branch_ref"]),
                digest_json(tip["state_ref"]),
                digest_json(tip),
                target,
                sha("reconciliation-contract"),
                sha("reconciliation-authorization"),
            )
        )
    return tuple(votes)


def _records(cycle_count: int):
    common = make_state_ref(
        trust_domain="example.procurement",
        logical_state_id="authorization-state",
        causal_epoch=0,
        semantic_state_sha256=sha("epoch-0"),
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
                accumulator_contract_sha256=sha("accumulator-contract"),
                authorization_contract_sha256=sha("accumulator-authorization"),
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


def valid_view():
    records, accumulator = _records(9)
    consistency = build_lineage_root_consistency_package(
        records[:3],
        records[2]["lineage_accumulator"],
        records,
        accumulator,
        membership_contract_sha256=sha("membership"),
        authorization_contract_sha256=sha("authorization"),
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
        previous_statement_sha256=sha("statement-6"),
        statement_provenance_sha256=sha("producer-statement-7-proof"),
    )
    return anchor, current_accumulator, statement

def old_policy():
    return build_lineage_witness_policy(
        policy_id="lineage-witness-set",
        policy_epoch=1,
        authorized_witness_ids=["w1", "w2", "w3", "w4", "w5"],
        threshold=3,
        witness_contract_sha256=sha("old-witness-contract"),
        authorization_contract_sha256=sha("old-witness-authorization"),
    )


def new_policy(suffix="a"):
    witnesses = (
        ["w4", "w5", "w6", "w7", "w8"]
        if suffix == "a"
        else ["w3", "w6", "w9", "w10", "w11"]
    )
    return build_lineage_witness_policy(
        policy_id="lineage-witness-set",
        policy_epoch=2,
        authorized_witness_ids=witnesses,
        threshold=3,
        witness_contract_sha256=sha(f"new-{suffix}-witness-contract"),
        authorization_contract_sha256=sha(f"new-{suffix}-witness-authorization"),
    )


def normal_observation(a, acc, statement, policy, witness_id, sequence, previous, salt):
    return build_lineage_witness_observation(
        a,
        acc,
        statement,
        policy,
        verified=True,
        witness_id=witness_id,
        witness_sequence=sequence,
        previous_observation_sha256=previous,
        observation_provenance_sha256=sha(f"{salt}-{witness_id}-proof"),
    )


def canonical_handoff(new_suffix="a", old_handoff_ids=("w3", "w4", "w5")):
    a, acc, statement = valid_view()
    old = old_policy()
    new = new_policy(new_suffix)

    old_active_obs = {
        witness_id: normal_observation(
            a,
            acc,
            statement,
            old,
            witness_id,
            1,
            ZERO_SHA256,
            "old-active",
        )
        for witness_id in ("w1", "w2", "w3")
    }
    old_active = build_lineage_witness_quorum_package(
        a, acc, statement, old, list(old_active_obs.values())
    )

    handoff_statement = build_witness_policy_handoff_statement(
        a,
        acc,
        statement,
        old,
        new,
        verified=True,
        handoff_contract_sha256=sha("handoff-contract"),
        authorization_contract_sha256=sha("handoff-authorization"),
        handoff_provenance_sha256=sha(f"handoff-{new_suffix}-producer-proof"),
    )

    # w3 continues the old accepted chain. w4/w5 can count in both role
    # certificates. w6 seeds the new-policy side and then continues into the
    # activation quorum.
    handoff_obs = {
        "w3": build_witness_policy_handoff_observation(
            handoff_statement,
            old,
            new,
            verified=True,
            witness_id="w3",
            witness_sequence=2,
            previous_observation_sha256=digest_json(old_active_obs["w3"]),
            observation_provenance_sha256=sha(f"handoff-{new_suffix}-w3-proof"),
        ),
        "w4": build_witness_policy_handoff_observation(
            handoff_statement,
            old,
            new,
            verified=True,
            witness_id="w4",
            witness_sequence=1,
            previous_observation_sha256=ZERO_SHA256,
            observation_provenance_sha256=sha(f"handoff-{new_suffix}-w4-proof"),
        ),
        "w5": build_witness_policy_handoff_observation(
            handoff_statement,
            old,
            new,
            verified=True,
            witness_id="w5",
            witness_sequence=1,
            previous_observation_sha256=ZERO_SHA256,
            observation_provenance_sha256=sha(f"handoff-{new_suffix}-w5-proof"),
        ),
        "w6": build_witness_policy_handoff_observation(
            handoff_statement,
            old,
            new,
            verified=True,
            witness_id="w6",
            witness_sequence=1,
            previous_observation_sha256=ZERO_SHA256,
            observation_provenance_sha256=sha(f"handoff-{new_suffix}-w6-proof"),
        ),
    }
    if new_suffix == "b":
        # The alternative new policy does not authorize w4/w5. Add its own
        # new-side quorum while retaining old-policy continuity at w3.
        handoff_obs = {
            "w3": handoff_obs["w3"],
            "w6": handoff_obs["w6"],
            "w9": build_witness_policy_handoff_observation(
                handoff_statement,
                old,
                new,
                verified=True,
                witness_id="w9",
                witness_sequence=1,
                previous_observation_sha256=ZERO_SHA256,
                observation_provenance_sha256=sha("handoff-b-w9-proof"),
            ),
            "w10": build_witness_policy_handoff_observation(
                handoff_statement,
                old,
                new,
                verified=True,
                witness_id="w10",
                witness_sequence=1,
                previous_observation_sha256=ZERO_SHA256,
                observation_provenance_sha256=sha("handoff-b-w10-proof"),
            ),
        }
        old_handoff_ids = ("w1", "w2", "w3")
        # Old-only observations needed by the second conflicting old quorum.
        for witness_id in ("w1", "w2"):
            handoff_obs[witness_id] = build_witness_policy_handoff_observation(
                handoff_statement,
                old,
                new,
                verified=True,
                witness_id=witness_id,
                witness_sequence=2,
                previous_observation_sha256=digest_json(old_active_obs[witness_id]),
                observation_provenance_sha256=sha(
                    f"handoff-b-{witness_id}-proof"
                ),
            )

    new_handoff_ids = (
        ("w4", "w5", "w6")
        if new_suffix == "a"
        else ("w6", "w9", "w10")
    )
    activation_ids = (
        ("w6", "w7", "w8")
        if new_suffix == "a"
        else ("w6", "w9", "w11")
    )
    new_activation_obs = []
    for witness_id in activation_ids:
        if witness_id in handoff_obs:
            new_activation_obs.append(
                normal_observation(
                    a,
                    acc,
                    statement,
                    new,
                    witness_id,
                    int(handoff_obs[witness_id]["witness_sequence"]) + 1,
                    digest_json(handoff_obs[witness_id]),
                    f"new-{new_suffix}-activation",
                )
            )
        else:
            new_activation_obs.append(
                normal_observation(
                    a,
                    acc,
                    statement,
                    new,
                    witness_id,
                    1,
                    ZERO_SHA256,
                    f"new-{new_suffix}-activation",
                )
            )
    new_activation = build_lineage_witness_quorum_package(
        a, acc, statement, new, new_activation_obs
    )
    package = build_witness_policy_handoff_package(
        old_active,
        new_activation,
        handoff_statement,
        list(handoff_obs.values()),
        old_handoff_witness_ids=old_handoff_ids,
        new_handoff_witness_ids=new_handoff_ids,
    )
    return package


def test_canonical_handoff_closes_both_policy_continuity_edges():
    package = canonical_handoff()
    decision = verify_witness_policy_handoff_package(package)
    assert decision.verified is True
    assert decision.reason == LINEAGE_WITNESS_POLICY_HANDOFF_REASON
    assert decision.old_continuity_witness_ids == ("w3",)
    assert decision.new_continuity_witness_ids == ("w6",)
    assert decision.cross_policy_handoff_witness_ids == ("w4", "w5")
    assert decision.old_minimum_quorum_intersection == 1
    assert decision.new_minimum_quorum_intersection == 1
    assert decision.no_unprotected_acceptance_gap is True
    assert decision.conditional_handoff_status == CONDITIONAL_HANDOFF_STATUS
    assert decision.global_non_equivocation_status == "unproven"


def test_package_is_canonical_and_exact():
    package = canonical_handoff()
    assert package["handoff_observations"] == sorted(
        package["handoff_observations"], key=lambda item: item["witness_id"]
    )
    for key in (
        "old_handoff_certificate",
        "new_handoff_certificate",
        "handoff_certificate",
    ):
        tampered = deepcopy(package)
        tampered[key]["extra"] = True
        assert not verify_witness_policy_handoff_package(tampered).verified
    tampered = deepcopy(package)
    tampered["extra"] = True
    assert not verify_witness_policy_handoff_package(tampered).verified


def test_policy_transition_requires_same_id_next_epoch_and_new_bytes():
    package = canonical_handoff()
    old_package = package["old_active_quorum_package"]
    new_package = deepcopy(package["new_activation_quorum_package"])
    handoff = package["handoff_statement"]

    for mutation in (
        lambda p: p["witness_policy"].__setitem__("policy_id", "other"),
        lambda p: p["witness_policy"].__setitem__("policy_epoch", 3),
        lambda p: p.__setitem__(
            "witness_policy", deepcopy(old_package["witness_policy"])
        ),
    ):
        candidate = deepcopy(new_package)
        mutation(candidate)
        assert not verify_witness_policy_handoff_package(
            {
                **deepcopy(package),
                "new_activation_quorum_package": candidate,
            }
        ).verified

    bad = deepcopy(handoff)
    bad["new_policy_epoch"] = True
    assert not validate_witness_policy_handoff_statement(
        bad,
        old_package["membership_anchor"],
        old_package["current_accumulator"],
        old_package["producer_statement"],
        old_package["witness_policy"],
        new_package["witness_policy"],
    )


def test_old_continuity_predecessor_and_sequence_fail_closed():
    package = canonical_handoff()
    for field, value, expected in (
        (
            "previous_observation_sha256",
            sha("wrong-old-predecessor"),
            "old_handoff_witness_predecessor_mismatch",
        ),
        (
            "witness_sequence",
            3,
            "old_handoff_witness_sequence_discontinuity",
        ),
    ):
        tampered = deepcopy(package)
        observation = next(
            item
            for item in tampered["handoff_observations"]
            if item["witness_id"] == "w3"
        )
        observation[field] = value
        tampered["old_handoff_certificate"]["handoff_observation_sha256"] = [
            digest_json(
                next(
                    item
                    for item in tampered["handoff_observations"]
                    if item["witness_id"] == witness_id
                )
            )
            for witness_id in tampered["old_handoff_certificate"]["witness_ids"]
        ]
        tampered["new_handoff_certificate"]["handoff_observation_sha256"] = [
            digest_json(
                next(
                    item
                    for item in tampered["handoff_observations"]
                    if item["witness_id"] == witness_id
                )
            )
            for witness_id in tampered["new_handoff_certificate"]["witness_ids"]
        ]
        assert verify_witness_policy_handoff_package(tampered).reason == expected


def test_new_activation_continuity_fails_closed():
    package = canonical_handoff()
    tampered = deepcopy(package)
    observation = next(
        item
        for item in tampered["new_activation_quorum_package"][
            "witness_observations"
        ]
        if item["witness_id"] == "w6"
    )
    observation["previous_observation_sha256"] = sha("wrong-new-predecessor")
    tampered["new_activation_quorum_package"]["quorum_certificate"][
        "witness_observation_sha256"
    ] = [
        digest_json(item)
        for item in tampered["new_activation_quorum_package"][
            "witness_observations"
        ]
    ]
    assert (
        verify_witness_policy_handoff_package(tampered).reason
        == "new_handoff_witness_predecessor_mismatch"
    )


def test_old_and_new_packages_must_accept_exact_same_view():
    package = canonical_handoff()
    tampered = deepcopy(package)
    tampered["new_activation_quorum_package"]["membership_anchor"][
        "tree_size"
    ] += 1
    assert (
        verify_witness_policy_handoff_package(tampered).reason
        == "producer_statement_invalid"
    )


def test_handoff_observation_rebinding_and_order_fail_closed():
    package = canonical_handoff()
    tampered = deepcopy(package)
    tampered["handoff_observations"].reverse()
    assert (
        verify_witness_policy_handoff_package(tampered).reason
        == "witness_policy_handoff_observation_order_invalid"
    )

    tampered = deepcopy(package)
    tampered["handoff_observations"][0]["new_policy_sha256"] = sha("other-policy")
    assert (
        verify_witness_policy_handoff_package(tampered).reason
        == "witness_policy_handoff_observation_invalid"
    )



def test_unused_handoff_observation_fails_closed():
    package = canonical_handoff()
    old = package["old_active_quorum_package"]["witness_policy"]
    new = package["new_activation_quorum_package"]["witness_policy"]
    extra = build_witness_policy_handoff_observation(
        package["handoff_statement"],
        old,
        new,
        verified=True,
        witness_id="w7",
        witness_sequence=1,
        previous_observation_sha256=ZERO_SHA256,
        observation_provenance_sha256=sha("unused-w7-proof"),
    )
    tampered = deepcopy(package)
    tampered["handoff_observations"].append(extra)
    tampered["handoff_observations"].sort(key=lambda item: item["witness_id"])
    decision = verify_witness_policy_handoff_package(tampered)
    assert decision.verified is False
    assert (
        decision.reason
        == "witness_policy_handoff_observation_coverage_invalid"
    )

def test_builder_rejects_insufficient_and_unauthorized_role_quorums():
    package = canonical_handoff()
    with pytest.raises(ValueError, match="old_handoff_quorum_insufficient"):
        build_witness_policy_handoff_package(
            package["old_active_quorum_package"],
            package["new_activation_quorum_package"],
            package["handoff_statement"],
            package["handoff_observations"],
            old_handoff_witness_ids=["w3", "w4"],
            new_handoff_witness_ids=["w4", "w5", "w6"],
        )
    with pytest.raises(ValueError, match="new_handoff_witness_unauthorized"):
        build_witness_policy_handoff_package(
            package["old_active_quorum_package"],
            package["new_activation_quorum_package"],
            package["handoff_statement"],
            package["handoff_observations"],
            old_handoff_witness_ids=["w3", "w4", "w5"],
            new_handoff_witness_ids=["w1", "w4", "w5"],
        )


def test_conflicting_rotations_expose_old_policy_double_signer():
    first = canonical_handoff("a")
    second = canonical_handoff("b")
    decision = detect_witness_policy_handoff_equivocation(first, second)
    assert decision.verified is True
    assert decision.equivocation_detected is True
    assert (
        decision.reason
        == LINEAGE_WITNESS_POLICY_HANDOFF_EQUIVOCATION_DETECTED_REASON
    )
    assert decision.double_signing_old_witness_ids == ("w3",)
    assert decision.evidence is not None
    assert decision.evidence["minimum_old_quorum_intersection"] == 1
    assert decision.evidence["global_non_equivocation_status"] == "unproven"


def test_identical_handoff_does_not_prove_equivocation():
    package = canonical_handoff()
    decision = detect_witness_policy_handoff_equivocation(package, package)
    assert decision.verified is True
    assert decision.equivocation_detected is False
    assert decision.reason == "lineage_witness_policy_handoff_equivocation_not_proven"


def test_handoff_statement_exact_shape_and_context_binding():
    package = canonical_handoff()
    old_package = package["old_active_quorum_package"]
    new_package = package["new_activation_quorum_package"]
    statement = deepcopy(package["handoff_statement"])
    statement["extra"] = True
    assert not validate_witness_policy_handoff_statement(
        statement,
        old_package["membership_anchor"],
        old_package["current_accumulator"],
        old_package["producer_statement"],
        old_package["witness_policy"],
        new_package["witness_policy"],
    )

    statement = deepcopy(package["handoff_statement"])
    statement["producer_statement_sha256"] = sha("other-statement")
    assert not validate_witness_policy_handoff_statement(
        statement,
        old_package["membership_anchor"],
        old_package["current_accumulator"],
        old_package["producer_statement"],
        old_package["witness_policy"],
        new_package["witness_policy"],
    )


def test_handoff_observation_duplicate_and_boolean_sequence_fail_closed():
    package = canonical_handoff()
    tampered = deepcopy(package)
    tampered["handoff_observations"].append(
        deepcopy(tampered["handoff_observations"][0])
    )
    tampered["handoff_observations"] = sorted(
        tampered["handoff_observations"], key=lambda item: item["witness_id"]
    )
    assert (
        verify_witness_policy_handoff_package(tampered).reason
        == "witness_policy_handoff_observation_duplicate"
    )

    tampered = deepcopy(package)
    tampered["handoff_observations"][0]["witness_sequence"] = True
    assert (
        verify_witness_policy_handoff_package(tampered).reason
        == "witness_policy_handoff_observation_invalid"
    )


def test_handoff_role_certificate_tampering_fails_closed():
    package = canonical_handoff()
    tampered = deepcopy(package)
    tampered["old_handoff_certificate"]["threshold"] = 4
    assert (
        verify_witness_policy_handoff_package(tampered).reason
        == "old_handoff_certificate_invalid"
    )

    tampered = deepcopy(package)
    tampered["new_handoff_certificate"]["handoff_observation_sha256"].reverse()
    assert (
        verify_witness_policy_handoff_package(tampered).reason
        == "new_handoff_certificate_invalid"
    )


def test_handoff_receipt_recomputation_fails_closed():
    package = canonical_handoff()
    tampered = deepcopy(package)
    tampered["handoff_certificate"]["no_unprotected_acceptance_gap"] = False
    assert (
        verify_witness_policy_handoff_package(tampered).reason
        == "witness_policy_handoff_certificate_mismatch"
    )

    tampered = deepcopy(package)
    tampered["handoff_certificate"]["cross_policy_handoff_witness_ids"] = []
    assert (
        verify_witness_policy_handoff_package(tampered).reason
        == "witness_policy_handoff_certificate_mismatch"
    )


def test_new_activation_sequence_discontinuity_fails_closed():
    package = canonical_handoff()
    tampered = deepcopy(package)
    observation = next(
        item
        for item in tampered["new_activation_quorum_package"][
            "witness_observations"
        ]
        if item["witness_id"] == "w6"
    )
    observation["witness_sequence"] = 3
    tampered["new_activation_quorum_package"]["quorum_certificate"][
        "witness_observation_sha256"
    ] = [
        digest_json(item)
        for item in tampered["new_activation_quorum_package"][
            "witness_observations"
        ]
    ]
    assert (
        verify_witness_policy_handoff_package(tampered).reason
        == "new_handoff_witness_sequence_discontinuity"
    )


def test_fully_disjoint_policy_sets_can_handoff_with_dual_quorums():
    a, acc, statement = valid_view()
    old = old_policy()
    new = build_lineage_witness_policy(
        policy_id="lineage-witness-set",
        policy_epoch=2,
        authorized_witness_ids=["w6", "w7", "w8", "w9", "w10"],
        threshold=3,
        witness_contract_sha256=sha("disjoint-new-contract"),
        authorization_contract_sha256=sha("disjoint-new-authorization"),
    )
    old_obs = {
        witness_id: normal_observation(
            a,
            acc,
            statement,
            old,
            witness_id,
            1,
            ZERO_SHA256,
            "disjoint-old-active",
        )
        for witness_id in ("w1", "w2", "w3")
    }
    old_package = build_lineage_witness_quorum_package(
        a, acc, statement, old, list(old_obs.values())
    )
    handoff_statement = build_witness_policy_handoff_statement(
        a,
        acc,
        statement,
        old,
        new,
        verified=True,
        handoff_contract_sha256=sha("disjoint-handoff-contract"),
        authorization_contract_sha256=sha("disjoint-handoff-authorization"),
        handoff_provenance_sha256=sha("disjoint-handoff-proof"),
    )
    handoff = {}
    for witness_id in ("w1", "w2", "w3"):
        handoff[witness_id] = build_witness_policy_handoff_observation(
            handoff_statement,
            old,
            new,
            verified=True,
            witness_id=witness_id,
            witness_sequence=2,
            previous_observation_sha256=digest_json(old_obs[witness_id]),
            observation_provenance_sha256=sha(f"disjoint-{witness_id}-proof"),
        )
    for witness_id in ("w6", "w7", "w8"):
        handoff[witness_id] = build_witness_policy_handoff_observation(
            handoff_statement,
            old,
            new,
            verified=True,
            witness_id=witness_id,
            witness_sequence=1,
            previous_observation_sha256=ZERO_SHA256,
            observation_provenance_sha256=sha(f"disjoint-{witness_id}-proof"),
        )
    activation = []
    for witness_id in ("w6", "w9", "w10"):
        if witness_id == "w6":
            activation.append(
                normal_observation(
                    a,
                    acc,
                    statement,
                    new,
                    witness_id,
                    2,
                    digest_json(handoff[witness_id]),
                    "disjoint-activation",
                )
            )
        else:
            activation.append(
                normal_observation(
                    a,
                    acc,
                    statement,
                    new,
                    witness_id,
                    1,
                    ZERO_SHA256,
                    "disjoint-activation",
                )
            )
    new_package = build_lineage_witness_quorum_package(
        a, acc, statement, new, activation
    )
    package = build_witness_policy_handoff_package(
        old_package,
        new_package,
        handoff_statement,
        list(handoff.values()),
        old_handoff_witness_ids=["w1", "w2", "w3"],
        new_handoff_witness_ids=["w6", "w7", "w8"],
    )
    decision = verify_witness_policy_handoff_package(package)
    assert decision.verified is True
    assert decision.cross_policy_handoff_witness_ids == ()
    assert decision.old_continuity_witness_ids == ("w1", "w2", "w3")
    assert decision.new_continuity_witness_ids == ("w6",)


def test_equivocation_comparison_requires_same_old_context():
    first = canonical_handoff("a")
    second = canonical_handoff("b")
    second = deepcopy(second)
    second["old_active_quorum_package"]["witness_policy"]["policy_epoch"] = 9
    decision = detect_witness_policy_handoff_equivocation(first, second)
    assert decision.verified is False
