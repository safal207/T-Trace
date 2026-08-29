from __future__ import annotations

from copy import deepcopy
from dataclasses import replace

import pytest

from scripts.verify_witness_policy_handoff_chain import (
    CHAIN_AUTHORIZATION,
    CHAIN_CONTRACT,
    CHAIN_ID,
    _handoff,
    _initial_active,
    build_canonical_handoff_chain_fixture,
)
from ttrace.lineage_witness_handoff_chain import (
    CHAIN_FORK_NOT_PROVEN_REASON,
    CHAIN_FORK_REASON,
    CHAIN_REASON,
    CHAIN_REF_KEYS,
    CONDITIONAL_HANDOFF_CHAIN_STATUS,
    advance_witness_policy_handoff_chain,
    build_seed_witness_policy_handoff_chain,
    detect_witness_policy_handoff_chain_fork,
    validate_witness_policy_handoff_chain_agreement,
    validate_witness_policy_handoff_chain_ref,
    validate_witness_policy_handoff_chain_step,
    verify_witness_policy_handoff_chain,
)
from ttrace.portable_causality import digest_json


def _chain():
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
    assert seed.verified and seed.chain_ref is not None
    second = advance_witness_policy_handoff_chain(seed.chain_ref, packages[1])
    assert second.verified and second.chain_ref is not None
    third = advance_witness_policy_handoff_chain(second.chain_ref, packages[2])
    assert third.verified and third.chain_ref is not None
    return fixture, seed, second, third


def test_three_handoffs_rebuild_to_one_exact_active_tip() -> None:
    fixture, _, _, third = _chain()
    decision = verify_witness_policy_handoff_chain(
        fixture["packages"],
        third.chain_ref,
        chain_id=CHAIN_ID,
        expected_genesis_policy_epoch=1,
        expected_genesis_policy_sha256=digest_json(fixture["policies"][0]),
        chain_contract_sha256=CHAIN_CONTRACT,
        authorization_contract_sha256=CHAIN_AUTHORIZATION,
    )
    assert decision.verified is True
    assert decision.reason == CHAIN_REASON
    assert decision.completed_handoffs == 3
    assert decision.current_policy_epoch == 4
    assert decision.chain_ref_sha256 == digest_json(third.chain_ref)
    assert decision.conditional_handoff_chain_status == (
        CONDITIONAL_HANDOFF_CHAIN_STATUS
    )
    assert decision.global_non_equivocation_status == "unproven"


def test_chain_ref_shape_is_fixed_and_scalar() -> None:
    _, seed, second, third = _chain()
    for agreement in (seed, second, third):
        assert agreement.chain_ref is not None
        assert set(agreement.chain_ref) == CHAIN_REF_KEYS
        assert len(agreement.chain_ref) == 18
        assert all(
            not isinstance(value, (dict, list, tuple))
            for value in agreement.chain_ref.values()
        )
        assert validate_witness_policy_handoff_chain_ref(agreement.chain_ref)


def test_seed_and_advance_agreements_recompute_independently() -> None:
    fixture, seed, second, _ = _chain()
    assert validate_witness_policy_handoff_chain_agreement(
        seed,
        fixture["packages"][0],
        previous_chain_ref=None,
        chain_id=CHAIN_ID,
        expected_genesis_policy_epoch=1,
        expected_genesis_policy_sha256=digest_json(fixture["policies"][0]),
        chain_contract_sha256=CHAIN_CONTRACT,
        authorization_contract_sha256=CHAIN_AUTHORIZATION,
    )
    assert validate_witness_policy_handoff_chain_agreement(
        second,
        fixture["packages"][1],
        previous_chain_ref=seed.chain_ref,
    )


@pytest.mark.parametrize(
    "field",
    [
        "chain_id",
        "policy_id",
        "genesis_policy_epoch",
        "genesis_policy_sha256",
        "completed_handoffs",
        "current_policy_epoch",
        "current_policy_sha256",
        "current_activation_package_sha256",
        "current_activation_certificate_sha256",
        "current_handoff_package_sha256",
        "current_handoff_certificate_sha256",
        "previous_chain_ref_sha256",
        "previous_chain_root_sha256",
        "step_commitment_sha256",
        "chain_contract_sha256",
        "authorization_contract_sha256",
    ],
)
def test_tampering_any_root_bound_field_fails(field: str) -> None:
    _, _, _, third = _chain()
    tampered = deepcopy(third.chain_ref)
    assert tampered is not None
    if field in {
        "genesis_policy_epoch",
        "completed_handoffs",
        "current_policy_epoch",
    }:
        tampered[field] += 1
    elif field in {"chain_id", "policy_id"}:
        tampered[field] += ".tampered"
    else:
        tampered[field] = digest_json({"tampered": field})
    assert not validate_witness_policy_handoff_chain_ref(tampered)


def test_non_integer_counters_and_unknown_fields_fail_closed() -> None:
    _, seed, _, third = _chain()
    for invalid in (True, 1.0):
        for field in (
            "genesis_policy_epoch",
            "completed_handoffs",
            "current_policy_epoch",
        ):
            tampered = deepcopy(third.chain_ref)
            assert tampered is not None
            tampered[field] = invalid
            assert not validate_witness_policy_handoff_chain_ref(tampered)

    assert seed.step_commitment is not None
    for field in ("old_policy_epoch", "new_policy_epoch"):
        tampered_step = deepcopy(seed.step_commitment)
        tampered_step[field] = float(tampered_step[field])
        assert not validate_witness_policy_handoff_chain_step(tampered_step)

    tampered = deepcopy(third.chain_ref)
    assert tampered is not None
    tampered["extra"] = True
    assert not validate_witness_policy_handoff_chain_ref(tampered)


def test_seed_requires_exact_pinned_genesis_policy() -> None:
    fixture = build_canonical_handoff_chain_fixture()
    package = fixture["packages"][0]
    wrong_digest = build_seed_witness_policy_handoff_chain(
        package,
        chain_id=CHAIN_ID,
        expected_genesis_policy_epoch=1,
        expected_genesis_policy_sha256=digest_json({"wrong": "genesis"}),
        chain_contract_sha256=CHAIN_CONTRACT,
        authorization_contract_sha256=CHAIN_AUTHORIZATION,
    )
    assert wrong_digest.verified is False
    assert wrong_digest.reason == "handoff_chain_genesis_policy_mismatch"

    wrong_epoch = build_seed_witness_policy_handoff_chain(
        package,
        chain_id=CHAIN_ID,
        expected_genesis_policy_epoch=2,
        expected_genesis_policy_sha256=digest_json(fixture["policies"][0]),
        chain_contract_sha256=CHAIN_CONTRACT,
        authorization_contract_sha256=CHAIN_AUTHORIZATION,
    )
    assert wrong_epoch.verified is False
    assert wrong_epoch.reason == "handoff_chain_genesis_epoch_mismatch"


def test_valid_standalone_handoff_with_different_old_activation_is_rejected() -> None:
    fixture, seed, _, _ = _chain()
    package_1 = fixture["packages"][0]
    policy_2 = fixture["policies"][1]
    policy_3 = fixture["policies"][2]
    old = package_1["new_activation_quorum_package"]
    replacement = _initial_active(
        old["membership_anchor"],
        old["current_accumulator"],
        old["producer_statement"],
        policy_2,
        ("w4", "w5", "w6"),
    )
    standalone_valid = _handoff(
        replacement,
        policy_3,
        old_handoff_ids=("w4", "w5", "w6"),
        new_handoff_ids=("w7", "w8", "w9"),
        activation_ids=("w9", "w10", "w11"),
        salt="replacement-handoff",
    )
    decision = advance_witness_policy_handoff_chain(
        seed.chain_ref, standalone_valid
    )
    assert decision.verified is False
    assert decision.reason == "handoff_chain_activation_carry_forward_mismatch"


def test_rollback_and_replay_fail_closed() -> None:
    fixture, seed, second, _ = _chain()
    rollback = advance_witness_policy_handoff_chain(
        second.chain_ref, fixture["packages"][0]
    )
    assert rollback.verified is False
    assert rollback.reason == "handoff_chain_old_policy_epoch_mismatch"

    replay = advance_witness_policy_handoff_chain(
        second.chain_ref, fixture["packages"][1]
    )
    assert replay.verified is False
    assert replay.reason == "handoff_chain_old_policy_epoch_mismatch"


def test_reordered_and_truncated_histories_do_not_match_pinned_tip() -> None:
    fixture, _, _, third = _chain()
    reordered = verify_witness_policy_handoff_chain(
        (fixture["packages"][1], fixture["packages"][0]),
        third.chain_ref,
        chain_id=CHAIN_ID,
        expected_genesis_policy_epoch=1,
        expected_genesis_policy_sha256=digest_json(fixture["policies"][0]),
        chain_contract_sha256=CHAIN_CONTRACT,
        authorization_contract_sha256=CHAIN_AUTHORIZATION,
    )
    assert reordered.verified is False

    truncated = verify_witness_policy_handoff_chain(
        fixture["packages"][:2],
        third.chain_ref,
        chain_id=CHAIN_ID,
        expected_genesis_policy_epoch=1,
        expected_genesis_policy_sha256=digest_json(fixture["policies"][0]),
        chain_contract_sha256=CHAIN_CONTRACT,
        authorization_contract_sha256=CHAIN_AUTHORIZATION,
    )
    assert truncated.verified is False
    assert truncated.reason == "handoff_chain_tip_mismatch"


def test_parallel_direct_successors_produce_fork_evidence() -> None:
    fixture, seed, _, _ = _chain()
    decision = detect_witness_policy_handoff_chain_fork(
        seed.chain_ref,
        fixture["packages"][1],
        fixture["alternate_second_package"],
    )
    assert decision.verified is True
    assert decision.fork_detected is True
    assert decision.reason == CHAIN_FORK_REASON
    assert decision.evidence is not None
    assert decision.evidence["previous_chain_ref_sha256"] == digest_json(
        seed.chain_ref
    )
    assert decision.evidence["candidate_a_new_policy_sha256"] != (
        decision.evidence["candidate_b_new_policy_sha256"]
    )
    assert decision.evidence["global_non_equivocation_status"] == "unproven"


def test_identical_successor_does_not_prove_a_fork() -> None:
    fixture, seed, _, _ = _chain()
    decision = detect_witness_policy_handoff_chain_fork(
        seed.chain_ref,
        fixture["packages"][1],
        fixture["packages"][1],
    )
    assert decision.verified is True
    assert decision.fork_detected is False
    assert decision.reason == CHAIN_FORK_NOT_PROVEN_REASON


def test_step_predecessor_rules_are_strict() -> None:
    _, seed, second, _ = _chain()
    assert seed.step_commitment is not None
    assert second.step_commitment is not None
    seed_bad = deepcopy(seed.step_commitment)
    seed_bad["previous_chain_ref_sha256"] = digest_json({"not": "zero"})
    assert not validate_witness_policy_handoff_chain_step(seed_bad)

    advance_bad = deepcopy(second.step_commitment)
    advance_bad["previous_chain_root_sha256"] = "0" * 64
    assert not validate_witness_policy_handoff_chain_step(advance_bad)


def test_receipt_extensions_fail_independent_recomputation() -> None:
    fixture, seed, _, _ = _chain()
    tampered = replace(seed, receipt={**seed.receipt, "extra": True})
    assert not validate_witness_policy_handoff_chain_agreement(
        tampered,
        fixture["packages"][0],
        previous_chain_ref=None,
        chain_id=CHAIN_ID,
        expected_genesis_policy_epoch=1,
        expected_genesis_policy_sha256=digest_json(fixture["policies"][0]),
        chain_contract_sha256=CHAIN_CONTRACT,
        authorization_contract_sha256=CHAIN_AUTHORIZATION,
    )
