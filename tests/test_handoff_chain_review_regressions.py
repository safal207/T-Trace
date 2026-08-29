from __future__ import annotations

from copy import deepcopy

from scripts.verify_witness_policy_handoff_chain import (
    CHAIN_AUTHORIZATION,
    CHAIN_CONTRACT,
    CHAIN_ID,
    build_canonical_handoff_chain_fixture,
)
from ttrace.lineage_witness_handoff_chain import (
    advance_witness_policy_handoff_chain,
    build_seed_witness_policy_handoff_chain,
    detect_witness_policy_handoff_chain_fork,
    validate_witness_policy_handoff_chain_agreement,
    validate_witness_policy_handoff_chain_fork_evidence,
)
from ttrace.portable_causality import digest_json


def _seed():
    fixture = build_canonical_handoff_chain_fixture()
    seed = build_seed_witness_policy_handoff_chain(
        fixture["packages"][0],
        chain_id=CHAIN_ID,
        expected_genesis_policy_epoch=1,
        expected_genesis_policy_sha256=digest_json(fixture["policies"][0]),
        chain_contract_sha256=CHAIN_CONTRACT,
        authorization_contract_sha256=CHAIN_AUTHORIZATION,
    )
    assert seed.verified is True
    assert seed.chain_ref is not None
    return fixture, seed


def test_public_seed_agreement_rejects_boolean_genesis_epoch() -> None:
    fixture, seed = _seed()
    assert not validate_witness_policy_handoff_chain_agreement(
        seed,
        fixture["packages"][0],
        previous_chain_ref=None,
        chain_id=CHAIN_ID,
        expected_genesis_policy_epoch=True,
        expected_genesis_policy_sha256=digest_json(fixture["policies"][0]),
        chain_contract_sha256=CHAIN_CONTRACT,
        authorization_contract_sha256=CHAIN_AUTHORIZATION,
    )


def test_serialized_fork_evidence_recomputes_from_pinned_inputs() -> None:
    fixture, seed = _seed()
    package_a = fixture["packages"][1]
    package_b = fixture["alternate_second_package"]
    decision = detect_witness_policy_handoff_chain_fork(
        seed.chain_ref, package_a, package_b
    )
    assert decision.verified is True
    assert decision.fork_detected is True
    assert decision.evidence is not None
    assert validate_witness_policy_handoff_chain_fork_evidence(
        decision.evidence, seed.chain_ref, package_a, package_b
    )

    extended = deepcopy(decision.evidence)
    extended["extra"] = True
    assert not validate_witness_policy_handoff_chain_fork_evidence(
        extended, seed.chain_ref, package_a, package_b
    )

    boolean_epoch = deepcopy(decision.evidence)
    boolean_epoch["old_policy_epoch"] = True
    assert not validate_witness_policy_handoff_chain_fork_evidence(
        boolean_epoch, seed.chain_ref, package_a, package_b
    )

    rebound = deepcopy(decision.evidence)
    rebound["candidate_a_chain_ref_sha256"] = digest_json(
        {"wrong": "candidate"}
    )
    assert not validate_witness_policy_handoff_chain_fork_evidence(
        rebound, seed.chain_ref, package_a, package_b
    )

    second = advance_witness_policy_handoff_chain(seed.chain_ref, package_a)
    assert second.verified is True
    assert second.chain_ref is not None
    assert not validate_witness_policy_handoff_chain_fork_evidence(
        decision.evidence, second.chain_ref, package_a, package_b
    )


def test_identical_successor_has_no_serialized_fork_evidence() -> None:
    fixture, seed = _seed()
    package = fixture["packages"][1]
    decision = detect_witness_policy_handoff_chain_fork(
        seed.chain_ref, package, package
    )
    assert decision.verified is True
    assert decision.fork_detected is False
    assert decision.evidence is None
    assert not validate_witness_policy_handoff_chain_fork_evidence(
        {}, seed.chain_ref, package, package
    )
