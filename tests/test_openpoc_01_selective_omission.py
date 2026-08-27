from pathlib import Path

import pytest

from openpoc.effect_gate import (
    BypassableRuntime,
    Effect,
    EffectBlocked,
    EffectGate,
    EffectStore,
    Recorder,
)
from openpoc.verify_assurance import assess_assurance, evaluate_manifest, load_trace

ROOT = Path(__file__).resolve().parents[1]
SCENARIOS = ROOT / "examples" / "openpoc-01"


def test_bypass_trace_passes_structural_validation_but_assurance_fails():
    report = evaluate_manifest(SCENARIOS / "bypass.scenario.json")

    assert report.trace_valid is True
    assert report.capture_complete is False
    assert report.capture_status == "violated"
    assert report.effect_bound is False
    assert report.missing_effect_ids == ("effect-hidden",)
    assert report.overall_assurance == "insufficient"


def test_trace_only_verifier_reports_unproven_not_complete():
    records = load_trace(SCENARIOS / "bypass.ttrace.jsonl")
    report = assess_assurance(
        records,
        receipt_effect_ids={"effect-captured"},
        external_effect_ids=None,
        non_bypassable_gate_attested=False,
    )

    assert report.trace_valid is True
    assert report.effect_bound is None
    assert report.capture_status == "unproven"
    assert report.capture_complete is False


def test_honest_run_without_gate_attestation_remains_unproven():
    report = evaluate_manifest(SCENARIOS / "honest.scenario.json")

    assert report.trace_valid is True
    assert report.effect_bound is True
    assert report.capture_status == "unproven"
    assert report.capture_complete is False


def test_effect_gate_blocks_effect_without_precommitment():
    store = EffectStore()
    recorder = Recorder()
    gate = EffectGate(store=store, recorder=recorder)
    effect = Effect(
        effect_id="effect-blocked",
        action="transfer",
        target="ledger/account-2",
        payload={"amount": 500},
    )

    with pytest.raises(EffectBlocked, match="precommitment required"):
        gate.execute(effect, None)

    assert store.effect_ids == set()
    assert recorder.receipt_effect_ids == set()


def test_gated_effect_is_precommitted_receipted_and_sufficient():
    store = EffectStore()
    recorder = Recorder()
    gate = EffectGate(store=store, recorder=recorder)
    effect = Effect(
        effect_id="effect-gated",
        action="transfer",
        target="ledger/account-2",
        payload={"amount": 500},
    )

    precommitment = recorder.precommit(effect)
    receipt = gate.execute(effect, precommitment)

    assert store.effect_ids == {"effect-gated"}
    assert recorder.precommitted_effect_ids == {"effect-gated"}
    assert recorder.receipt_effect_ids == {"effect-gated"}
    assert receipt.effect_digest == effect.digest

    report = evaluate_manifest(SCENARIOS / "gated.scenario.json")
    assert report.capture_status == "supported-under-stated-assumptions"
    assert report.capture_complete is True
    assert report.overall_assurance == "sufficient-under-stated-assumptions"


def test_bypassable_runtime_can_create_hidden_effect_while_receipts_stay_valid():
    store = EffectStore()
    recorder = Recorder()
    runtime = BypassableRuntime(store=store, recorder=recorder)

    captured = Effect(
        effect_id="effect-captured",
        action="transfer",
        target="ledger/account-1",
        payload={"amount": 100},
    )
    hidden = Effect(
        effect_id="effect-hidden",
        action="transfer",
        target="ledger/account-2",
        payload={"amount": 900},
    )

    runtime.execute_via_gate(captured)
    runtime.execute_bypass(hidden)

    assert store.effect_ids == {"effect-captured", "effect-hidden"}
    assert recorder.receipt_effect_ids == {"effect-captured"}
