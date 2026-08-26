import json
import shutil
from pathlib import Path

import pytest

from openpoc.verify_reproducibility import SUPPORTED, evaluate_manifest

ROOT = Path(__file__).resolve().parents[1]
SCENARIOS = ROOT / "examples" / "openpoc-02"


def _copy_scenario_bundle(source: Path, target: Path) -> Path:
    target.mkdir()
    manifest = json.loads(source.read_text(encoding="utf-8"))
    for key in ("recipe", "input"):
        relative_path = manifest["artifacts"][key]
        shutil.copy2(source.parent / relative_path, target / relative_path)
    destination = target / source.name
    destination.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return destination


def test_complete_bound_replay_supports_the_scoped_claim():
    report = evaluate_manifest(SCENARIOS / "complete-replay.scenario.json")

    assert report.artifact_bindings_valid is True
    assert report.environment_compatible is True
    assert report.replay_executed is True
    assert report.relation_satisfied is True
    assert report.reproduction_status == SUPPORTED
    assert report.capture_status == SUPPORTED
    assert report.claim_verdict == SUPPORTED
    assert report.errors == ()


def test_incomplete_transcript_can_replay_while_capture_claim_fails():
    report = evaluate_manifest(
        SCENARIOS / "incomplete-but-reproducible.scenario.json"
    )

    assert report.reproduction_status == SUPPORTED
    assert report.relation_satisfied is True
    assert report.record_integrity_status == "assumed-valid-for-boundary-test"
    assert report.capture_status == "violated"
    assert report.missing_effect_ids == ("effect-hidden",)
    assert report.claim_verdict == "violated"


def test_independent_replay_falsifies_a_bound_wrong_output():
    report = evaluate_manifest(SCENARIOS / "output-mismatch.scenario.json")

    assert report.replay_executed is True
    assert report.relation_satisfied is False
    assert report.reproduction_status == "violated"
    assert report.capture_status == SUPPORTED
    assert report.claim_verdict == "violated"
    assert report.actual_output == {"total_amount": 1000, "effect_count": 2}


def test_unavailable_declared_environment_keeps_replay_unproven():
    report = evaluate_manifest(SCENARIOS / "environment-mismatch.scenario.json")

    assert report.artifact_bindings_valid is True
    assert report.environment_compatible is False
    assert report.replay_executed is False
    assert report.relation_satisfied is None
    assert report.reproduction_status == "unproven"
    assert report.claim_verdict == "insufficient"


def test_fixture_assumed_integrity_cannot_satisfy_a_required_dimension(tmp_path):
    source = SCENARIOS / "complete-replay.scenario.json"
    scenario = _copy_scenario_bundle(source, tmp_path / "integrity-only")
    manifest = json.loads(scenario.read_text(encoding="utf-8"))
    manifest["claim"]["required_dimensions"] = ["record_integrity"]
    scenario.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")

    report = evaluate_manifest(scenario)

    assert report.record_integrity_status == "assumed-valid-for-boundary-test"
    assert report.claim_verdict == "insufficient"


def test_input_digest_mismatch_fails_closed_before_replay(tmp_path):
    source = SCENARIOS / "complete-replay.scenario.json"
    scenario = _copy_scenario_bundle(source, tmp_path / "digest-mismatch")
    input_path = scenario.parent / "complete-input.json"
    inputs = json.loads(input_path.read_text(encoding="utf-8"))
    inputs["effects"][0]["amount"] = 101
    input_path.write_text(json.dumps(inputs, indent=2) + "\n", encoding="utf-8")

    report = evaluate_manifest(scenario)

    assert report.artifact_bindings_valid is False
    assert report.replay_executed is False
    assert report.reproduction_status == "unproven"
    assert any("input digest mismatch" in error for error in report.errors)


def test_artifact_path_escape_fails_closed_before_replay(tmp_path):
    source = SCENARIOS / "complete-replay.scenario.json"
    scenario = _copy_scenario_bundle(source, tmp_path / "path-escape")
    manifest = json.loads(scenario.read_text(encoding="utf-8"))
    manifest["artifacts"]["recipe"] = "../outside.recipe.json"
    scenario.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")

    report = evaluate_manifest(scenario)

    assert report.artifact_bindings_valid is False
    assert report.replay_executed is False
    assert report.claim_verdict == "insufficient"
    assert any("escapes the scenario directory" in error for error in report.errors)


def test_required_dimensions_must_be_unique(tmp_path):
    source = SCENARIOS / "complete-replay.scenario.json"
    scenario = _copy_scenario_bundle(source, tmp_path / "duplicate-dimension")
    manifest = json.loads(scenario.read_text(encoding="utf-8"))
    manifest["claim"]["required_dimensions"] = [
        "reproducibility",
        "reproducibility",
    ]
    scenario.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")

    report = evaluate_manifest(scenario)

    assert report.claim_verdict == "insufficient"
    assert "claim.required_dimensions must be unique" in report.errors


@pytest.mark.parametrize(
    "scenario_name",
    [
        "complete-replay.scenario.json",
        "environment-mismatch.scenario.json",
        "incomplete-but-reproducible.scenario.json",
        "output-mismatch.scenario.json",
    ],
)
def test_checked_in_scenario_expectations_match(scenario_name):
    scenario = SCENARIOS / scenario_name
    manifest = json.loads(scenario.read_text(encoding="utf-8"))
    actual = evaluate_manifest(scenario).to_dict()

    for key, expected_value in manifest["expected"].items():
        actual_value = actual[key]
        if isinstance(actual_value, tuple):
            actual_value = list(actual_value)
        assert actual_value == expected_value, key
