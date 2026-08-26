from __future__ import annotations

import argparse
import hashlib
import json
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any


SCENARIO_SCHEMA = "openpoc-reproducibility-scenario/v0.1"
RECIPE_SCHEMA = "openpoc-replay-recipe/v0.1"
INPUT_SCHEMA = "openpoc-effect-input/v0.1"
ENGINE_ID = "openpoc-replay/v0.1"
SUPPORTED = "supported-under-stated-assumptions"


@dataclass(frozen=True)
class ReproducibilityReport:
    claim_id: str
    artifact_bindings_valid: bool
    environment_compatible: bool
    replay_executed: bool
    relation_satisfied: bool | None
    reproduction_status: str
    capture_status: str
    record_integrity_status: str
    claim_verdict: str
    actual_output: dict[str, Any] | None
    actual_output_sha256: str | None
    missing_effect_ids: tuple[str, ...]
    unexpected_input_effect_ids: tuple[str, ...]
    errors: tuple[str, ...]
    trust_assumptions: tuple[str, ...]
    non_claims: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _load_json_object(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        value = json.load(handle)
    if not isinstance(value, dict):
        raise ValueError(f"{path}: expected a JSON object")
    return value


def _canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def _sha256_bytes(value: bytes) -> str:
    return f"sha256:{hashlib.sha256(value).hexdigest()}"


def _sha256_file(path: Path) -> str:
    return _sha256_bytes(path.read_bytes())


def _sha256_json(value: Any) -> str:
    return _sha256_bytes(_canonical_json_bytes(value))


def _resolve_artifact(base: Path, relative_path: Any, label: str) -> Path:
    if not isinstance(relative_path, str) or not relative_path:
        raise ValueError(f"{label} must be a non-empty relative path")
    candidate = (base / relative_path).resolve()
    base_resolved = base.resolve()
    if candidate != base_resolved and base_resolved not in candidate.parents:
        raise ValueError(f"{label} escapes the scenario directory")
    if not candidate.is_file():
        raise ValueError(f"{label} does not resolve to a file: {relative_path}")
    return candidate


def _parse_python_floor(value: Any) -> tuple[int, int]:
    if not isinstance(value, str) or not value.startswith(">="):
        raise ValueError("runtime.python_requires must use the form >=MAJOR.MINOR")
    pieces = value[2:].split(".")
    if len(pieces) != 2 or not all(piece.isdigit() for piece in pieces):
        raise ValueError("runtime.python_requires must use the form >=MAJOR.MINOR")
    return int(pieces[0]), int(pieces[1])


def _execute_recipe(
    recipe: dict[str, Any],
    inputs: dict[str, Any],
) -> tuple[dict[str, int], tuple[str, ...]]:
    if recipe.get("schema") != RECIPE_SCHEMA:
        raise ValueError(f"unsupported recipe schema: {recipe.get('schema')!r}")
    if not isinstance(recipe.get("recipe_id"), str) or not recipe.get("recipe_id"):
        raise ValueError("recipe.recipe_id must be a non-empty string")
    if recipe.get("operation") != "sum-integer-field":
        raise ValueError(f"unsupported recipe operation: {recipe.get('operation')!r}")
    if inputs.get("schema") != INPUT_SCHEMA:
        raise ValueError(f"unsupported input schema: {inputs.get('schema')!r}")

    collection_key = recipe.get("collection")
    effect_id_field = recipe.get("effect_id_field")
    value_field = recipe.get("value_field")
    output = recipe.get("output")
    if not all(
        isinstance(value, str) and value
        for value in (collection_key, effect_id_field, value_field)
    ):
        raise ValueError("recipe collection and field names must be non-empty strings")
    if not isinstance(output, dict):
        raise ValueError("recipe.output must be an object")
    total_field = output.get("total_field")
    count_field = output.get("count_field")
    if not all(
        isinstance(value, str) and value for value in (total_field, count_field)
    ):
        raise ValueError("recipe output field names must be non-empty strings")
    if total_field == count_field:
        raise ValueError("recipe output field names must be distinct")

    effects = inputs.get(collection_key)
    if not isinstance(effects, list):
        raise ValueError(f"input field {collection_key!r} must be an array")

    total = 0
    effect_ids: list[str] = []
    for index, effect in enumerate(effects):
        if not isinstance(effect, dict):
            raise ValueError(f"effect {index} must be an object")
        effect_id = effect.get(effect_id_field)
        amount = effect.get(value_field)
        if not isinstance(effect_id, str) or not effect_id:
            raise ValueError(f"effect {index} has an invalid effect identifier")
        if effect_id in effect_ids:
            raise ValueError(f"duplicate effect identifier: {effect_id}")
        if not isinstance(amount, int) or isinstance(amount, bool) or amount < 0:
            raise ValueError(f"effect {effect_id} has an invalid non-negative amount")
        effect_ids.append(effect_id)
        total += amount

    return (
        {total_field: total, count_field: len(effects)},
        tuple(effect_ids),
    )


def _record_integrity_status(
    evidence: Any,
    actual_input_sha256: str | None,
) -> str:
    if not isinstance(evidence, dict) or actual_input_sha256 is None:
        return "unproven"
    expected_markers = (
        evidence.get("producer_attestation"),
        evidence.get("transparency_inclusion"),
        evidence.get("transparency_consistency"),
    )
    if evidence.get("submitted_input_sha256") != actual_input_sha256:
        return "violated"
    if all(marker == "fixture-assumed-valid" for marker in expected_markers):
        return "assumed-valid-for-boundary-test"
    return "unproven"


def _claim_verdict(
    required_dimensions: Any,
    statuses: dict[str, str],
    errors: list[str],
) -> str:
    if errors:
        return "insufficient"
    if not isinstance(required_dimensions, list) or not required_dimensions:
        errors.append("claim.required_dimensions must be a non-empty array")
        return "insufficient"
    if not all(isinstance(dimension, str) for dimension in required_dimensions):
        errors.append("claim.required_dimensions must contain strings")
        return "insufficient"
    if len(set(required_dimensions)) != len(required_dimensions):
        errors.append("claim.required_dimensions must be unique")
        return "insufficient"

    selected: list[str] = []
    for dimension in required_dimensions:
        if dimension not in statuses:
            errors.append(f"unsupported required assurance dimension: {dimension!r}")
            return "insufficient"
        selected.append(statuses[dimension])

    if "violated" in selected:
        return "violated"
    if all(status == SUPPORTED for status in selected):
        return SUPPORTED
    return "insufficient"


def evaluate_manifest(path: Path) -> ReproducibilityReport:
    manifest = _load_json_object(path)
    errors: list[str] = []

    if manifest.get("schema") != SCENARIO_SCHEMA:
        errors.append(f"unsupported scenario schema: {manifest.get('schema')!r}")

    claim = manifest.get("claim")
    if not isinstance(claim, dict):
        claim = {}
        errors.append("claim must be an object")
    claim_id = claim.get("claim_id")
    if not isinstance(claim_id, str) or not claim_id:
        claim_id = "invalid-claim"
        errors.append("claim.claim_id must be a non-empty string")
    if not isinstance(claim.get("property"), str) or not claim.get("property"):
        errors.append("claim.property must be a non-empty string")
    if not isinstance(claim.get("scope"), dict) or not claim.get("scope"):
        errors.append("claim.scope must be a non-empty object")
    if not isinstance(claim.get("confidence_target"), str) or not claim.get(
        "confidence_target"
    ):
        errors.append("claim.confidence_target must be a non-empty string")
    adversary_model = claim.get("adversary_model")
    if not isinstance(adversary_model, dict):
        errors.append("claim.adversary_model must be an object")
    elif not all(
        isinstance(adversary_model.get(field), list)
        for field in ("controls", "excludes")
    ):
        errors.append("claim.adversary_model must declare controls and excludes arrays")
    elif not all(
        isinstance(value, str) and value
        for field in ("controls", "excludes")
        for value in adversary_model[field]
    ):
        errors.append(
            "claim.adversary_model controls and excludes must contain non-empty strings"
        )

    artifacts = manifest.get("artifacts")
    if not isinstance(artifacts, dict):
        artifacts = {}
        errors.append("artifacts must be an object")

    recipe: dict[str, Any] | None = None
    inputs: dict[str, Any] | None = None
    actual_input_sha256: str | None = None
    artifact_bindings_valid = True
    try:
        recipe_path = _resolve_artifact(path.parent, artifacts.get("recipe"), "recipe")
        input_path = _resolve_artifact(path.parent, artifacts.get("input"), "input")
        actual_recipe_sha256 = _sha256_file(recipe_path)
        actual_input_sha256 = _sha256_file(input_path)
        if artifacts.get("recipe_sha256") != actual_recipe_sha256:
            errors.append(
                "recipe digest mismatch: "
                f"expected {artifacts.get('recipe_sha256')!r}, got {actual_recipe_sha256!r}"
            )
            artifact_bindings_valid = False
        if artifacts.get("input_sha256") != actual_input_sha256:
            errors.append(
                "input digest mismatch: "
                f"expected {artifacts.get('input_sha256')!r}, got {actual_input_sha256!r}"
            )
            artifact_bindings_valid = False
        recipe = _load_json_object(recipe_path)
        inputs = _load_json_object(input_path)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        errors.append(str(exc))
        artifact_bindings_valid = False

    expected_output = manifest.get("expected_output")
    if not isinstance(expected_output, dict):
        errors.append("expected_output must be an object")
        artifact_bindings_valid = False
        expected_output = {}
    actual_expected_output_sha256 = _sha256_json(expected_output)
    if manifest.get("expected_output_sha256") != actual_expected_output_sha256:
        errors.append(
            "expected output digest mismatch: "
            f"expected {manifest.get('expected_output_sha256')!r}, "
            f"got {actual_expected_output_sha256!r}"
        )
        artifact_bindings_valid = False

    runtime = manifest.get("runtime")
    environment_compatible = False
    if not isinstance(runtime, dict):
        errors.append("runtime must be an object")
    elif runtime.get("engine") != ENGINE_ID:
        errors.append(f"unsupported replay engine: {runtime.get('engine')!r}")
    else:
        try:
            python_floor = _parse_python_floor(runtime.get("python_requires"))
            environment_compatible = sys.version_info[:2] >= python_floor
        except ValueError as exc:
            errors.append(str(exc))

    replay_executed = False
    relation_satisfied: bool | None = None
    actual_output: dict[str, Any] | None = None
    actual_output_sha256: str | None = None
    input_effect_ids: tuple[str, ...] = ()
    execution_blocked = not artifact_bindings_valid or recipe is None or inputs is None
    if not execution_blocked and environment_compatible:
        try:
            actual_output, input_effect_ids = _execute_recipe(recipe, inputs)
            replay_executed = True
            actual_output_sha256 = _sha256_json(actual_output)
            relation_satisfied = actual_output == expected_output
        except ValueError as exc:
            errors.append(str(exc))

    if not artifact_bindings_valid or not environment_compatible or not replay_executed:
        reproduction_status = "unproven"
    elif relation_satisfied is False:
        reproduction_status = "violated"
    else:
        reproduction_status = SUPPORTED

    capture = manifest.get("capture")
    missing_effect_ids: tuple[str, ...] = ()
    unexpected_input_effect_ids: tuple[str, ...] = ()
    if not isinstance(capture, dict) or not isinstance(
        capture.get("external_effect_ids"), list
    ):
        capture_status = "unproven"
    else:
        external_values = capture["external_effect_ids"]
        if not all(isinstance(value, str) and value for value in external_values):
            errors.append("capture.external_effect_ids must contain non-empty strings")
            capture_status = "unproven"
        elif not replay_executed:
            capture_status = "unproven"
        else:
            external_ids = set(external_values)
            presented_ids = set(input_effect_ids)
            if len(external_ids) != len(external_values):
                errors.append("capture.external_effect_ids must be unique")
                capture_status = "unproven"
            else:
                missing_effect_ids = tuple(sorted(external_ids - presented_ids))
                unexpected_input_effect_ids = tuple(sorted(presented_ids - external_ids))
                if missing_effect_ids or unexpected_input_effect_ids:
                    capture_status = "violated"
                elif capture.get("non_bypassable_gate_attested") is True:
                    capture_status = SUPPORTED
                else:
                    capture_status = "unproven"

    record_integrity_status = _record_integrity_status(
        manifest.get("external_evidence"),
        actual_input_sha256,
    )
    statuses = {
        "reproducibility": reproduction_status,
        "capture_completeness": capture_status,
        "record_integrity": record_integrity_status,
    }
    claim_verdict = _claim_verdict(
        claim.get("required_dimensions"),
        statuses,
        errors,
    )

    assumptions = [
        "SHA-256 collision resistance",
        "the independent replay verifier and local runtime are not compromised",
        "the declarative recipe correctly encodes the property under test",
    ]
    if isinstance(capture, dict) and isinstance(
        capture.get("external_effect_ids"), list
    ):
        assumptions.append(
            "external effect inventory is independent fixture ground truth"
        )
    if isinstance(capture, dict) and capture.get("non_bypassable_gate_attested") is True:
        assumptions.append("all relevant effects must traverse the attested gate")
    if isinstance(manifest.get("external_evidence"), dict):
        assumptions.append(
            "transparency and producer-attestation validity are fixture inputs, "
            "not production proof validation"
        )

    non_claims = (
        "successful replay over supplied inputs does not prove that the inputs "
        "are complete",
        "record integrity does not reveal effects that never entered the evidence "
        "path",
        "the fixture is not a production TEE, SCITT, PKI, SNARK, or "
        "transparency-log implementation",
    )

    return ReproducibilityReport(
        claim_id=claim_id,
        artifact_bindings_valid=artifact_bindings_valid,
        environment_compatible=environment_compatible,
        replay_executed=replay_executed,
        relation_satisfied=relation_satisfied,
        reproduction_status=reproduction_status,
        capture_status=capture_status,
        record_integrity_status=record_integrity_status,
        claim_verdict=claim_verdict,
        actual_output=actual_output,
        actual_output_sha256=actual_output_sha256,
        missing_effect_ids=missing_effect_ids,
        unexpected_input_effect_ids=unexpected_input_effect_ids,
        errors=tuple(errors),
        trust_assumptions=tuple(assumptions),
        non_claims=non_claims,
    )


def _expected_mismatches(
    report: ReproducibilityReport,
    expected: dict[str, Any],
) -> list[str]:
    actual = report.to_dict()
    mismatches: list[str] = []
    for key, expected_value in expected.items():
        actual_value = actual.get(key)
        if isinstance(actual_value, tuple):
            actual_value = list(actual_value)
        if actual_value != expected_value:
            mismatches.append(
                f"{key}: expected {expected_value!r}, got {actual_value!r}"
            )
    return mismatches


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Replay a bound OpenPoC claim and report assurance dimensions separately"
    )
    parser.add_argument("manifest", help="Path to an OpenPoC-02 scenario manifest")
    args = parser.parse_args()

    manifest_path = Path(args.manifest)
    try:
        manifest = _load_json_object(manifest_path)
        report = evaluate_manifest(manifest_path)
    except Exception as exc:
        print(json.dumps({"error": str(exc)}, indent=2))
        return 1

    print(json.dumps(report.to_dict(), indent=2))
    expected = manifest.get("expected")
    if isinstance(expected, dict):
        mismatches = _expected_mismatches(report, expected)
        if mismatches:
            print("EXPECTED RESULT MISMATCH")
            for mismatch in mismatches:
                print(f"  - {mismatch}")
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
