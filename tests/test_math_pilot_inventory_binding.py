import hashlib
import json

import pytest

from openpoc.math_pilot import PilotError
from scripts.create_math_pilot_manifest import bind_inventory


def fixture_bundle(tmp_path):
    bundle = tmp_path / "bundle"
    bundle.mkdir()
    config = "lean/ComparatorChallenges/BorsukNine.json"
    (bundle / config).parent.mkdir(parents=True)
    (bundle / config).write_text(json.dumps({"theorem_names": ["Fixture.goal"]}))
    (bundle / "fixture.lean").write_text("-- Synthetic input, no proof claim\n")
    (bundle / "toolchain.lock").write_text("fixture-version\n")
    files = []
    for path, role in [(config, "comparator_configuration"),
                       ("fixture.lean", "solution_import_closure"),
                       ("toolchain.lock", "dependency_metadata")]:
        raw = (bundle / path).read_bytes()
        files.append({"bundle_path": path, "role": role,
                      "sha256": hashlib.sha256(raw).hexdigest(), "size_bytes": len(raw)})
    inventory = {"source": {"repository": "fixture/only", "commit": "a" * 40},
                 "comparator": {"theorem_names": ["Fixture.goal"]},
                 "files": files, "derived_files": []}
    raw = json.dumps(inventory)
    (bundle / "source-inventory.json").write_text(raw)
    expected = tmp_path / "independent-inventory.json"
    expected.write_text(raw)
    return bundle, expected, inventory


def test_complete_inventory_becomes_declared_receipt_inputs(tmp_path):
    bundle, expected, _ = fixture_bundle(tmp_path)
    manifest = bind_inventory(bundle, expected)
    assert {entry["path"] for entry in manifest["inputs"]} == {
        "lean/ComparatorChallenges/BorsukNine.json", "fixture.lean", "toolchain.lock",
        "source-inventory.json"}
    assert manifest["coverage"] == "declared-inputs-only"


def test_changed_prepared_bytes_are_rejected_against_retained_policy(tmp_path):
    bundle, expected, _ = fixture_bundle(tmp_path)
    (bundle / "fixture.lean").write_text("changed\n")
    with pytest.raises(PilotError, match="retained source policy"):
        bind_inventory(bundle, expected)


def test_rebound_inventory_and_sources_cannot_replace_retained_policy(tmp_path):
    bundle, expected, inventory = fixture_bundle(tmp_path)
    raw = b"changed\n"
    (bundle / "fixture.lean").write_bytes(raw)
    inventory["files"][1].update(sha256=hashlib.sha256(raw).hexdigest(), size_bytes=len(raw))
    (bundle / "source-inventory.json").write_text(json.dumps(inventory))
    with pytest.raises(PilotError, match="independently retained inventory"):
        bind_inventory(bundle, expected)
