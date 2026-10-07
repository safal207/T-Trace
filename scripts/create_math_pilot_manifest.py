"""Bind a prepared bundle to the independently retained family-156 inventory."""

import argparse
import json
from pathlib import Path

from openpoc.math_pilot import PilotError, canonical_bytes, create_manifest, digest, write_json


ROOT = Path(__file__).resolve().parents[1]


def bind_inventory(bundle: Path, expected_inventory: Path) -> dict:
    actual = json.loads((bundle / "source-inventory.json").read_bytes())
    expected = json.loads(expected_inventory.read_bytes())
    if actual != expected:
        raise PilotError("prepared inventory differs from independently retained inventory")
    config = "lean/ComparatorChallenges/BorsukNine.json"
    sources = [item["bundle_path"] for item in actual["files"]
               if item["role"] in {"solution_import_closure", "challenge_template"}]
    dependencies = [item["bundle_path"] for item in actual["files"]
                    if item["bundle_path"] != config and item["bundle_path"] not in sources]
    dependencies += [item["path"] for item in actual["derived_files"]]
    dependencies.append("source-inventory.json")
    manifest = create_manifest(bundle, actual["source"]["repository"],
                               actual["source"]["commit"],
                               actual["comparator"]["theorem_names"],
                               config, sources, dependencies)
    retained = {item["bundle_path"]: item for item in expected["files"]}
    retained.update({item["path"]: item for item in expected["derived_files"]})
    for item in manifest["inputs"]:
        if item["path"] in retained:
            policy = retained[item["path"]]
            if item["sha256"] != policy["sha256"] or item["size_bytes"] != policy["size_bytes"]:
                raise PilotError(f"prepared bytes differ from retained source policy: {item['path']}")
    return manifest


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bundle", type=Path, required=True)
    parser.add_argument("--expected-inventory", type=Path,
                        default=ROOT / "examples/math-pilot-156/source-inventory.json")
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    try:
        if args.out.exists() or args.out.is_symlink():
            raise PilotError("manifest output already exists")
        manifest = bind_inventory(args.bundle, args.expected_inventory)
        write_json(args.out, manifest)
    except (PilotError, OSError, ValueError, KeyError) as error:
        parser.exit(2, f"Manifest binding rejected: {error}\n")
    print(json.dumps({"manifest_sha256": digest(canonical_bytes(manifest)),
                      "input_count": len(manifest["inputs"]),
                      "proof_execution": "NOT_RUN"}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
