"""Snapshot pinned dependency Git blobs, including literal symlink blobs.

Symlink targets are recorded as Git data, not dereferenced source content.
This is a point-in-time snapshot; compiled dependency caches remain trusted.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
from typing import Any


PINNED_MATHLIB_REV = "d13f23b723b8a846827a245b89c10fc7d3f11612"


class DependencySnapshotError(ValueError):
    """A dependency checkout did not match the bounded pinned snapshot policy."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise DependencySnapshotError(message)


def _git(repo: Path, *args: str) -> bytes:
    env = {"PATH": "/usr/bin:/bin", "GIT_NO_REPLACE_OBJECTS": "1", "GIT_NO_LAZY_FETCH": "1"}
    return subprocess.check_output(["git", "--no-replace-objects", "-C", str(repo), *args], env=env)


def _tracked_blob(repo: Path, path: str, mode: str, kind: str, blob: str) -> dict[str, Any]:
    _require(kind == "blob" and mode in ("100644", "100755", "120000"),
             f"Unsupported tracked mode/kind: {path}: {mode} {kind}")
    relative = Path(path)
    _require(not relative.is_absolute() and ".." not in relative.parts,
             f"Unsafe tracked path: {path}")
    target = repo / relative
    # Git tree directories cannot be substituted with filesystem symlinks.
    parent = target.parent
    while parent != repo:
        _require(not parent.is_symlink(), f"Symlink directory in tracked path: {path}")
        parent = parent.parent
    try:
        actual_mode = target.lstat().st_mode
    except FileNotFoundError as error:
        raise DependencySnapshotError(f"Missing tracked file: {path}") from error
    entry: dict[str, Any] = {"path": path, "mode": mode, "git_blob": blob}
    if mode == "120000":
        _require(stat.S_ISLNK(actual_mode), f"Expected actual symlink: {path}")
        link_text = os.readlink(target)
        link_path = Path(link_text)
        _require(not link_path.is_absolute(), f"Absolute symlink target: {path}")
        try:
            destination = (target.parent / link_path).resolve(strict=False)
        except (OSError, RuntimeError) as error:
            raise DependencySnapshotError(f"Cannot resolve contained symlink target: {path}") from error
        _require(destination.is_relative_to(repo.resolve()), f"Symlink target outside dependency repo: {path}")
        # Git's symlink blob stores exactly the link text. A contained dangling
        # symlink is valid data here; target existence is not asserted.
        raw = os.fsencode(link_text)
        entry["symlink_target"] = link_text
    else:
        _require(stat.S_ISREG(actual_mode), f"Expected regular tracked file: {path}")
        # Git records only the owner's executable bit for regular files;
        # other permission bits do not distinguish 100644 from 100755.
        _require(bool(actual_mode & stat.S_IXUSR) == (mode == "100755"),
                 f"Tracked executable mode mismatch: {path}")
        raw = target.read_bytes()
    actual_blob = hashlib.sha1(f"blob {len(raw)}\0".encode() + raw).hexdigest()
    _require(actual_blob == blob, f"Tracked Git blob mismatch: {path}")
    entry["sha256"] = hashlib.sha256(raw).hexdigest()
    return entry


def snapshot_dependencies(root: Path, *, expected_mathlib_rev: str = PINNED_MATHLIB_REV) -> dict[str, Any]:
    root = root.resolve(strict=True)
    manifest = json.loads((root / "lake-manifest.json").read_text())
    package_root = root / manifest.get("packagesDir", ".lake/packages")
    mathlib_packages = json.loads((package_root / "mathlib/lake-manifest.json").read_text())["packages"]
    expected = {package["name"]: package for package in mathlib_packages}
    selected = {package["name"]: package for package in manifest["packages"] if package["name"] != "mathlib"}
    _require(set(selected) == set(expected), "Selected dependency names differ from pinned Mathlib manifest")
    for name, package in selected.items():
        _require(package["type"] == expected[name]["type"] == "git", f"Non-Git dependency: {name}")
        _require((package["url"], package["rev"]) == (expected[name]["url"], expected[name]["rev"]),
                 f"Dependency pin differs from pinned Mathlib manifest: {name}")
    items = []
    for package in manifest["packages"]:
        _require(package["type"] == "git" and bool(re.fullmatch("[0-9a-f]{40}", package["rev"])),
                 f"Invalid Git dependency pin: {package['name']}")
        repo = (package_root / package["name"]).resolve(strict=True)
        _require(_git(repo, "rev-parse", "HEAD").decode().strip() == package["rev"],
                 f"Dependency checkout HEAD differs from pin: {package['name']}")
        _require(not _git(repo, "for-each-ref", "--format=%(refname)", "refs/replace").strip(),
                 f"Git replacement refs forbidden: {package['name']}")
        files = []
        for tree_entry in _git(repo, "ls-tree", "-r", "-z", "HEAD").split(b"\0"):
            if not tree_entry:
                continue
            metadata, raw_path = tree_entry.split(b"\t", 1)
            mode, kind, blob = metadata.decode().split()
            files.append(_tracked_blob(repo, os.fsdecode(raw_path), mode, kind, blob))
        items.append({"name": package["name"], "url": package["url"], "commit": package["rev"], "files": files})
    _require(any(item["name"] == "mathlib" and item["commit"] == expected_mathlib_rev for item in items),
             "Unexpected Mathlib pin")
    return {"schema": "ttrace.math-pilot.dependency-snapshot/v1",
            "scope": "selected-manifest-tracked-source-bytes", "packages": items,
            "compiled_cache": "TRUSTED_NOT_REBUILT"}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("bundle", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    result = snapshot_dependencies(args.bundle)
    args.output.write_text(json.dumps(result, sort_keys=True, separators=(",", ":")) + "\n")


if __name__ == "__main__":
    main()
