"""Synthetic Git fixtures check dependency data integrity, not Lean proofs."""

import hashlib
import json
import os
from pathlib import Path
import subprocess

import pytest

from scripts.math_pilot_dependencies import DependencySnapshotError, snapshot_dependencies


def git(repo, *args):
    return subprocess.run(["git", "-C", str(repo), *args], capture_output=True,
                          check=True).stdout.decode().strip()


def commit(repo, message="Synthetic dependency fixture"):
    git(repo, "add", "--all")
    git(repo, "-c", "user.name=Synthetic", "-c", "user.email=fixture@example.invalid",
        "commit", "-qm", message)
    return git(repo, "rev-parse", "HEAD")


def fixture_dependency(tmp_path, *, link_target="lean", dangling=False):
    bundle = tmp_path / "bundle"
    repo = bundle / ".lake/packages/mathlib"
    repo.mkdir(parents=True)
    git(repo, "init", "-q")
    (repo / "lake-manifest.json").write_text(json.dumps({"packages": []}))
    (repo / "regular.txt").write_text("synthetic tracked source\n")
    (repo / "lean").write_text("synthetic executable, not Lean\n")
    (repo / "lean").chmod(0o755)
    (repo / "lean.py").symlink_to(link_target)
    if dangling:
        (repo / "contained-dangling").symlink_to("missing-contained-target")
    revision = commit(repo)
    (bundle / "lake-manifest.json").write_text(json.dumps({
        "packagesDir": ".lake/packages",
        "packages": [{"name": "mathlib", "type": "git", "url": "https://example.invalid/synthetic",
                      "rev": revision}]}))
    return bundle, repo, revision


def snapshot(bundle, revision):
    # The production CLI always enforces the actual pinned Mathlib revision.
    # Tests substitute only this synthetic Git fixture's independently retained pin.
    return snapshot_dependencies(bundle, expected_mathlib_rev=revision)


def test_regular_and_executable_files_still_match_git_blobs(tmp_path):
    bundle, repo, revision = fixture_dependency(tmp_path)
    files = {entry["path"]: entry for entry in snapshot(bundle, revision)["packages"][0]["files"]}
    for path, mode in (("regular.txt", "100644"), ("lean", "100755")):
        assert files[path]["mode"] == mode
        assert files[path]["sha256"] == hashlib.sha256((repo / path).read_bytes()).hexdigest()
        assert "symlink_target" not in files[path]


def test_contained_symlink_snapshot_hashes_literal_target_without_dereference(tmp_path):
    bundle, repo, revision = fixture_dependency(tmp_path)
    entry = next(item for item in snapshot(bundle, revision)["packages"][0]["files"] if item["path"] == "lean.py")
    assert entry["mode"] == "120000"
    assert entry["symlink_target"] == "lean"
    raw = os.fsencode(os.readlink(repo / "lean.py"))
    assert entry["sha256"] == hashlib.sha256(raw).hexdigest()
    assert entry["git_blob"] == hashlib.sha1(f"blob {len(raw)}\0".encode() + raw).hexdigest()
    assert entry["sha256"] != hashlib.sha256((repo / "lean").read_bytes()).hexdigest()


def test_contained_dangling_symlink_is_valid_pinned_git_data(tmp_path):
    bundle, _, revision = fixture_dependency(tmp_path, dangling=True)
    entry = next(item for item in snapshot(bundle, revision)["packages"][0]["files"]
                 if item["path"] == "contained-dangling")
    assert entry["mode"] == "120000"
    assert entry["symlink_target"] == "missing-contained-target"


def test_changed_link_literal_rejected_even_if_same_resolved_target(tmp_path):
    bundle, repo, revision = fixture_dependency(tmp_path)
    (repo / "lean.py").unlink()
    (repo / "lean.py").symlink_to("./lean")
    with pytest.raises(DependencySnapshotError, match="Git blob mismatch"):
        snapshot(bundle, revision)


def test_symlink_replaced_with_matching_regular_blob_bytes_rejected(tmp_path):
    bundle, repo, revision = fixture_dependency(tmp_path)
    (repo / "lean.py").unlink()
    (repo / "lean.py").write_text("lean")
    with pytest.raises(DependencySnapshotError, match="Expected actual symlink"):
        snapshot(bundle, revision)


@pytest.mark.parametrize("target", ["/absolute/outside", "../outside"])
def test_pinned_absolute_or_outside_symlink_refused(tmp_path, target):
    bundle, _, revision = fixture_dependency(tmp_path, link_target=target)
    with pytest.raises(DependencySnapshotError, match="Absolute symlink target|outside dependency repo"):
        snapshot(bundle, revision)


def test_regular_tracked_file_replaced_by_symlink_refused(tmp_path):
    bundle, repo, revision = fixture_dependency(tmp_path)
    (repo / "regular.txt").unlink()
    (repo / "regular.txt").symlink_to("lean")
    with pytest.raises(DependencySnapshotError, match="Expected regular tracked file"):
        snapshot(bundle, revision)


def test_changed_regular_file_refused(tmp_path):
    bundle, repo, revision = fixture_dependency(tmp_path)
    (repo / "regular.txt").write_text("modified source\n")
    with pytest.raises(DependencySnapshotError, match="Git blob mismatch"):
        snapshot(bundle, revision)


def test_tracked_gitlink_mode_and_commit_kind_refused(tmp_path):
    bundle, repo, revision = fixture_dependency(tmp_path)
    git(repo, "update-index", "--add", "--cacheinfo", f"160000,{revision},unsupported-submodule")
    git(repo, "-c", "user.name=Synthetic", "-c", "user.email=fixture@example.invalid",
        "commit", "-qm", "Synthetic Gitlink")
    revision = git(repo, "rev-parse", "HEAD")
    manifest = json.loads((bundle / "lake-manifest.json").read_text())
    manifest["packages"][0]["rev"] = revision
    (bundle / "lake-manifest.json").write_text(json.dumps(manifest))
    with pytest.raises(DependencySnapshotError, match="Unsupported tracked mode/kind"):
        snapshot(bundle, revision)


def test_git_replace_cannot_rebind_pinned_dependency(tmp_path):
    bundle, repo, original = fixture_dependency(tmp_path)
    (repo / "regular.txt").write_text("replacement bytes\n")
    replacement = commit(repo, "Synthetic replacement")
    git(repo, "replace", original, replacement)
    git(repo, "reset", "--hard", original)
    with pytest.raises(DependencySnapshotError, match="Git replacement refs forbidden"):
        snapshot(bundle, original)


def test_production_mathlib_revision_is_still_enforced(tmp_path):
    bundle, _, _ = fixture_dependency(tmp_path)
    with pytest.raises(DependencySnapshotError, match="Unexpected Mathlib pin"):
        snapshot_dependencies(bundle)
