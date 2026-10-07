"""Source preparation binds bytes, pins, scope and source state independently."""

import hashlib
import json
from pathlib import Path
import subprocess

import pytest

from scripts import prepare_math_pilot as pilot


def git(repo, *args):
    return subprocess.check_output(["git", "-C", str(repo), *args]).decode().strip()


@pytest.fixture
def source(tmp_path):
    repo = tmp_path / "source"
    repo.mkdir()
    git(repo, "init", "--quiet")
    git(repo, "config", "user.email", "fixture@example.invalid")
    git(repo, "config", "user.name", "Fixture")
    files = {
        "lean/OAI/Geometry/Borsuk/Main.lean":
            b'import Mathlib\nimport OAI.Geometry.Borsuk.Child\n'
            b'/- nested /- sorry -/ axiom -/\n'
            b'theorem euclidean_nine_counterexample : True := by trivial\n',
        "lean/OAI/Geometry/Borsuk/Child.lean":
            b'import Mathlib\n-- admit\ntheorem main_theorem : True := by trivial\n',
        pilot.CHALLENGE_LEAN: b'import Mathlib\ntheorem main_theorem : True := by sorry\n',
        pilot.CHALLENGE_JSON: json.dumps({
            "challenge_module": "ComparatorChallenges.BorsukNine",
            "solution_module": pilot.SOLUTION_MODULE,
            "theorem_names": ["OAI.BorsukNine.main_theorem"],
            "definition_names": [], "permitted_axioms": ["propext"], "enable_nanoda": False,
        }).encode(),
        "lean/lean-toolchain": b'leanprover/lean4:v4.34.1\n',
        "lean/lake-manifest.json": json.dumps({"packages": [{
            "type": "git", "name": "mathlib",
            "url": "https://github.com/leanprover-community/mathlib4.git",
            "rev": "a" * 40, "inputRev": "a" * 40, "inherited": False,
        }]}).encode(),
        "lean/lakefile.lean": b'-- Upstream hooks must never execute.\n',
        f"{pilot.PAPER_ROOT}/README.md": b'Fixture paper\n',
        f"{pilot.PAPER_ROOT}/paper.pdf": b'%PDF fixture\n',
    }
    for path, raw in files.items():
        destination = repo / path
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(raw)
    git(repo, "add", ".")
    git(repo, "commit", "--quiet", "-m", "fixture")
    return repo, git(repo, "rev-parse", "HEAD")


def commit(repo):
    git(repo, "add", "--all")
    git(repo, "commit", "--quiet", "-m", "fixture change")
    return git(repo, "rev-parse", "HEAD")


def test_inventory_is_deterministic_and_binds_full_closure(source, tmp_path):
    repo, head = source
    inventory, bundle = pilot.build_inventory(repo, head)
    again, second_bundle = pilot.build_inventory(repo, head)
    assert inventory == again and bundle == second_bundle
    assert inventory["source"]["head_initial"] == inventory["source"]["head_final"] == head
    assert inventory["scope"]["oai_module_count"] == 2
    assert inventory["scope"]["external_imports"] == ["Mathlib"]
    assert inventory["scope"]["solution_code_token_signal_counts"] == {"sorry": 0, "admit": 0, "axiom": 0}
    challenge = next(item for item in inventory["files"] if item["role"] == "challenge_template")
    assert challenge["code_token_signals"]["sorry"] == [2]
    assert inventory["targets"][0]["comparator_selected"] is True
    assert inventory["targets"][1]["comparator_selected"] is False
    assert inventory["targets"][1]["requires_separate_goal"] is True
    for item in inventory["files"]:
        raw = bundle[item["bundle_path"]]
        assert item["sha256"] == hashlib.sha256(raw).hexdigest()
        assert item["git_blob"] == hashlib.sha1(f"blob {len(raw)}\0".encode() + raw).hexdigest()
    assert "lean/lakefile.lean" not in bundle
    assert "lean/lake-manifest.json" not in bundle
    assert "provenance/upstream/lean/lakefile.lean" in bundle
    assert b'"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"' in bundle["lean/lakefile.toml"]
    out = tmp_path / "bundle"
    assert pilot.prepare(repo, out, head) == inventory
    assert json.loads((out / "source-inventory.json").read_bytes()) == inventory


def test_missing_transitive_local_import_is_rejected(source):
    repo, _ = source
    (repo / "lean/OAI/Geometry/Borsuk/Child.lean").unlink()
    head = commit(repo)
    with pytest.raises(pilot.PreparationError, match="Missing pinned source file"):
        pilot.build_inventory(repo, head)


def test_dirty_tracked_source_is_rejected(source):
    repo, head = source
    (repo / "lean/OAI/Geometry/Borsuk/Child.lean").write_text("import Mathlib\naxiom forged : False\n")
    with pytest.raises(pilot.PreparationError, match="Dirty tracked subject"):
        pilot.build_inventory(repo, head)


def test_dirty_skip_worktree_source_is_still_rejected(source):
    repo, head = source
    path = "lean/OAI/Geometry/Borsuk/Child.lean"
    git(repo, "update-index", "--skip-worktree", path)
    (repo / path).write_text("import Mathlib\naxiom forged : False\n")
    with pytest.raises(pilot.PreparationError, match="Dirty tracked subject"):
        pilot.build_inventory(repo, head)


def test_sparse_absent_sources_are_read_from_immutable_blobs(source):
    repo, head = source
    path = "lean/OAI/Geometry/Borsuk/Child.lean"
    git(repo, "update-index", "--skip-worktree", path)
    (repo / path).unlink()
    inventory, bundle = pilot.build_inventory(repo, head)
    assert inventory["scope"]["oai_module_count"] == 2
    assert path in bundle


def test_wrong_source_head_is_rejected(source):
    repo, head = source
    with pytest.raises(pilot.PreparationError, match="Wrong source HEAD"):
        pilot.build_inventory(repo, "0" * 40)
    git(repo, "commit", "--quiet", "--allow-empty", "-m", "another head")
    with pytest.raises(pilot.PreparationError, match="Wrong source HEAD"):
        pilot.build_inventory(repo, head)


def test_git_replace_cannot_substitute_a_tree_beneath_the_pinned_commit(source):
    repo, head = source
    path = repo / "lean/OAI/Geometry/Borsuk/Child.lean"
    original = path.read_bytes()
    path.write_text("import Mathlib\naxiom forged : False\n")
    replacement = commit(repo)
    git(repo, "reset", "--hard", head)
    git(repo, "replace", head, replacement)
    # Reproduce the dangerous condition: numeric HEAD is unchanged while Git's
    # default object lookup silently obtains replacement source bytes.
    assert git(repo, "rev-parse", "HEAD") == head
    assert "axiom forged" in git(repo, "show", f"{head}:lean/OAI/Geometry/Borsuk/Child.lean")
    assert pilot._git(repo, "show", f"{head}:lean/OAI/Geometry/Borsuk/Child.lean") == original
    with pytest.raises(pilot.PreparationError, match="Git replace refs"):
        pilot.build_inventory(repo, head)


def test_git_replace_refs_created_during_preparation_are_rejected(source, monkeypatch):
    repo, head = source
    original_subject_clean = pilot._subject_clean

    def add_replacement(*args):
        original_subject_clean(*args)
        git(repo, "replace", head, head)

    monkeypatch.setattr(pilot, "_subject_clean", add_replacement)
    with pytest.raises(pilot.PreparationError, match="Git replace refs"):
        pilot.build_inventory(repo, head)


def test_source_head_change_during_preparation_is_rejected(source, monkeypatch):
    repo, head = source
    observed = iter([head, "0" * 40])
    monkeypatch.setattr(pilot, "_head", lambda unused: next(observed))
    with pytest.raises(pilot.PreparationError, match="HEAD changed"):
        pilot.build_inventory(repo, head)


def test_unbound_external_import_is_rejected(source):
    repo, _ = source
    (repo / "lean/OAI/Geometry/Borsuk/Child.lean").write_text("import Foreign.Project\n")
    head = commit(repo)
    with pytest.raises(pilot.PreparationError, match="Unbound external import"):
        pilot.build_inventory(repo, head)


@pytest.mark.parametrize("text", ["public import OAI.Child\n", "import OAI.«Child»\n", "import\n OAI.Child\n"])
def test_unsupported_import_syntax_fails_closed(text):
    with pytest.raises(pilot.PreparationError, match="Unsupported import"):
        pilot.parse_imports(text)


def test_comments_and_strings_do_not_create_fake_imports_or_signals():
    text = ('/- import OAI.Fake /- sorry -/ axiom -/\nimport Mathlib\n'
            '-- admit\ndef example := "sorry\\\" axiom"\n')
    assert pilot.parse_imports(text) == ["Mathlib"]
    assert pilot.token_signals(text) == {"sorry": [], "admit": [], "axiom": []}


def test_output_never_overwrites_source_or_existing_bundle(source, tmp_path):
    repo, head = source
    with pytest.raises(pilot.PreparationError, match="inside the source"):
        pilot.prepare(repo, repo / "bundle", head)
    out = tmp_path / "occupied"
    out.mkdir()
    (out / "sentinel").write_text("preserve")
    with pytest.raises(pilot.PreparationError, match="absent or empty"):
        pilot.prepare(repo, out, head)
    assert (out / "sentinel").read_text() == "preserve"
