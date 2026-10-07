#!/usr/bin/env python3
"""Prepare a pinned, selected-module input bundle without executing Lean code.

This is source preparation, not a proof checker.  No upstream Lakefile is run.
Only ordinary, one-line Lean imports with simple module names are supported;
other import syntax is rejected instead of silently understating the closure.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
from typing import Any


PINNED_COMMIT = "adc7f1241b42e322a6451854ab7e4b4c146bf78a"
SOURCE_URL = "https://github.com/openai/math"
SOLUTION_MODULE = "OAI.Geometry.Borsuk.Main"
CHALLENGE_LEAN = "lean/ComparatorChallenges/BorsukNine.lean"
CHALLENGE_JSON = "lean/ComparatorChallenges/BorsukNine.json"
PAPER_ROOT = (
    "preprints/A-nine-dimensional-counterexample-to-Borsuks-covering-assertion-"
    "September-23-2026"
)
METADATA_PATHS = (
    "lean/lean-toolchain", "lean/lake-manifest.json", "lean/lakefile.lean",
    CHALLENGE_JSON, f"{PAPER_ROOT}/README.md", f"{PAPER_ROOT}/paper.pdf",
)
MODULE_RE = re.compile(r"[A-Za-z_][A-Za-z_0-9]*(?:\.[A-Za-z_][A-Za-z_0-9]*)*\Z")


class PreparationError(RuntimeError):
    """The pinned input bundle cannot be established."""


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def _git(repo: Path, *args: str) -> bytes:
    # A partial clone must contain the needed objects already; preparation must
    # not fetch mutable remote content or evaluate project-supplied build hooks.
    env = dict(os.environ, GIT_NO_LAZY_FETCH="1", GIT_OPTIONAL_LOCKS="0",
               GIT_NO_REPLACE_OBJECTS="1")
    result = subprocess.run(
        ["git", "--no-replace-objects", "-C", str(repo), *args], stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, env=env, check=False,
    )
    if result.returncode:
        detail = result.stderr.decode(errors="replace").strip()
        raise PreparationError(f"git {args[0]} failed: {detail}")
    return result.stdout


def _head(repo: Path) -> str:
    return _git(repo, "rev-parse", "HEAD").decode().strip()


def _reject_replace_refs(repo: Path) -> None:
    replacements = _git(repo, "for-each-ref", "--format=%(refname)", "refs/replace").decode().strip()
    if replacements:
        raise PreparationError(f"Git replace refs are not permitted: {replacements}")


def _tree(repo: Path, commit: str) -> dict[str, tuple[str, str]]:
    entries = {}
    for entry in _git(repo, "ls-tree", "-r", "-z", commit).split(b"\0"):
        if not entry:
            continue
        meta, path = entry.split(b"\t", 1)
        mode, kind, blob = meta.decode().split()
        if kind == "blob":
            entries[path.decode()] = (mode, blob)
    return entries


def _read_blob(repo: Path, tree: dict[str, tuple[str, str]], path: str) -> bytes:
    if path not in tree:
        raise PreparationError(f"Missing pinned source file: {path}")
    mode, blob = tree[path]
    if mode not in {"100644", "100755"}:
        raise PreparationError(f"Unsupported source mode {mode}: {path}")
    raw = _git(repo, "cat-file", "blob", blob)
    git_hash = hashlib.sha1(f"blob {len(raw)}\0".encode() + raw).hexdigest()
    if git_hash != blob:
        raise PreparationError(f"Git blob content mismatch: {path}")
    return raw


def strip_comments_and_strings(text: str) -> str:
    """Mask comments/strings, retaining newlines and code token positions.

    Lean block comments nest.  Unterminated comments/strings fail preparation;
    this deliberately remains a lexical scan rather than semantic elaboration.
    """
    result = list(text)
    pos, block_depth, in_string = 0, 0, False
    while pos < len(text):
        if block_depth:
            if text.startswith("/-", pos):
                block_depth += 1
                result[pos:pos + 2] = "  "
                pos += 2
            elif text.startswith("-/", pos):
                block_depth -= 1
                result[pos:pos + 2] = "  "
                pos += 2
            else:
                if text[pos] != "\n":
                    result[pos] = " "
                pos += 1
        elif in_string:
            if text[pos] == "\\":
                result[pos] = " "
                pos += 1
                if pos < len(text):
                    if text[pos] != "\n":
                        result[pos] = " "
                    pos += 1
            else:
                if text[pos] == '"':
                    in_string = False
                if text[pos] != "\n":
                    result[pos] = " "
                pos += 1
        elif text.startswith("/-", pos):
            block_depth = 1
            result[pos:pos + 2] = "  "
            pos += 2
        elif text.startswith("--", pos):
            while pos < len(text) and text[pos] != "\n":
                result[pos] = " "
                pos += 1
        elif text[pos] == '"':
            in_string = True
            result[pos] = " "
            pos += 1
        else:
            pos += 1
    if block_depth or in_string:
        raise PreparationError("Unterminated Lean comment or string")
    return "".join(result)


def parse_imports(text: str) -> list[str]:
    code = strip_comments_and_strings(text)
    imports = []
    for number, line in enumerate(code.splitlines(), 1):
        line = line.strip()
        if re.match(r"(?:public\s+|private\s+)?import\b", line):
            if not line.startswith("import "):
                raise PreparationError(f"Unsupported import syntax on line {number}")
            names = line[7:].split()
            if not names or not all(MODULE_RE.fullmatch(name) for name in names):
                raise PreparationError(f"Unsupported import syntax on line {number}")
            imports.extend(names)
    return sorted(set(imports))


def token_signals(text: str) -> dict[str, list[int]]:
    code = strip_comments_and_strings(text)
    return {
        token: [code.count("\n", 0, match.start()) + 1
                for match in re.finditer(rf"\b{token}\b", code)]
        for token in ("sorry", "admit", "axiom")
    }


def _subject_clean(repo: Path, commit: str, sources: dict[str, bytes]) -> None:
    paths = sorted(sources)
    for diff_args in (("diff", "--name-only", commit, "--"),
                      ("diff", "--cached", "--name-only", commit, "--")):
        dirty = _git(repo, *diff_args, *paths).decode().strip()
        if dirty:
            raise PreparationError(f"Dirty tracked subject paths: {dirty}")
    # Explicit byte checks also cover modified skip-worktree files, which Git
    # diff can omit in a sparse checkout.  Missing sparse files are permitted.
    sparse = {}
    for entry in _git(repo, "ls-files", "-v", "-z", "--", *paths).split(b"\0"):
        if entry:
            sparse[entry[2:].decode()] = entry[:1] == b"S"
    for path, raw in sources.items():
        candidate = repo / path
        for part in candidate.parents:
            if part == repo:
                break
            if part.is_symlink():
                raise PreparationError(f"Symlink in source path: {path}")
        if candidate.is_symlink():
            raise PreparationError(f"Symlink source: {path}")
        if candidate.exists():
            if not candidate.is_file() or candidate.read_bytes() != raw:
                raise PreparationError(f"Dirty tracked subject path: {path}")
        elif not sparse.get(path, False):
            raise PreparationError(f"Deleted tracked subject path: {path}")


def selected_lakefile(mathlib_rev: str) -> bytes:
    if not re.fullmatch(r"[0-9a-f]{40}", mathlib_rev):
        raise PreparationError("Mathlib dependency revision must be a full Git SHA")
    # Authored locally: the upstream Lakefile is captured only as evidence.
    return (
        '# T-Trace pilot156 selected-module profile; upstream hooks are not executed.\n'
        'name = "ttrace_math_pilot_156"\n'
        'version = "0.1.0"\n\n'
        '[[require]]\nname = "mathlib"\n'
        'git = "https://github.com/leanprover-community/mathlib4.git"\n'
        f'rev = "{mathlib_rev}"\n\n'
        '[[lean_lib]]\nname = "OAI"\n\n'
        '[[lean_lib]]\nname = "ComparatorChallenges"\n'
    ).encode()


def build_inventory(repo: Path, expected_commit: str = PINNED_COMMIT
                    ) -> tuple[dict[str, Any], dict[str, bytes]]:
    """Return deterministic metadata and bundle bytes for the pinned subject.

    expected_commit is an API parameter to support local fixture repositories;
    the command-line pilot always uses PINNED_COMMIT.
    """
    repo = repo.resolve()
    _reject_replace_refs(repo)
    initial = _head(repo)
    if initial != expected_commit:
        raise PreparationError(f"Wrong source HEAD: expected {expected_commit}, observed {initial}")
    tree = _tree(repo, expected_commit)
    sources: dict[str, bytes] = {}
    modules: dict[str, list[str]] = {}
    pending, external = [SOLUTION_MODULE], set()
    while pending:
        module = pending.pop()
        if module in modules:
            continue
        path = "lean/" + module.replace(".", "/") + ".lean"
        raw = sources.setdefault(path, _read_blob(repo, tree, path))
        imports = parse_imports(raw.decode())
        modules[module] = imports
        for imported in imports:
            if imported == "OAI" or imported.startswith("OAI."):
                pending.append(imported)
            elif imported == "Mathlib" or imported.startswith("Mathlib."):
                external.add(imported)
            elif imported == "Lean" or imported.startswith("Lean.") or imported == "Init" or imported.startswith("Init."):
                external.add(imported)
            else:
                raise PreparationError(f"Unbound external import {imported} in {path}")
    for path in (*METADATA_PATHS, CHALLENGE_LEAN):
        sources[path] = _read_blob(repo, tree, path)
    challenge = json.loads(sources[CHALLENGE_JSON])
    if (challenge.get("solution_module") != SOLUTION_MODULE
            or challenge.get("challenge_module") != "ComparatorChallenges.BorsukNine"
            or challenge.get("theorem_names") != ["OAI.BorsukNine.main_theorem"]):
        raise PreparationError("Unexpected Comparator target configuration")
    challenge_imports = parse_imports(sources[CHALLENGE_LEAN].decode())
    if not set(challenge_imports).issubset(external):
        raise PreparationError("Challenge has imports outside selected solution dependency profile")
    manifest = json.loads(sources["lean/lake-manifest.json"])
    dependencies = []
    for package in manifest["packages"]:
        if package.get("type") != "git" or not re.fullmatch(r"[0-9a-f]{40}", package.get("rev", "")):
            raise PreparationError(f"Unpinned upstream dependency: {package.get('name')}")
        dependencies.append({key: package[key] for key in ("name", "url", "rev", "inputRev", "inherited")})
    mathlib = [p for p in dependencies if p["name"] == "mathlib"]
    if len(mathlib) != 1:
        raise PreparationError("Expected exactly one Mathlib dependency pin")
    toolchain = sources["lean/lean-toolchain"].decode().strip()
    if not re.fullmatch(r"leanprover/lean4:v\d+\.\d+\.\d+", toolchain):
        raise PreparationError("Expected a version-pinned Lean toolchain")
    _subject_clean(repo, expected_commit, sources)
    if _head(repo) != initial:
        raise PreparationError("Source HEAD changed during preparation")
    _reject_replace_refs(repo)
    entries, bundle, total_signals = [], {}, {token: 0 for token in ("sorry", "admit", "axiom")}
    total_lines = 0
    for path, raw in sorted(sources.items()):
        is_solution = path.startswith("lean/OAI/")
        role = ("solution_import_closure" if is_solution else
                "challenge_template" if path == CHALLENGE_LEAN else
                "comparator_configuration" if path == CHALLENGE_JSON else "source_metadata")
        bundle_path = (f"provenance/upstream/{path}" if path in {
            "lean/lake-manifest.json", "lean/lakefile.lean"} else path)
        item: dict[str, Any] = {
            "path": path, "bundle_path": bundle_path, "role": role,
            "git_blob": tree[path][1], "sha256": hashlib.sha256(raw).hexdigest(),
            "size_bytes": len(raw),
        }
        if path.endswith(".lean") and role != "source_metadata":
            text = raw.decode()
            item["line_count"] = len(text.splitlines())
            item["imports"] = parse_imports(text)
            item["code_token_signals"] = token_signals(text)
            if is_solution:
                item["module"] = path[5:-5].replace("/", ".")
                total_lines += item["line_count"]
                for token, lines in item["code_token_signals"].items():
                    total_signals[token] += len(lines)
        entries.append(item)
        bundle[bundle_path] = raw
    lakefile = selected_lakefile(mathlib[0]["rev"])
    bundle["lean/lakefile.toml"] = lakefile
    inventory = {
        "schema": "ttrace.math-pilot.source-inventory/v1", "pilot": "openai-math-156",
        "source": {"repository": SOURCE_URL, "commit": expected_commit,
                   "head_initial": initial, "head_final": initial,
                   "tracked_subject_clean": True,
                   "replace_refs_checked_empty": True, "git_replacements_disabled": True},
        "profile": "selected-module-mathlib-only",
        "scope": {"solution_module": SOLUTION_MODULE, "oai_module_count": len(modules),
                  "oai_line_count": total_lines, "external_imports": sorted(external),
                  "solution_code_token_signal_counts": total_signals,
                  "challenge_sorry": "Intentional unproved challenge template; not a solution proof."},
        "targets": [
            {"name": "OAI.BorsukNine.main_theorem", "comparator_selected": True,
             "verification_status": "not_executed"},
            {"name": "OAI.BorsukNine.euclidean_nine_counterexample", "comparator_selected": False,
             "verification_status": "not_executed", "requires_separate_goal": True},
        ],
        "dependencies": {"toolchain": toolchain, "selected_direct": mathlib,
                         "upstream_manifest_pins": sorted(dependencies, key=lambda p: p["name"]),
                         "dependency_closure_verified": False},
        "comparator": challenge,
        "files": entries,
        "derived_files": [{"path": "lean/lakefile.toml", "sha256": hashlib.sha256(lakefile).hexdigest(),
                           "size_bytes": len(lakefile), "origin": "locally-authored-selected-module-profile"}],
        "limitations": [
            "Source lexical signals do not establish Lean semantics, theorem truth, or allowed axiom closure.",
            "Neither Lean elaboration nor Comparator has been executed by this preparation script.",
            "Dependency repository bytes and Mathlib transitive imports are not verified by this inventory.",
            "The selected-module profile does not reproduce the entire upstream Lake project or execute its hooks.",
            "Paper-to-formalization alignment and scientific novelty require separate review.",
        ],
    }
    inventory["bundle_inputs_sha256"] = hashlib.sha256(canonical({
        path: hashlib.sha256(raw).hexdigest() for path, raw in sorted(bundle.items())
    })).hexdigest()
    return inventory, bundle


def prepare(repo: Path, output_dir: Path, expected_commit: str = PINNED_COMMIT) -> dict[str, Any]:
    output = output_dir.resolve()
    source = repo.resolve()
    if output == source or source in output.parents:
        raise PreparationError("Output must not be inside the source repository")
    if output.exists() and (not output.is_dir() or any(output.iterdir())):
        raise PreparationError("Output directory must be absent or empty")
    inventory, bundle = build_inventory(source, expected_commit)
    output.mkdir(parents=True, exist_ok=True)
    for path, raw in sorted(bundle.items()):
        destination = output / path
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(raw)
    (output / "source-inventory.json").write_text(
        json.dumps(inventory, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    )
    return inventory


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-repo", type=Path, required=True)
    output = parser.add_mutually_exclusive_group(required=True)
    output.add_argument("--output-dir", type=Path, help="Materialize selected source bundle")
    output.add_argument("--inventory-only", type=Path, help="Write deterministic metadata only")
    args = parser.parse_args()
    try:
        if args.output_dir:
            inventory = prepare(args.source_repo, args.output_dir)
        else:
            inventory, _ = build_inventory(args.source_repo)
            args.inventory_only.parent.mkdir(parents=True, exist_ok=True)
            args.inventory_only.write_text(
                json.dumps(inventory, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
            )
    except (PreparationError, UnicodeDecodeError, ValueError, KeyError) as exc:
        parser.exit(1, f"Preparation rejected: {exc}\n")
    print(json.dumps({"status": "prepared-source-only", "commit": inventory["source"]["commit"],
                      "oai_module_count": inventory["scope"]["oai_module_count"],
                      "bundle_inputs_sha256": inventory["bundle_inputs_sha256"]}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
