"""Acquire and check the selected Asqav corpus against receiver-selected pins.

This is a data transport layer around the existing receipt verifier. It does
not authenticate a publisher, supply receiver trust, or execute upstream code.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import subprocess
from pathlib import Path
from typing import Any

PIN_SCHEMA = "ttrace.asqav-source-selection/v1"
PACKAGE_SCHEMA = "ttrace.asqav-frozen-package/v1"
REPORT_SCHEMA = "ttrace.asqav-frozen-package-report/v1"
PREFIX = "verifier/conformance-vectors/"
VECTORS = (
    "asqav-14-omitted-action-chain", "asqav-15-unsigned-gap",
    "asqav-16-chain-emission-blocked",
)
VECTOR_FILES = ("predecessor.json", "receipt.json", "jwks.json", "expected.json")
OUTCOME_FIELDS = ("format", "outcome", "reason_code")
VECTOR_PATHS = tuple(PREFIX + vector + "/" + name for vector in VECTORS for name in VECTOR_FILES)
SELECTED_PATHS = frozenset((*VECTOR_PATHS, "LICENSE", PREFIX + "manifest.json",
                            PREFIX + "manifest.lock.json"))
MAX_METADATA_BYTES = 128 * 1024
MAX_FILE_BYTES = 1024 * 1024


class SourcePackageError(ValueError):
    """Selected bytes, metadata, or required source relationships did not match."""


def _json(raw: bytes, label: str) -> Any:
    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result = {}
        for key, value in items:
            if key in result:
                raise SourcePackageError(f"{label}: duplicate JSON key")
            result[key] = value
        return result

    def constant(value: str) -> None:
        raise SourcePackageError(f"{label}: non-finite JSON constant")

    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=pairs, parse_constant=constant)
    except (UnicodeError, ValueError, RecursionError) as exc:
        raise SourcePackageError(f"{label}: invalid JSON ({exc})") from exc


def _encoded(value: Any) -> bytes:
    # Transport metadata only; receipt signatures use the native canonicalizer.
    return (json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + "\n").encode("utf-8")


def _fields(value: Any, fields: set[str], label: str) -> None:
    if not isinstance(value, dict) or set(value) != fields:
        raise SourcePackageError(f"{label}: expected exact fields {sorted(fields)}")


def _bounded(path: Path, maximum: int) -> bytes:
    if not stat.S_ISREG(path.stat().st_mode):
        raise SourcePackageError("input must be a regular file")
    with path.open("rb") as handle:
        raw = handle.read(maximum + 1)
    if len(raw) > maximum:
        raise SourcePackageError("input exceeds the byte limit")
    return raw


def _external_pins(path: Path, package_root: Path) -> tuple[dict, str]:
    path = path.resolve(strict=True)
    if path.is_relative_to(package_root.resolve()):
        raise SourcePackageError("receiver-selected pins must be outside the package")
    raw = _bounded(path, MAX_METADATA_BYTES)
    pins = _json(raw, "receiver pins")
    _fields(pins, {"schema", "source_repository", "source_commit", "files"}, "receiver pins")
    if pins["schema"] != PIN_SCHEMA or pins["source_repository"] != "jagmarques/asqav-sdk":
        raise SourcePackageError("unsupported source-selection profile")
    if not isinstance(pins["source_commit"], str) or not re.fullmatch(r"[0-9a-f]{40}", pins["source_commit"]):
        raise SourcePackageError("source_commit must be a full lowercase hexadecimal SHA")
    if not isinstance(pins["files"], dict) or set(pins["files"]) != SELECTED_PATHS:
        raise SourcePackageError("selection must contain exactly the 15 declared source paths")
    for name, entry in pins["files"].items():
        _fields(entry, {"bytes", "sha256", "git_blob"}, name)
        if type(entry["bytes"]) is not int or not 0 < entry["bytes"] <= MAX_FILE_BYTES:
            raise SourcePackageError(f"{name}: invalid byte count")
        for field, width in (("sha256", 64), ("git_blob", 40)):
            if not isinstance(entry[field], str) or not re.fullmatch(r"[0-9a-f]{" + str(width) + "}", entry[field]):
                raise SourcePackageError(f"{name}: invalid {field}")
    return pins, hashlib.sha256(raw).hexdigest()


def _check_bytes(raw: bytes, entry: dict, label: str) -> None:
    if len(raw) != entry["bytes"]:
        raise SourcePackageError(f"{label}: byte count mismatch")
    if hashlib.sha256(raw).hexdigest() != entry["sha256"]:
        raise SourcePackageError(f"{label}: SHA-256 mismatch")
    blob = b"blob " + str(len(raw)).encode("ascii") + b"\0" + raw
    if hashlib.sha1(blob).hexdigest() != entry["git_blob"]:
        raise SourcePackageError(f"{label}: Git blob mismatch")


def _package_manifest(pins: dict) -> bytes:
    return _encoded({"schema": PACKAGE_SCHEMA, "selection": pins})


def _relationships(contents: dict[str, bytes], pins: dict) -> None:
    manifest = _json(contents[PREFIX + "manifest.json"], "upstream manifest")
    lock = _json(contents[PREFIX + "manifest.lock.json"], "upstream lock")
    if not isinstance(manifest, list) or not isinstance(lock, dict) or not isinstance(lock.get("files"), list):
        raise SourcePackageError("invalid upstream manifest/lock shape")

    def index(records: list, field: str) -> dict:
        result = {}
        for record in records:
            if not isinstance(record, dict) or not isinstance(record.get(field), str):
                raise SourcePackageError(f"invalid upstream {field} record")
            key = record[field]
            if key in result:
                raise SourcePackageError(f"duplicate upstream {field} record")
            result[key] = record
        return result

    by_vector = index(manifest, "dir")
    by_path = index(lock["files"], "path")
    for vector in VECTORS:
        record = by_vector.get(vector)
        expected = _json(contents[PREFIX + vector + "/expected.json"], "expected vector")
        if not isinstance(record, dict) or not isinstance(expected, dict):
            raise SourcePackageError("missing selected manifest record")
        observed = {key: value for key, value in record.items() if key != "dir"}
        for document in (observed, expected):
            if set(document) not in (set(OUTCOME_FIELDS), set(OUTCOME_FIELDS) | {"notes"}):
                raise SourcePackageError("unsupported selected outcome-record fields")
            if not all(isinstance(document[key], str) for key in document):
                raise SourcePackageError("outcome-record values must be strings")
        # The pinned upstream has intentionally different narrative notes in
        # these files. Preserve both raw files; compare the machine outcome only.
        if _encoded({key: observed[key] for key in OUTCOME_FIELDS}) != _encoded(
                {key: expected[key] for key in OUTCOME_FIELDS}):
            raise SourcePackageError("selected manifest record mismatch")
    for name in VECTOR_PATHS:
        record = by_path.get(name[len(PREFIX):])
        entry = pins["files"][name]
        if (not isinstance(record, dict) or type(record.get("bytes")) is not int
                or record["bytes"] != entry["bytes"] or record.get("sha256") != entry["sha256"]):
            raise SourcePackageError("selected lock record mismatch")


def _inventory(root: Path) -> None:
    expected_files = SELECTED_PATHS | {"manifest.json"}
    expected_dirs = {str(parent).replace("\\", "/") for name in expected_files
                     for parent in Path(name).parents if str(parent) != "."}
    found = set()
    count = 0
    for directory, dirs, files in os.walk(root, followlinks=False):
        for name in (*dirs, *files):
            count += 1
            if count > 64:
                raise SourcePackageError("package has too many filesystem entries")
            path = Path(directory) / name
            if path.is_symlink() or not path.resolve().is_relative_to(root):
                raise SourcePackageError("package links are not supported")
            relative = path.relative_to(root).as_posix()
            if name in dirs:
                if relative not in expected_dirs:
                    raise SourcePackageError("unexpected package directory")
            else:
                if relative not in expected_files or not stat.S_ISREG(path.stat().st_mode):
                    raise SourcePackageError("unexpected package file")
                found.add(relative)
    if found != expected_files:
        raise SourcePackageError("package is missing a required file")


def _read_package(root: Path, pins: dict) -> dict[str, bytes]:
    root = root.resolve(strict=True)
    _inventory(root)
    manifest = _bounded(root / "manifest.json", MAX_METADATA_BYTES)
    if manifest != _package_manifest(pins):
        raise SourcePackageError("package manifest differs from receiver-selected pins")
    contents = {}
    for name, entry in pins["files"].items():
        raw = _bounded(root / name, entry["bytes"])
        _check_bytes(raw, entry, name)
        contents[name] = raw
    _relationships(contents, pins)
    return contents


def _git(upstream: Path, *arguments: str) -> bytes:
    result = subprocess.run(
        ["git", "--no-replace-objects", "-C", str(upstream.resolve()), *arguments],
        capture_output=True, timeout=30, check=False,
    )
    if result.returncode:
        raise SourcePackageError("cannot read the selected Git revision/object")
    return result.stdout


def export_package(upstream: Path, destination: Path, trusted_pins: Path) -> dict:
    """Export Git objects, never transformed/dirty checkout files or upstream code."""
    pins, pin_digest = _external_pins(trusted_pins, destination)
    if destination.exists() or destination.is_symlink():
        raise SourcePackageError("destination must not already exist")
    commit = pins["source_commit"]
    observed = _git(upstream, "rev-parse", "--verify", commit + "^{commit}").decode("ascii").strip()
    if observed != commit:
        raise SourcePackageError("selected Git commit mismatch")
    contents = {}
    for name, entry in pins["files"].items():
        reference = commit + ":" + name
        size = _git(upstream, "cat-file", "-s", reference).decode("ascii").strip()
        if size != str(entry["bytes"]):
            raise SourcePackageError("selected Git object size mismatch")
        raw = _git(upstream, "cat-file", "blob", reference)
        _check_bytes(raw, entry, name)
        contents[name] = raw
    _relationships(contents, pins)
    destination.mkdir(parents=True, exist_ok=False)
    for name, raw in contents.items():
        path = destination / name
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("xb") as handle:
            handle.write(raw)
    with (destination / "manifest.json").open("xb") as handle:
        handle.write(_package_manifest(pins))
    return {"schema": REPORT_SCHEMA, "operation": "export", "source_commit": commit,
            "receiver_pins_sha256": pin_digest, "source_file_count": len(contents),
            "source_bytes": sum(map(len, contents.values())),
            "status": "exported-against-receiver-selected-pins"}


def verify_package(root: Path, trusted_pins: Path) -> dict:
    pins, pin_digest = _external_pins(trusted_pins, root)
    contents = _read_package(root, pins)
    try:
        from .asqav_capture_compat import CompatibilityReport, report_as_json, verify_vector_documents
    except ImportError as exc:
        raise SourcePackageError("receipt verification requires the installed receipts dependencies") from exc

    observations = []
    for vector in VECTORS:
        documents = [_json(contents[PREFIX + vector + "/" + name], name) for name in VECTOR_FILES]
        if not all(isinstance(document, dict) for document in documents):
            raise SourcePackageError("vector documents must be objects")
        observations.append(verify_vector_documents(vector, *documents))
    compatibility = CompatibilityReport(pins["source_repository"], pins["source_commit"], tuple(observations))
    return {
        "schema": REPORT_SCHEMA, "operation": "verify",
        "status": "agree" if compatibility.all_agree else "not-agreed",
        "receiver_pins_sha256": pin_digest,
        "transport_manifest_sha256": hashlib.sha256(_package_manifest(pins)).hexdigest(),
        "source_binding": {"status": "matches-receiver-selected-pins",
                           "raw_files_checked": len(contents), "manifest_records_checked": 3,
                           "manifest_comparison_fields": list(OUTCOME_FIELDS),
                           "lock_records_checked": 12, "original_license_included": True},
        "compatibility": report_as_json(compatibility),
        "trust_boundary": {
            "origin": "receiver independently accepts the external selection pins",
            "jwks": "pinned fixture key material, not production authorization",
            "freshness": "not evaluated", "external_pilot": "not performed",
            "publisher_authentication": "not established by matching hashes alone",
            "upstream_code_executed": False,
        },
    }


def render_markdown(report: dict) -> str:
    compatibility = report["compatibility"]
    rows = [f"| `{item['vector']}` | {item['status']} | {item['marker']} |"
            for item in compatibility["observations"]]
    return "\n".join([
        "# Frozen Asqav source-package verification", "",
        f"Result: **{report['status']}** for the selected three-vector corpus.", "",
        f"Source commit: `{compatibility['source_commit']}`.",
        f"Receiver pin-file SHA-256: `{report['receiver_pins_sha256']}`.",
        f"Transport manifest SHA-256: `{report['transport_manifest_sha256']}`.", "",
        "15 original source files matched the receiver-selected pins, including LICENSE.",
        "Three manifest outcomes (format/outcome/reason_code) and 12 lock records matched.",
        "Narrative notes are preserved independently, not required to be equal. Upstream code was not executed.", "",
        "| Vector | Comparison | Signed marker |", "|---|---|---|", *rows, "",
        "## Decision boundary", "",
        "This reproduces the selected fixture comparison only. The receiver must obtain and",
        "accept the pin file independently of the package. Matching hashes alone do not",
        "authenticate the publisher; bundled JWKS are fixture data, not a production trust root.",
        "A signed declaration does not independently establish its stated external cause.",
        "Capture completeness, current authorization, freshness, real-world effects, and an",
        "external pilot are not proved. The original upstream LICENSE travels unchanged;",
        "T-Trace's license does not replace it.", "",
    ])


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="operation", required=True)
    export = sub.add_parser("export")
    export.add_argument("upstream", type=Path)
    export.add_argument("destination", type=Path)
    export.add_argument("--trusted-pins", required=True, type=Path)
    verify = sub.add_parser("verify")
    verify.add_argument("package", type=Path)
    verify.add_argument("--trusted-pins", required=True, type=Path)
    verify.add_argument("--format", choices=("json", "markdown"), default="json")
    args = parser.parse_args(argv)
    try:
        if args.operation == "export":
            report = export_package(args.upstream, args.destination, args.trusted_pins)
        else:
            report = verify_package(args.package, args.trusted_pins)
    except (OSError, ValueError, subprocess.TimeoutExpired) as exc:
        print(json.dumps({"schema": REPORT_SCHEMA, "status": "error", "error": str(exc)}))
        return 1
    if args.operation == "verify" and args.format == "markdown":
        print(render_markdown(report), end="")
    else:
        print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["status"] in ("agree", "exported-against-receiver-selected-pins") else 1


if __name__ == "__main__":
    raise SystemExit(main())
