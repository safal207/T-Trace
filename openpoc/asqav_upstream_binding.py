from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any


class SourceBindingError(ValueError):
    """Raised when the local frozen selection diverges from exact upstream."""


@dataclass(frozen=True)
class SourceBindingReport:
    schema: str
    source_repository: str
    expected_commit: str
    observed_commit: str
    raw_paths_compared: int
    manifest_records_compared: int
    lock_records_compared: int
    verified: bool

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SourceBindingError(f"cannot load {path}: {exc}") from exc


def _read_bytes(path: Path) -> bytes:
    try:
        return path.read_bytes()
    except OSError as exc:
        raise SourceBindingError(f"cannot read {path}: {exc}") from exc


def _observed_git_commit(upstream_root: Path) -> str:
    try:
        return subprocess.check_output(
            ["git", "-C", str(upstream_root), "rev-parse", "HEAD"],
            text=True,
            stderr=subprocess.STDOUT,
        ).strip()
    except (OSError, subprocess.CalledProcessError) as exc:
        raise SourceBindingError(
            f"cannot resolve upstream checkout commit at {upstream_root}: {exc}"
        ) from exc


def _upstream_paths(expected: dict[str, Any], *, relative_path: str) -> list[str]:
    paths = expected.get("upstream_paths")
    if not isinstance(paths, list) or not paths or not all(
        isinstance(path, str) and path for path in paths
    ):
        raise SourceBindingError(
            f"{relative_path}: upstream_paths must be a non-empty string array"
        )
    if len(paths) != len(set(paths)):
        raise SourceBindingError(f"{relative_path}: duplicate upstream_paths")
    return paths


def verify_upstream_binding(
    local_root: Path,
    upstream_root: Path,
    *,
    observed_commit: str | None = None,
) -> SourceBindingReport:
    pins = _load_json(local_root / "pins.json")
    if not isinstance(pins, dict):
        raise SourceBindingError("pins.json must contain an object")
    if pins.get("schema") != "ttrace.asqav-selective-omission-pins/v1":
        raise SourceBindingError("unsupported pins schema")

    expected_commit = pins.get("source_commit")
    if not isinstance(expected_commit, str) or len(expected_commit) != 40:
        raise SourceBindingError("source_commit must be a full 40-character SHA")
    resolved_commit = observed_commit or _observed_git_commit(upstream_root)
    if resolved_commit != expected_commit:
        raise SourceBindingError(
            f"upstream checkout mismatch: expected {expected_commit}, got {resolved_commit}"
        )

    files = pins.get("files")
    vectors = pins.get("vectors")
    if not isinstance(files, dict) or not files:
        raise SourceBindingError("pins.files must be a non-empty object")
    if not isinstance(vectors, list) or not vectors:
        raise SourceBindingError("pins.vectors must be a non-empty array")

    raw_paths_compared = 0
    path_to_pin: dict[str, dict[str, Any]] = {}
    for relative_path, expected in sorted(files.items()):
        if not isinstance(relative_path, str) or not isinstance(expected, dict):
            raise SourceBindingError("malformed pins.files entry")
        local_raw = _read_bytes(local_root / relative_path)
        for upstream_path in _upstream_paths(expected, relative_path=relative_path):
            upstream_raw = _read_bytes(upstream_root / upstream_path)
            if upstream_raw != local_raw:
                raise SourceBindingError(
                    f"raw source mismatch: {relative_path} != {upstream_path}"
                )
            existing = path_to_pin.get(upstream_path)
            if existing is not None and existing != expected:
                raise SourceBindingError(
                    f"conflicting local pins map to upstream path {upstream_path}"
                )
            path_to_pin[upstream_path] = expected
            raw_paths_compared += 1

    manifest_path = pins.get("source_manifest")
    lock_path = pins.get("source_manifest_lock")
    if not isinstance(manifest_path, str) or not isinstance(lock_path, str):
        raise SourceBindingError("source manifest paths must be strings")

    manifest = _load_json(upstream_root / manifest_path)
    if not isinstance(manifest, list):
        raise SourceBindingError("upstream manifest must be an array")
    manifest_by_dir = {
        record.get("dir"): record
        for record in manifest
        if isinstance(record, dict) and isinstance(record.get("dir"), str)
    }

    manifest_records_compared = 0
    for vector in vectors:
        if not isinstance(vector, dict) or not isinstance(vector.get("id"), str):
            raise SourceBindingError("malformed vector pin")
        vector_id = vector["id"]
        record = manifest_by_dir.get(vector_id)
        if not isinstance(record, dict):
            raise SourceBindingError(f"manifest has no record for {vector_id}")
        expected_record = _load_json(local_root / vector_id / "expected.json")
        if not isinstance(expected_record, dict):
            raise SourceBindingError(f"{vector_id}/expected.json must be an object")
        observed_record = {key: value for key, value in record.items() if key != "dir"}
        if observed_record != expected_record:
            raise SourceBindingError(
                f"manifest record mismatch for {vector_id}: {observed_record!r}"
            )
        manifest_records_compared += 1

    lock_document = _load_json(upstream_root / lock_path)
    if not isinstance(lock_document, dict) or not isinstance(
        lock_document.get("files"), list
    ):
        raise SourceBindingError("upstream manifest lock must contain files[]")
    lock_by_path = {
        record.get("path"): record
        for record in lock_document["files"]
        if isinstance(record, dict) and isinstance(record.get("path"), str)
    }

    lock_records_compared = 0
    for upstream_path, expected in sorted(path_to_pin.items()):
        prefix = "verifier/conformance-vectors/"
        if not upstream_path.startswith(prefix):
            raise SourceBindingError(
                f"upstream path is outside conformance-vector root: {upstream_path}"
            )
        lock_relative_path = upstream_path[len(prefix) :]
        record = lock_by_path.get(lock_relative_path)
        if not isinstance(record, dict):
            raise SourceBindingError(
                f"manifest lock has no record for {lock_relative_path}"
            )
        if record.get("sha256") != expected.get("sha256"):
            raise SourceBindingError(
                f"manifest-lock sha256 mismatch for {lock_relative_path}"
            )
        if record.get("bytes") != expected.get("bytes"):
            raise SourceBindingError(
                f"manifest-lock byte-count mismatch for {lock_relative_path}"
            )
        lock_records_compared += 1

    return SourceBindingReport(
        schema="ttrace.asqav-upstream-binding/v1",
        source_repository=pins["source_repository"],
        expected_commit=expected_commit,
        observed_commit=resolved_commit,
        raw_paths_compared=raw_paths_compared,
        manifest_records_compared=manifest_records_compared,
        lock_records_compared=lock_records_compared,
        verified=True,
    )


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Bind the frozen T-Trace selection to an exact Asqav checkout, "
            "including raw bytes, manifest records, and manifest-lock records"
        )
    )
    parser.add_argument("local_root", type=Path)
    parser.add_argument("upstream_root", type=Path)
    args = parser.parse_args()

    try:
        report = verify_upstream_binding(args.local_root, args.upstream_root)
    except SourceBindingError as exc:
        print(json.dumps({"status": "error", "error": str(exc)}, indent=2))
        return 1

    print(json.dumps(report.to_dict(), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
