"""Offline CLI for the controlled artifact-handoff profile."""

from __future__ import annotations

import argparse
import json
import stat
from pathlib import Path

from ttrace.artifact_handoff import (
    HandoffValidationError, MAX_ARTIFACT_BYTES, MAX_METADATA_BYTES, MAX_RECEIPT_BYTES,
    PROFILE, REPORT_SCHEMA, verify_artifact_handoff,
)


def _read(path: Path, maximum: int) -> bytes:
    if path.is_symlink() or not stat.S_ISREG(path.stat().st_mode):
        raise HandoffValidationError("invalid-filesystem-entry", "only regular files are supported")
    with path.open("rb") as handle:
        raw = handle.read(maximum + 1)
    if len(raw) > maximum:
        raise HandoffValidationError("input-limit", "file exceeds selected profile bound")
    return raw


def verify_directory(package: Path, receiver_context: Path) -> dict:
    package = package.resolve(strict=True)
    context = receiver_context.resolve(strict=True)
    if context.is_relative_to(package):
        raise HandoffValidationError("self-supplied-context", "receiver context must be selected outside the package")
    if not package.is_dir():
        raise HandoffValidationError("invalid-package-files", "package must be a directory")
    limits = {"manifest.json": MAX_METADATA_BYTES, "artifact.bin": MAX_ARTIFACT_BYTES,
              "sender.jsonl": MAX_RECEIPT_BYTES, "receiver.jsonl": MAX_RECEIPT_BYTES}
    files = {}
    for count, path in enumerate(package.iterdir(), 1):
        if count > 4 or path.name not in limits:
            raise HandoffValidationError("invalid-package-files", "unexpected package entry")
        if path.is_symlink() or not path.resolve().is_relative_to(package):
            raise HandoffValidationError("invalid-filesystem-entry", "package links are not supported")
        files[path.name] = _read(path, limits[path.name])
    return verify_artifact_handoff(files, _read(context, MAX_METADATA_BYTES))


def render_markdown(report: dict) -> str:
    rows = [f"| {role} | {item['signature']} | {item['claim_binding']} | {item['historical_authority']} | {item['current_authority']} |"
            for role, item in report["receipts"].items()]
    return "\n".join([
        "# Artifact handoff verification", "",
        f"Handoff at the selected cutoff: **{report['handoff_at_cutoff']}**.",
        f"Supplied-snapshot comparison: **{report['cross_source']['status']}**.", "",
        f"Receiver context SHA-256: `{report['receiver_context_sha256']}`.",
        f"Transport manifest SHA-256: `{report['package_manifest_sha256']}`.",
        f"Audit cutoff (Unix ms): `{report['audit_cutoff_ms']}`; evaluation time: `{report['evaluation_time_ms']}`.", "",
        "| Role | Signature | Expected claim | Historical authority | Current authority |", "|---|---|---|---|---|", *rows, "",
        "## How to use this result", "",
        "The receiver must independently accept the policy archive, key-status completeness,",
        "observation times and snapshot finality. Matching the package manifest alone is not",
        "publisher authentication. Historical authority is evaluated at the accepted observation",
        "time, not an independently proved execution/signing instant. Current authority is a",
        "separate result and is not permission to execute a new action.", "",
        "Missing evidence is not approval. A late receipt cannot repair an earlier snapshot.",
        "The report does not prove global capture completeness, real-world effect truth,",
        "production non-bypassability, independent organizations, or an external pilot.", "",
    ])


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("package", type=Path)
    parser.add_argument("--receiver-context", required=True, type=Path)
    parser.add_argument("--format", choices=("json", "markdown"), default="json")
    args = parser.parse_args(argv)
    try:
        report = verify_directory(args.package, args.receiver_context)
    except HandoffValidationError as exc:
        print(json.dumps({"schema": REPORT_SCHEMA, "profile": PROFILE, "status": "invalid-input",
                          "error": {"code": exc.code, "message": str(exc)}}, sort_keys=True))
        return 2
    except OSError:
        print(json.dumps({"schema": REPORT_SCHEMA, "profile": PROFILE, "status": "invalid-input",
                          "error": {"code": "input-unavailable", "message": "required input could not be read"}}, sort_keys=True))
        return 2
    if args.format == "markdown":
        print(render_markdown(report), end="")
    else:
        print(json.dumps(report, indent=2, sort_keys=True))
    # Successful evaluation, including negative/insufficient verdicts, is not
    # a generic approval. Callers must inspect the named report dimensions.
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
