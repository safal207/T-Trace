"""Bounded input/receipt integrity checks for a math proof pilot.

This module does not decide mathematical truth. EXIT_ZERO describes a process;
UNASSESSED describes its proof semantics. Hashes are not signatures. A verifier
must receive the expected subject and fresh run nonce through a trusted channel.
Only declared inputs are covered, not an inferred Lean dependency closure.
Input snapshots before and after execution cannot detect transient changes that
are restored before the final snapshot. Read-only execution is a caller duty.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import math
import os
from pathlib import Path, PurePosixPath
import platform
import re
import shutil
import signal
import subprocess
import sys
import time
from typing import Any


MANIFEST_SCHEMA = "math-pilot-manifest/v1"
RECEIPT_SCHEMA = "math-pilot-receipt/v1"
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
COMMIT = re.compile(r"[0-9a-f]{40}\Z")


class PilotError(ValueError):
    """The bounded verification contract was not satisfied."""


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


def digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _keys(value: Any, expected: set[str], name: str) -> None:
    if not isinstance(value, dict) or set(value) != expected:
        raise PilotError(f"{name}: missing or unexpected fields")


def _sha(value: Any, name: str) -> None:
    if not isinstance(value, str) or not SHA256.fullmatch(value):
        raise PilotError(f"{name}: expected lowercase SHA-256")


def relative_path(value: str) -> str:
    if not isinstance(value, str) or not value or "\\" in value:
        raise PilotError("input path must be a nonempty relative POSIX path")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in (".", "..") for part in value.split("/")):
        raise PilotError(f"unsafe path: {value}")
    if path.as_posix() != value or any(not part for part in value.split("/")):
        raise PilotError(f"noncanonical path: {value}")
    return value


def safe_file(root: Path, value: str) -> Path:
    relative_path(value)
    root = root.resolve(strict=True)
    result = root
    for part in PurePosixPath(value).parts:
        result = result / part
        if result.is_symlink():
            raise PilotError(f"symlink forbidden: {value}")
    if not result.is_file():
        raise PilotError(f"missing regular file: {value}")
    return result


def _read_json(path: Path) -> Any:
    def no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise PilotError(f"duplicate JSON key: {key}")
            result[key] = value
        return result
    try:
        if path.is_symlink() or not path.is_file():
            raise PilotError(f"missing regular JSON file: {path.name}")
        return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=no_duplicates,
                          parse_constant=lambda x: (_ for _ in ()).throw(PilotError(x)))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise PilotError(f"invalid JSON file: {path.name}") from error


def write_json(path: Path, value: Any) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False,
                               allow_nan=False) + "\n", encoding="utf-8")


def _theorems(value: Any) -> list[str]:
    if not isinstance(value, list) or not value or any(
            not isinstance(name, str) or not name.strip() for name in value):
        raise PilotError("theorem_names must be a nonempty string list")
    if len(set(value)) != len(value):
        raise PilotError("duplicate theorem names")
    return value


def _git_bytes(bundle: Path, *args: str) -> bytes:
    try:
        result = subprocess.run(["git", "--no-replace-objects", "-C", str(bundle), *args], capture_output=True,
                                timeout=30, check=False)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise PilotError("git provenance check unavailable") from error
    if result.returncode:
        raise PilotError("git provenance check failed")
    return result.stdout


def validate_manifest(manifest: Any) -> None:
    _keys(manifest, {"schema", "subject", "config_path", "inputs", "coverage"}, "manifest")
    if manifest["schema"] != MANIFEST_SCHEMA or manifest["coverage"] != "declared-inputs-only":
        raise PilotError("unsupported manifest schema or coverage")
    subject = manifest["subject"]
    _keys(subject, {"repository", "commit", "theorem_names", "origin_check"}, "subject")
    if not isinstance(subject["repository"], str) or not subject["repository"]:
        raise PilotError("repository identifier is required")
    if not isinstance(subject["commit"], str) or not COMMIT.fullmatch(subject["commit"]):
        raise PilotError("subject commit must be a full lowercase 40-character Git SHA")
    _theorems(subject["theorem_names"])
    if subject["origin_check"] not in ("git-blobs-at-commit", "caller-asserted"):
        raise PilotError("unsupported origin check")
    relative_path(manifest["config_path"])
    inputs = manifest["inputs"]
    if not isinstance(inputs, list) or not inputs:
        raise PilotError("missing declared inputs")
    paths: set[str] = set()
    roles: set[str] = set()
    for entry in inputs:
        _keys(entry, {"path", "role", "sha256", "size_bytes"}, "input")
        path = relative_path(entry["path"])
        if path in paths:
            raise PilotError("duplicate declared path")
        paths.add(path)
        if entry["role"] not in ("config", "source", "dependency"):
            raise PilotError("unsupported input role")
        roles.add(entry["role"])
        _sha(entry["sha256"], "input digest")
        if type(entry["size_bytes"]) is not int or entry["size_bytes"] < 0:
            raise PilotError("invalid file size")
    if roles != {"config", "source", "dependency"}:
        raise PilotError("config, source and dependency inputs are all required")
    configs = [entry["path"] for entry in inputs if entry["role"] == "config"]
    if configs != [manifest["config_path"]]:
        raise PilotError("config inventory must contain exactly the selected config")


def preflight_manifest(bundle: Path, manifest: Any) -> dict[str, Any]:
    validate_manifest(manifest)
    bundle = bundle.resolve(strict=True)
    for entry in manifest["inputs"]:
        data = safe_file(bundle, entry["path"]).read_bytes()
        if len(data) != entry["size_bytes"] or digest(data) != entry["sha256"]:
            raise PilotError(f"input changed: {entry['path']}")
    config = _read_json(safe_file(bundle, manifest["config_path"]))
    if not isinstance(config, dict) or config.get("theorem_names") != manifest["subject"]["theorem_names"]:
        raise PilotError("config theorem_names differ from subject")
    if manifest["subject"]["origin_check"] == "git-blobs-at-commit":
        commit = manifest["subject"]["commit"]
        if _git_bytes(bundle, "for-each-ref", "--format=%(refname)", "refs/replace").strip():
            raise PilotError("Git replacement refs are forbidden for origin checks")
        if _git_bytes(bundle, "rev-parse", "HEAD").decode().strip() != commit:
            raise PilotError("checkout HEAD differs from subject commit")
        for entry in manifest["inputs"]:
            blob = _git_bytes(bundle, "show", f"{commit}:{entry['path']}")
            if digest(blob) != entry["sha256"]:
                raise PilotError(f"input is not the Git blob at subject commit: {entry['path']}")
    return {"input_integrity": "VALID", "manifest_sha256": digest(canonical_bytes(manifest)),
            "execution_status": "NOT_RUN", "proof_semantic_status": "NOT_ESTABLISHED",
            "coverage": manifest["coverage"]}


def create_manifest(bundle: Path, repository: str, commit: str, theorem_names: list[str],
                    config_path: str, source_paths: list[str], dependency_paths: list[str],
                    check_git: bool = False) -> dict[str, Any]:
    entries = []
    for role, paths in (("config", [config_path]), ("source", source_paths),
                        ("dependency", dependency_paths)):
        for value in paths:
            data = safe_file(bundle, value).read_bytes()
            entries.append({"path": value, "role": role, "sha256": digest(data),
                            "size_bytes": len(data)})
    manifest = {"schema": MANIFEST_SCHEMA,
                "subject": {"repository": repository, "commit": commit,
                            "theorem_names": theorem_names,
                            "origin_check": "git-blobs-at-commit" if check_git else "caller-asserted"},
                "config_path": config_path, "inputs": sorted(entries, key=lambda x: x["path"]),
                "coverage": "declared-inputs-only"}
    preflight_manifest(bundle, manifest)
    return manifest


def _now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


def _timestamp(value: Any) -> dt.datetime:
    try:
        parsed = dt.datetime.fromisoformat(value)
    except (TypeError, ValueError) as error:
        raise PilotError("invalid timestamp") from error
    if parsed.tzinfo is None:
        raise PilotError("timestamps must include timezone")
    return parsed


def _executable(argv0: str, bundle: Path) -> Path | None:
    if "/" in argv0:
        value = Path(argv0)
        value = value if value.is_absolute() else bundle / value
        # Preserve the executable's invocation name: resolving a symlink can
        # change virtualenv Python or argv[0]-selected launcher behavior.
        return value.absolute() if value.is_file() else None
    # Popen changes cwd before resolving relative PATH entries. Mirror that
    # search here, then use the resulting absolute path for actual execution.
    entries = []
    for item in os.environ.get("PATH", os.defpath).split(os.pathsep):
        directory = Path(item or ".")
        directory = directory if directory.is_absolute() else bundle / directory
        entries.append(str(directory.absolute()))
    found = shutil.which(argv0, path=os.pathsep.join(entries))
    return Path(found).absolute() if found else None


def _config_argument(command: list[str], bundle: Path, config_path: str) -> bool:
    expected = bundle / config_path
    # Require the selected config as a separate argv item, not text in a shell script.
    for token in command[1:]:
        if token.startswith("-"):
            continue
        candidate = Path(token)
        candidate = candidate if candidate.is_absolute() else bundle / candidate
        if candidate.absolute() == expected.absolute():
            return True
    return False


def _tool_identity(command: list[str], bundle: Path) -> dict[str, Any]:
    executable = _executable(command[0], bundle)
    identity: dict[str, Any] = {
        "python": platform.python_version(), "platform": platform.platform(),
        "executable_path": str(executable) if executable else None,
        "executable_sha256": digest(executable.read_bytes()) if executable else None,
        "version_probe": {"status": "NOT_PROBED", "reason": "no implicit execution outside supplied argv"},
    }
    return identity


def _terminate_owned_process(process: subprocess.Popen) -> None:
    """Stop the invocation's group, including descendants of an exited leader."""
    try:
        if os.name == "posix":
            os.killpg(process.pid, signal.SIGKILL)
        elif process.poll() is None:
            process.kill()
    except ProcessLookupError:
        pass
    process.wait()


def run_record(bundle: Path, manifest_path: Path, out: Path, command: list[str],
               run_id: str, timeout: float = 600) -> dict[str, Any]:
    if not isinstance(run_id, str) or len(run_id) < 16 or run_id.isspace():
        raise PilotError("use an independently generated fresh run nonce of at least 16 characters")
    if not command or any(not isinstance(token, str) or not token for token in command):
        raise PilotError("a nonempty subprocess argv is required")
    if not math.isfinite(timeout) or timeout <= 0:
        raise PilotError("timeout must be finite and positive")
    bundle = bundle.resolve(strict=True)
    manifest_path = manifest_path.resolve(strict=True)
    manifest_bytes = manifest_path.read_bytes()
    manifest = _read_json(manifest_path)
    preflight_manifest(bundle, manifest)
    if not _config_argument(command, bundle, manifest["config_path"]):
        raise PilotError("command does not receive the selected config as a separate argument")
    resolved_executable = _executable(command[0], bundle)
    # Record and invoke the same executable; a relative PATH must not cause
    # the parent's cwd binary to be hashed while a bundle binary is executed.
    command = [str(resolved_executable), *command[1:]] if resolved_executable else list(command)
    out = out.absolute()
    if out.exists() or out.is_symlink():
        raise PilotError("output directory already exists; use a new run directory")
    out.mkdir(parents=True, exist_ok=False)
    tool_identity = _tool_identity(command, bundle)
    started_at = _now()
    started = time.monotonic()
    code: int | None = None
    error: str | None = None
    status = "SPAWN_FAILED"
    with (out / "stdout.log").open("wb") as stdout, (out / "stderr.log").open("wb") as stderr:
        process = None
        interrupted = False
        try:
            try:
                process = subprocess.Popen(command, cwd=bundle, stdout=stdout, stderr=stderr,
                                           start_new_session=(os.name == "posix"))
            except OSError as exception:
                error = type(exception).__name__ + ": " + str(exception)
            else:
                try:
                    code = process.wait(timeout=timeout)
                    status = "EXIT_ZERO" if code == 0 else "EXIT_NONZERO"
                except subprocess.TimeoutExpired:
                    status = "TIMEOUT"
        except BaseException:
            interrupted = True
            raise
        finally:
            if process is not None:
                try:
                    _terminate_owned_process(process)
                except BaseException:
                    # Preserve the original interruption or postspawn error.
                    if not interrupted:
                        raise
        if status == "TIMEOUT":
            code = process.returncode
    ended_at = _now()
    inputs_after = "MATCHED_POSTRUN_SNAPSHOT"
    try:
        if manifest_path.read_bytes() != manifest_bytes:
            raise PilotError("manifest postrun snapshot differs from prerun snapshot")
        preflight_manifest(bundle, manifest)
    except (PilotError, OSError):
        inputs_after = "POSTRUN_MISMATCH"
    receipt = {
        "schema": RECEIPT_SCHEMA, "run_id": run_id, "started_at": started_at,
        "ended_at": ended_at, "manifest": manifest,
        "manifest_sha256": digest(canonical_bytes(manifest)),
        "manifest_file_sha256": digest(manifest_bytes),
        "command": command, "cwd": str(bundle), "tool_identity": tool_identity,
        "duration_seconds": round(time.monotonic() - started, 6),
        "exit_code": code, "execution_status": status,
        "proof_semantic_status": "UNASSESSED" if status == "EXIT_ZERO" else "NOT_ESTABLISHED",
        "inputs_after": inputs_after, "error": error,
        "artifacts": [{"path": name, "sha256": digest((out / name).read_bytes()),
                       "size_bytes": (out / name).stat().st_size}
                      for name in ("stdout.log", "stderr.log")],
    }
    write_json(out / "receipt.json", receipt)
    return receipt


def verify_receipt(bundle: Path, manifest_path: Path, receipt_path: Path, *,
                   expected_repository: str, expected_commit: str,
                   expected_theorems: list[str], expected_config: str,
                   expected_run_id: str, expected_manifest_sha256: str,
                   not_before: str | None = None) -> dict[str, Any]:
    manifest = _read_json(manifest_path)
    _sha(expected_manifest_sha256, "independently expected manifest digest")
    if digest(canonical_bytes(manifest)) != expected_manifest_sha256:
        raise PilotError("manifest differs from independently pinned manifest digest")
    preflight_manifest(bundle, manifest)
    subject = manifest["subject"]
    if (subject["repository"] != expected_repository or subject["commit"] != expected_commit
            or subject["theorem_names"] != expected_theorems
            or manifest["config_path"] != expected_config):
        raise PilotError("manifest differs from independently expected subject")
    receipt = _read_json(receipt_path)
    _keys(receipt, {"schema", "run_id", "started_at", "ended_at", "manifest", "manifest_sha256",
                    "manifest_file_sha256", "command", "cwd", "tool_identity", "duration_seconds",
                    "exit_code", "execution_status", "proof_semantic_status", "inputs_after",
                    "error", "artifacts"}, "receipt")
    if receipt["schema"] != RECEIPT_SCHEMA:
        raise PilotError("unsupported receipt schema")
    if receipt["run_id"] != expected_run_id or len(expected_run_id) < 16:
        raise PilotError("receipt is from a different or stale run")
    started, ended = _timestamp(receipt["started_at"]), _timestamp(receipt["ended_at"])
    if ended < started or (not_before and started < _timestamp(not_before)):
        raise PilotError("receipt fails freshness timestamp bounds")
    if receipt["manifest"] != manifest or receipt["manifest_sha256"] != digest(canonical_bytes(manifest)):
        raise PilotError("receipt manifest binding differs")
    if receipt["manifest_file_sha256"] != digest(manifest_path.read_bytes()):
        raise PilotError("manifest file bytes differ from recorded bytes")
    command = receipt["command"]
    if not isinstance(command, list) or not command or any(
            not isinstance(token, str) or not token for token in command):
        raise PilotError("invalid recorded command")
    if not _config_argument(command, bundle.resolve(), expected_config):
        raise PilotError("recorded command does not bind selected config")
    if receipt["inputs_after"] != "MATCHED_POSTRUN_SNAPSHOT":
        raise PilotError("postrun input snapshot mismatch")
    artifacts = receipt["artifacts"]
    if not isinstance(artifacts, list) or len(artifacts) != 2:
        raise PilotError("missing required execution artifacts")
    if [item.get("path") for item in artifacts if isinstance(item, dict)] != ["stdout.log", "stderr.log"]:
        raise PilotError("unexpected or missing execution artifacts")
    for item in artifacts:
        _keys(item, {"path", "sha256", "size_bytes"}, "artifact")
        data = safe_file(receipt_path.parent, item["path"]).read_bytes()
        if digest(data) != item["sha256"] or len(data) != item["size_bytes"]:
            raise PilotError("execution artifact bytes differ")
    status, code = receipt["execution_status"], receipt["exit_code"]
    if status not in ("EXIT_ZERO", "EXIT_NONZERO", "TIMEOUT", "SPAWN_FAILED"):
        raise PilotError("receipt contains no supported actual execution status")
    expected_semantic = "UNASSESSED" if status == "EXIT_ZERO" else "NOT_ESTABLISHED"
    if receipt["proof_semantic_status"] != expected_semantic:
        raise PilotError("receipt overstates proof semantics")
    if (status == "EXIT_ZERO" and (type(code) is not int or code != 0)) or (
            status in ("EXIT_NONZERO", "TIMEOUT") and (type(code) is not int or code == 0)) or (
            status == "SPAWN_FAILED" and code is not None):
        raise PilotError("execution status disagrees with exit code")
    tool = receipt["tool_identity"]
    _keys(tool, {"python", "platform", "executable_path", "executable_sha256", "version_probe"}, "tool identity")
    if status != "SPAWN_FAILED" and (not tool["executable_path"] or not tool["executable_sha256"]):
        raise PilotError("missing executed tool identity")
    if status != "SPAWN_FAILED" and (
            not isinstance(tool["executable_path"], str)
            or not Path(tool["executable_path"]).is_absolute()
            or tool["executable_path"] != command[0]):
        raise PilotError("executed tool identity differs from recorded command")
    # This is internal consistency of an unsigned archived receipt. The
    # original runtime need not exist on this host, and is not authenticated.
    if tool["executable_sha256"] is not None:
        _sha(tool["executable_sha256"], "executable digest")
    return {"receipt_integrity": "VALID", "execution_status": status,
            "proof_semantic_status": expected_semantic, "run_id": expected_run_id,
            "manifest_sha256": receipt["manifest_sha256"], "coverage": manifest["coverage"],
            "authenticity": "NOT_ASSESSED"}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="action", required=True)
    create = sub.add_parser("create", help="hash declared inputs and create a manifest")
    create.add_argument("--bundle", type=Path, required=True)
    create.add_argument("--repository", required=True)
    create.add_argument("--commit", required=True)
    create.add_argument("--theorem", action="append", required=True)
    create.add_argument("--config", required=True)
    create.add_argument("--source", action="append", required=True)
    create.add_argument("--dependency", action="append", required=True)
    create.add_argument("--check-git", action="store_true")
    create.add_argument("--out", type=Path, required=True)
    preflight = sub.add_parser("preflight", help="validate inputs; proof execution remains NOT_RUN")
    record = sub.add_parser("record", help="execute subprocess and record actual results")
    verify = sub.add_parser("verify", help="independently verify subject, receipt and logs")
    for command_parser in (preflight, record, verify):
        command_parser.add_argument("--bundle", type=Path, required=True)
        command_parser.add_argument("--manifest", type=Path, required=True)
    preflight.add_argument("--require-tool", action="append", default=[])
    record.add_argument("--out", type=Path, required=True)
    record.add_argument("--run-id", required=True)
    record.add_argument("--timeout", type=float, default=600)
    record.add_argument("command", nargs=argparse.REMAINDER)
    verify.add_argument("--receipt", type=Path, required=True)
    verify.add_argument("--expected-repository", required=True)
    verify.add_argument("--expected-commit", required=True)
    verify.add_argument("--expected-theorem", action="append", required=True)
    verify.add_argument("--expected-config", required=True)
    verify.add_argument("--expected-run-id", required=True)
    verify.add_argument("--expected-manifest-sha256", required=True)
    verify.add_argument("--not-before")
    args = parser.parse_args(argv)
    try:
        if args.action == "create":
            if args.out.exists():
                raise PilotError("manifest output already exists")
            result = create_manifest(args.bundle, args.repository, args.commit, args.theorem,
                                     args.config, args.source, args.dependency, args.check_git)
            write_json(args.out, result)
            result = preflight_manifest(args.bundle, result)
        elif args.action == "preflight":
            result = preflight_manifest(args.bundle, _read_json(args.manifest))
            result["blockers"] = [f"tool unavailable: {name}" for name in args.require_tool
                                   if _executable(name, args.bundle.resolve()) is None]
            print(json.dumps(result, sort_keys=True))
            return 1 if result["blockers"] else 0
        elif args.action == "record":
            command = args.command[1:] if args.command[:1] == ["--"] else args.command
            previous_handler = signal.getsignal(signal.SIGTERM)

            def terminate(signum, _frame):
                raise SystemExit(128 + signum)

            signal.signal(signal.SIGTERM, terminate)
            try:
                receipt = run_record(args.bundle, args.manifest, args.out, command, args.run_id, args.timeout)
            finally:
                signal.signal(signal.SIGTERM, previous_handler)
            result = {key: receipt[key] for key in ("run_id", "execution_status", "proof_semantic_status", "inputs_after")}
            print(json.dumps(result, sort_keys=True))
            return 0 if receipt["execution_status"] == "EXIT_ZERO" and receipt["inputs_after"] == "MATCHED_POSTRUN_SNAPSHOT" else 1
        else:
            result = verify_receipt(args.bundle, args.manifest, args.receipt,
                expected_repository=args.expected_repository, expected_commit=args.expected_commit,
                expected_theorems=args.expected_theorem, expected_config=args.expected_config,
                expected_run_id=args.expected_run_id,
                expected_manifest_sha256=args.expected_manifest_sha256, not_before=args.not_before)
            print(json.dumps(result, sort_keys=True))
            return 0 if result["execution_status"] == "EXIT_ZERO" else 1
        print(json.dumps(result, sort_keys=True))
        return 0
    except (PilotError, OSError) as error:
        print(json.dumps({"receipt_integrity": "INVALID", "error": str(error),
                          "proof_semantic_status": "NOT_ESTABLISHED"}, sort_keys=True))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
