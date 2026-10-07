"""Fail-closed verdict gates and a deadline for the hosted pilot's whole run.

These checks consume Comparator observations; they do not verify Lean proofs.
The supervisor gives the shell time to write partial evidence before CI's own
step deadline, and seals that evidence after the supervised process exits.
"""

from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import math
import os
from pathlib import Path, PurePosixPath
import signal
import subprocess
import sys
import time


RUN_BUDGET_SECONDS = 3300
CLEANUP_GRACE_SECONDS = 30
SOURCE_COMMIT = "adc7f1241b42e322a6451854ab7e4b4c146bf78a"
COMPARATOR_COMMIT = "d03acab154d269c06e60e4de7e4cc85deebff94b"
EXPORTER_COMMIT = "076e8e57707e813375e8f9da8bf989799ace9680"


class RunnerCheckError(ValueError):
    """A required observation did not match the recorded pilot profile."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RunnerCheckError(message)


def _write_json(path: Path, value: object) -> None:
    # An interrupted finalizer must leave either a complete report or none.
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")
    temporary.replace(path)


def check_exporter(manifest_path: str | Path, expected_rev: str) -> None:
    packages = json.loads(Path(manifest_path).read_text())["packages"]
    require(len(packages) == 1 and packages[0]["name"] == "lean4export",
            "Comparator manifest must contain only lean4export")
    require(packages[0]["rev"] == expected_rev, "Exporter revision does not match its pin")


def write_sparse_patterns(inventory_path: str | Path, destination: str | Path) -> None:
    inventory = json.loads(Path(inventory_path).read_text())
    paths = sorted({item["path"] for item in inventory["files"]})
    for path in paths:
        parsed = PurePosixPath(path)
        require(not parsed.is_absolute() and ".." not in parsed.parts,
                f"Source path must be relative and contained: {path!r}")
        require(not any(char in path for char in ("\n", "\r", "*", "?", "[", "]", "\\", "!")),
                f"Source path is not a literal sparse-checkout pattern: {path!r}")
    Path(destination).write_text("".join("/" + path + "\n" for path in paths))


def check_control(case: str, code: int, log_path: str | Path) -> None:
    text = Path(log_path).read_text(errors="replace")
    if case == "simple_match":
        okay = code == 0 and "Lean default kernel accepts the solution" in text and "Your solution is okay!" in text
    elif case == "simple_mismatch":
        okay = code != 0 and "Challenge and solution" in text and ("do not match" in text or "don't match" in text)
    elif case == "simple_axiom_issue":
        okay = code != 0 and "Illegal axiom detected: 'helper'" in text
    else:
        raise RunnerCheckError(f"Unknown Comparator control: {case}")
    require(okay, f"{case}: expected Comparator verdict not observed (exit={code})")
    print(f"{case}: expected Comparator verdict observed (exit={code})")


def check_acceptance(run_dir: str | Path) -> None:
    run = Path(run_dir)
    receipt = json.loads((run / "receipt.json").read_text())
    require(receipt["execution_status"] == "EXIT_ZERO" and type(receipt["exit_code"]) is int and receipt["exit_code"] == 0,
            "Selected Comparator did not exit successfully")
    require(receipt["inputs_after"] == "MATCHED_POSTRUN_SNAPSHOT", "Selected inputs changed after execution")
    require(receipt["proof_semantic_status"] == "UNASSESSED", "Receipt unexpectedly claims proof semantics")
    text = (run / "stdout.log").read_text(errors="replace")
    for marker in ("Building ComparatorChallenges.BorsukNine", "Building OAI.Geometry.Borsuk.Main",
                   "Lean default kernel accepts the solution", "Your solution is okay!"):
        require(marker in text, f"Selected Comparator output is missing: {marker}")
    print("Comparator accepted the selected theorem under the recorded profile.")


def write_result(evidence: str | Path, phase: str, code: int, status: str,
                 repo: str | Path, proof_started: bool) -> None:
    out = Path(evidence)
    out.mkdir(parents=True, exist_ok=True)
    receipt = {}
    receipt_path = out / "proof-run/receipt.json"
    if receipt_path.is_file():
        try:
            receipt = json.loads(receipt_path.read_text())
            if not isinstance(receipt, dict):
                receipt = {}
        except (OSError, ValueError):
            # A partial or malformed receipt cannot prevent the failure report.
            receipt = {}
    try:
        head = subprocess.run(["git", "-C", str(repo), "rev-parse", "HEAD"],
                              capture_output=True, text=True, timeout=5).stdout.strip()
    except (OSError, subprocess.TimeoutExpired):
        head = "UNAVAILABLE"
    report = {
        "schema": "ttrace.math-pilot.hosted-check/v1",
        "ended_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "ttrace_commit": head,
        "source_commit": SOURCE_COMMIT,
        "selected_theorems": ["OAI.BorsukNine.main_theorem"],
        "excluded_targets": ["OAI.BorsukNine.euclidean_nine_counterexample"],
        "phase": phase, "runner_exit_code": code,
        "comparator_semantic_status": status if code == 0 else "NOT_ESTABLISHED",
        "selected_proof_execution_status": receipt.get("execution_status", "INTERRUPTED_WITHOUT_RECEIPT" if proof_started else "NOT_RUN"),
        "receipt_proof_semantic_status": receipt.get("proof_semantic_status", "NOT_ESTABLISHED"),
        "profile": "selected-module-mathlib-only",
        "external_kernel": "NONE; Lean default kernel only",
        "toolchain": "leanprover/lean4:v4.34.1",
        "comparator_commit": COMPARATOR_COMMIT,
        "exporter_commit": EXPORTER_COMMIT,
        "toolchain_override": "Comparator/exporter upstream 4.34.0, explicitly built with 4.34.1",
        "limitations": [
            "Comparator acceptance is bounded to the selected challenge and theorem.",
            "Lean kernel, trusted challenge, pinned Mathlib cache, Landrun, syscall guard, OS and hardware remain assumptions.",
            "No independent external kernel was run.",
            "This run does not establish paper alignment, scientific novelty, or the separate nine-dimensional corollary.",
            "Source snapshots before and after execution cannot detect a transient source change restored before the final snapshot.",
        ],
    }
    _write_json(out / "result.json", report)
    print(json.dumps({"phase": phase, "exit_code": code, "comparator_semantic_status": report["comparator_semantic_status"]}))


def seal_evidence(evidence: str | Path) -> None:
    out = Path(evidence)
    # An interrupted earlier seal must not become a self-referential entry
    # that vanishes when this seal replaces its own temporary file.
    (out / "artifact-sha256.json.tmp").unlink(missing_ok=True)
    files = []
    for path in sorted(out.rglob("*")):
        if path.is_file() and path.name != "artifact-sha256.json":
            raw = path.read_bytes()
            files.append({"path": str(path.relative_to(out)), "sha256": hashlib.sha256(raw).hexdigest(), "size_bytes": len(raw)})
    _write_json(out / "artifact-sha256.json", files)


def _signal_group(pid: int, signum: int) -> None:
    try:
        os.killpg(pid, signum)
    except ProcessLookupError:
        pass


def _failure(stage: str, error: BaseException) -> dict[str, str]:
    return {"stage": stage, "type": type(error).__name__, "message": str(error)}


def _stop_process(process: subprocess.Popen, grace: float) -> list[dict[str, str]]:
    errors = []
    # Every action gets its own guard: a failed TERM/wait cannot skip KILL or
    # failure evidence. Even repeated interruption leaves a conservative report.
    try:
        _signal_group(process.pid, signal.SIGTERM)
    except BaseException as error:
        errors.append(_failure("cleanup-term", error))
    try:
        process.wait(timeout=grace)
    except subprocess.TimeoutExpired:
        pass  # Expected escalation when the child ignores TERM.
    except BaseException as error:
        errors.append(_failure("cleanup-grace-wait", error))
    try:
        # Terminate remaining members even if the leader exited promptly.
        _signal_group(process.pid, signal.SIGKILL)
    except BaseException as error:
        errors.append(_failure("cleanup-kill", error))
    try:
        process.wait(timeout=5)
    except BaseException as error:
        # Record an unresolved reap rather than losing the failure report or
        # waiting indefinitely for an uninterruptible task.
        errors.append(_failure("cleanup-reap", error))
    return errors


def supervise_run(command: list[str], evidence: str | Path, repo: str | Path, *,
                  timeout: float = RUN_BUDGET_SECONDS, grace: float = CLEANUP_GRACE_SECONDS) -> int:
    require(math.isfinite(timeout) and 0 < timeout <= RUN_BUDGET_SECONDS,
            f"Whole-run timeout must be finite, positive and at most {RUN_BUDGET_SECONDS}s")
    require(math.isfinite(grace) and 0 < grace <= CLEANUP_GRACE_SECONDS,
            f"Cleanup grace must be finite, positive and at most {CLEANUP_GRACE_SECONDS}s")
    started = time.monotonic()
    child_env = dict(os.environ, MATH_PILOT_SUPERVISOR_PID=str(os.getpid()))
    process = subprocess.Popen(command, start_new_session=True, env=child_env)
    timed_out = False
    supervision_error = None
    cleanup_errors = []
    try:
        code = process.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        cleanup_errors = _stop_process(process, grace)
        code = 124
    except (KeyboardInterrupt, SystemExit) as error:
        cleanup_errors = _stop_process(process, grace)
        code = 130 if isinstance(error, KeyboardInterrupt) else error.code
        if not isinstance(code, int) or code == 0:
            code = 1
    except BaseException as error:
        supervision_error = _failure("supervised-wait", error)
        cleanup_errors = _stop_process(process, grace)
        code = 1
    else:
        # The runner owns this process group; no log writer may outlive sealing.
        try:
            _signal_group(process.pid, signal.SIGKILL)
        except BaseException as error:
            cleanup_errors = [_failure("completed-group-kill", error)]
            cleanup_errors.extend(_stop_process(process, grace))
            if code == 0:
                code = 1
    if code < 0:
        code = 128 - code
    out = Path(evidence)
    out.mkdir(parents=True, exist_ok=True)
    result_path = out / "result.json"
    result = None
    if result_path.is_file():
        try:
            result = json.loads(result_path.read_text())
            if not (isinstance(result, dict)
                    and result.get("schema") == "ttrace.math-pilot.hosted-check/v1"
                    and isinstance(result.get("phase"), str)
                    and type(result.get("runner_exit_code")) is int
                    and isinstance(result.get("comparator_semantic_status"), str)
                    and isinstance(result.get("selected_proof_execution_status"), str)):
                result = None
        except (OSError, ValueError):
            pass
    if result is None:
        if code == 0:
            code = 1  # A lost/malformed final report cannot pass the CI gate.
        phase_path = out / "phase.txt"
        phase = phase_path.read_text().strip() if phase_path.is_file() else "before-preflight"
        write_result(out, phase, code, "NOT_ESTABLISHED", repo,
                     phase in ("selected-theorem-comparator", "postrun-source-and-receipt-check", "complete"))
    elif (code != 0 or result["runner_exit_code"] != 0
          or result["phase"] != "complete"
          or result["comparator_semantic_status"] != "COMPARATOR_ACCEPTED_SELECTED_THEOREM"
          or result["selected_proof_execution_status"] != "EXIT_ZERO"
          or result.get("receipt_proof_semantic_status") != "UNASSESSED"):
        if code == 0:
            code = result["runner_exit_code"] or 1
        # Deadline/interruption wins over a coincident success in finalization.
        result["runner_exit_code"] = code
        result["comparator_semantic_status"] = "NOT_ESTABLISHED"
        _write_json(result_path, result)
    supervision = {
        "whole_run_timeout_seconds": timeout, "cleanup_grace_seconds": grace,
        "whole_run_timed_out": timed_out, "runner_exit_code": code,
        "duration_seconds": time.monotonic() - started,
    }
    if supervision_error is not None:
        supervision["supervision_error"] = supervision_error
    if cleanup_errors:
        supervision["cleanup_errors"] = cleanup_errors
    _write_json(out / "supervision.json", supervision)
    seal_evidence(out)
    return code


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="action", required=True)
    exporter = commands.add_parser("exporter")
    exporter.add_argument("manifest")
    exporter.add_argument("revision")
    sparse = commands.add_parser("sparse-patterns")
    sparse.add_argument("inventory")
    sparse.add_argument("destination")
    control = commands.add_parser("control")
    control.add_argument("case")
    control.add_argument("code", type=int)
    control.add_argument("log")
    acceptance = commands.add_parser("acceptance")
    acceptance.add_argument("run")
    report = commands.add_parser("report")
    report.add_argument("evidence")
    report.add_argument("phase")
    report.add_argument("code", type=int)
    report.add_argument("status")
    report.add_argument("repo")
    report.add_argument("proof_started", type=int, choices=(0, 1))
    seal = commands.add_parser("seal")
    seal.add_argument("evidence")
    supervise = commands.add_parser("supervise")
    supervise.add_argument("--evidence", required=True)
    supervise.add_argument("--repo", required=True)
    supervise.add_argument("--timeout", type=float, default=RUN_BUDGET_SECONDS)
    supervise.add_argument("--grace", type=float, default=CLEANUP_GRACE_SECONDS)
    supervise.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    try:
        if args.action == "exporter":
            check_exporter(args.manifest, args.revision)
        elif args.action == "sparse-patterns":
            write_sparse_patterns(args.inventory, args.destination)
        elif args.action == "control":
            check_control(args.case, args.code, args.log)
        elif args.action == "acceptance":
            check_acceptance(args.run)
        elif args.action == "report":
            write_result(args.evidence, args.phase, args.code, args.status, args.repo, args.proof_started)
        elif args.action == "seal":
            seal_evidence(args.evidence)
        elif args.action == "supervise":
            command = args.command[1:] if args.command[:1] == ["--"] else args.command
            require(bool(command), "A supervised command is required")
            previous = signal.getsignal(signal.SIGTERM)
            def interrupted(signum, frame):
                raise SystemExit(128 + signum)
            signal.signal(signal.SIGTERM, interrupted)
            try:
                return supervise_run(command, args.evidence, args.repo, timeout=args.timeout, grace=args.grace)
            finally:
                signal.signal(signal.SIGTERM, previous)
    except (RunnerCheckError, OSError, ValueError, KeyError, TypeError) as error:
        parser.exit(1, f"Math pilot runner check failed: {error}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
