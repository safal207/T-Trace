"""Synthetic runner observations test verdict gates and bounded failure evidence."""

import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time

import pytest

from scripts import math_pilot_runner
from scripts.math_pilot_runner import RunnerCheckError, seal_evidence, supervise_run, write_result


REPO = Path(__file__).resolve().parents[1]
HELPER = REPO / "scripts/math_pilot_runner.py"
SHELL = REPO / "scripts/run_math_pilot_156.sh"
MARKERS = ["Building ComparatorChallenges.BorsukNine", "Building OAI.Geometry.Borsuk.Main",
           "Lean default kernel accepts the solution", "Your solution is okay!"]


def optimized(*arguments):
    return subprocess.run([sys.executable, str(HELPER), *map(str, arguments)],
                          env=dict(os.environ, PYTHONOPTIMIZE="1"), capture_output=True,
                          text=True, timeout=10)


def proof_fixture(tmp_path, *, receipt_changes=None, missing_marker=None):
    receipt = {"execution_status": "EXIT_ZERO", "exit_code": 0,
               "inputs_after": "MATCHED_POSTRUN_SNAPSHOT", "proof_semantic_status": "UNASSESSED"}
    receipt.update(receipt_changes or {})
    (tmp_path / "receipt.json").write_text(json.dumps(receipt))
    (tmp_path / "stdout.log").write_text("\n".join(marker for marker in MARKERS if marker != missing_marker))
    return tmp_path


def test_valid_acceptance_still_passes_optimized(tmp_path):
    result = optimized("acceptance", proof_fixture(tmp_path))
    assert result.returncode == 0, result.stderr
    assert "Comparator accepted the selected theorem" in result.stdout


@pytest.mark.parametrize("receipt_changes", [
    {"execution_status": "TIMEOUT"}, {"exit_code": 1},
    {"inputs_after": "CHANGED"}, {"proof_semantic_status": "COMPARATOR_ACCEPTED"},
])
def test_optimized_acceptance_rejects_inconsistent_receipt(tmp_path, receipt_changes):
    result = optimized("acceptance", proof_fixture(tmp_path, receipt_changes=receipt_changes))
    assert result.returncode != 0
    assert "Comparator accepted the selected theorem" not in result.stdout


@pytest.mark.parametrize("marker", MARKERS)
def test_optimized_acceptance_requires_every_observed_marker(tmp_path, marker):
    result = optimized("acceptance", proof_fixture(tmp_path, missing_marker=marker))
    assert result.returncode != 0
    assert "output is missing" in result.stderr


@pytest.mark.parametrize("case,code,text", [
    ("simple_match", 0, "Lean default kernel accepts the solution\nYour solution is okay!"),
    ("simple_mismatch", 1, "Challenge and solution do not match"),
    ("simple_axiom_issue", 1, "Illegal axiom detected: 'helper'"),
])
def test_optimized_controls_require_both_verdict_and_exit(tmp_path, case, code, text):
    log = tmp_path / "control.log"
    log.write_text(text)
    assert optimized("control", case, code, log).returncode == 0
    assert optimized("control", case, 1 - code, log).returncode != 0
    log.write_text("unrelated compiler failure")
    assert optimized("control", case, code, log).returncode != 0


@pytest.mark.parametrize("packages", [
    [{"name": "lean4export", "rev": "wrong-revision"}],
    [{"name": "different-package", "rev": "expected-revision"}],
    [{"name": "lean4export", "rev": "expected-revision"}, {"name": "extra", "rev": "extra"}],
])
def test_optimized_exporter_gate_rejects_changed_manifest(tmp_path, packages):
    manifest = tmp_path / "lake-manifest.json"
    manifest.write_text(json.dumps({"packages": packages}))
    assert optimized("exporter", manifest, "expected-revision").returncode != 0


def test_optimized_exporter_gate_accepts_its_exact_pin(tmp_path):
    manifest = tmp_path / "lake-manifest.json"
    manifest.write_text(json.dumps({"packages": [{"name": "lean4export", "rev": "expected-revision"}]}))
    assert optimized("exporter", manifest, "expected-revision").returncode == 0


@pytest.mark.parametrize("path", ["/absolute", "../escape", "glob*", "line\nbreak"])
def test_optimized_source_patterns_reject_nonliteral_or_uncontained_paths(tmp_path, path):
    inventory, patterns = tmp_path / "inventory.json", tmp_path / "patterns.txt"
    inventory.write_text(json.dumps({"files": [{"path": path}]}))
    assert optimized("sparse-patterns", inventory, patterns).returncode != 0
    assert not patterns.exists()


@pytest.mark.parametrize("denied_read_errno,denied_write_errno,expected", [
    (13, 13, 0), (1, 1, 0), (22, 13, 1), (13, 22, 1),
])
def test_optimized_runtime_denial_gate_requires_permission_errors(tmp_path, denied_read_errno, denied_write_errno, expected):
    # Execute the actual sandbox-control gate with synthetic denied IO. This
    # checks classification, rather than claiming real Landlock behavior.
    chunks = SHELL.read_text().split("<<'PY'\n")
    control = next(chunk.split("\nPY", 1)[0] for chunk in chunks if "Landrun readable control" in chunk)
    allowed = tmp_path / "allowed"
    allowed.mkdir()
    (allowed / "read-only.txt").write_text("readable\n")
    program = f"""
import pathlib, sys
original_read = pathlib.Path.read_text
def denied_read(path, *args, **kwargs):
    if path == pathlib.Path({str(allowed / 'read-only.txt')!r}):
        return original_read(path, *args, **kwargs)
    raise OSError({denied_read_errno}, 'synthetic read denial')
def denied_write(path, *args, **kwargs):
    raise OSError({denied_write_errno}, 'synthetic write denial')
pathlib.Path.read_text = denied_read
pathlib.Path.write_text = denied_write
sys.argv = ['synthetic-control', {str(tmp_path)!r}]
exec({control!r})
"""
    result = subprocess.run([sys.executable, "-O", "-c", program], capture_output=True,
                            text=True, timeout=5)
    assert result.returncode == expected, result.stderr


def live(pid):
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    stat = Path(f"/proc/{pid}/stat")
    return stat.exists() and stat.read_text().split(")", 1)[1].strip().split()[0] != "Z"


def assert_sealed(evidence):
    files = json.loads((evidence / "artifact-sha256.json").read_text())
    by_path = {entry["path"]: entry for entry in files}
    for path in ("result.json", "supervision.json"):
        assert by_path[path]["sha256"] == hashlib.sha256((evidence / path).read_bytes()).hexdigest()
    for entry in files:
        raw = (evidence / entry["path"]).read_bytes()
        assert entry["size_bytes"] == len(raw)
        assert entry["sha256"] == hashlib.sha256(raw).hexdigest()


def test_whole_run_deadline_preserves_actual_shell_finish_and_tee_log(tmp_path):
    # Keep the production preamble/EXIT trap/log setup, then substitute one
    # hanging preparation command. No production test-mode bypass is added.
    prefix = SHELL.read_text().split('python3 - "$MATH_EVIDENCE/runtime-preflight.json"', 1)[0]
    prefix = prefix.replace('MATH_REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"',
                            f'MATH_REPO_ROOT="{REPO}"')
    script = tmp_path / "hang-preparation.sh"
    script.write_text(prefix + '''
set_phase trusted-mathlib-dependencies
printf '%s\\n' 'synthetic preparation started'
sleep 30 &
MATH_FIXTURE_CHILD="$!"
printf '%s\\n' "$MATH_FIXTURE_CHILD" > "$MATH_EVIDENCE/preparation-child.pid"
wait "$MATH_FIXTURE_CHILD"
''')
    run = tmp_path / "run"
    evidence = run / "evidence"
    started = time.monotonic()
    result = optimized("supervise", "--timeout", 0.3, "--grace", 1,
                       "--evidence", evidence, "--repo", REPO, "--", "bash", script, run)
    assert result.returncode == 124, result.stderr
    assert time.monotonic() - started < 3
    report = json.loads((evidence / "result.json").read_text())
    assert report["phase"] == "trusted-mathlib-dependencies"
    assert report["selected_proof_execution_status"] == "NOT_RUN"
    assert report["runner_exit_code"] == 124
    assert report["comparator_semantic_status"] == "NOT_ESTABLISHED"
    assert "synthetic preparation started" in (evidence / "runner.log").read_text()
    assert not live(int((evidence / "preparation-child.pid").read_text()))
    assert json.loads((evidence / "supervision.json").read_text())["whole_run_timed_out"] is True
    assert_sealed(evidence)


@pytest.mark.parametrize("partial_result", ["{", "[]", "{}"])
def test_deadline_hard_kill_recovers_partial_or_malformed_final_report(tmp_path, partial_result):
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    program = "\n".join([
        "import os, pathlib, signal, time",
        "signal.signal(signal.SIGTERM, signal.SIG_IGN)",
        f"root = pathlib.Path({str(evidence)!r})",
        "(root / 'phase.txt').write_text('trusted-mathlib-dependencies\\n')",
        f"(root / 'result.json').write_text({partial_result!r})",
        "(root / 'preparation-child.pid').write_text(str(os.getpid()))",
        "time.sleep(30)",
    ])
    result = optimized("supervise", "--timeout", 0.2, "--grace", 0.1,
                       "--evidence", evidence, "--repo", REPO, "--", sys.executable, "-c", program)
    assert result.returncode == 124, result.stderr
    report = json.loads((evidence / "result.json").read_text())
    assert report["phase"] == "trusted-mathlib-dependencies"
    assert report["comparator_semantic_status"] == "NOT_ESTABLISHED"
    assert not live(int((evidence / "preparation-child.pid").read_text()))
    assert_sealed(evidence)


def test_deadline_wins_over_success_report_written_during_cleanup(tmp_path):
    evidence = tmp_path / "evidence"
    write_result(evidence, "complete", 0, "COMPARATOR_ACCEPTED_SELECTED_THEOREM", REPO, True)
    result = optimized("supervise", "--timeout", 0.1, "--grace", 0.1,
                       "--evidence", evidence, "--repo", REPO, "--", "sleep", "30")
    assert result.returncode == 124
    report = json.loads((evidence / "result.json").read_text())
    assert report["runner_exit_code"] == 124
    assert report["comparator_semantic_status"] == "NOT_ESTABLISHED"
    assert_sealed(evidence)


def test_missing_success_report_cannot_pass(tmp_path):
    result = optimized("supervise", "--evidence", tmp_path, "--repo", REPO, "--", "true")
    assert result.returncode != 0
    assert json.loads((tmp_path / "result.json").read_text())["comparator_semantic_status"] == "NOT_ESTABLISHED"
    assert_sealed(tmp_path)


def test_unestablished_success_report_cannot_pass(tmp_path):
    write_result(tmp_path, "source-preparation", 0, "NOT_ESTABLISHED", REPO, False)
    result = optimized("supervise", "--evidence", tmp_path, "--repo", REPO, "--", "true")
    assert result.returncode != 0
    report = json.loads((tmp_path / "result.json").read_text())
    assert report["runner_exit_code"] != 0
    assert report["comparator_semantic_status"] == "NOT_ESTABLISHED"
    assert_sealed(tmp_path)


@pytest.mark.parametrize("phase,expected", [("complete", 0), ("preflight", 1)])
def test_success_requires_completed_phase_and_recorded_receipt(tmp_path, phase, expected):
    proof = tmp_path / "proof-run"
    proof.mkdir()
    proof_fixture(proof)
    write_result(tmp_path, phase, 0, "COMPARATOR_ACCEPTED_SELECTED_THEOREM", REPO, True)
    result = optimized("supervise", "--evidence", tmp_path, "--repo", REPO, "--", "true")
    assert result.returncode == expected
    report = json.loads((tmp_path / "result.json").read_text())
    assert report["comparator_semantic_status"] == ("COMPARATOR_ACCEPTED_SELECTED_THEOREM" if expected == 0 else "NOT_ESTABLISHED")
    assert_sealed(tmp_path)


def test_reseal_discards_its_own_stale_temporary_file(tmp_path):
    (tmp_path / "runner.log").write_text("retained log\n")
    (tmp_path / "artifact-sha256.json.tmp").write_text("partial interrupted seal")
    seal_evidence(tmp_path)
    entries = json.loads((tmp_path / "artifact-sha256.json").read_text())
    assert [entry["path"] for entry in entries] == ["runner.log"]
    assert not (tmp_path / "artifact-sha256.json.tmp").exists()
    assert entries[0]["sha256"] == hashlib.sha256((tmp_path / "runner.log").read_bytes()).hexdigest()


def test_sigterm_supervisor_stops_owned_child_and_retains_evidence(tmp_path):
    evidence = tmp_path / "evidence"
    program = "\n".join([
        "import os, pathlib, time",
        f"root = pathlib.Path({str(evidence)!r})",
        "root.mkdir()",
        "(root / 'phase.txt').write_text('source-preparation\\n')",
        "(root / 'preparation-child.pid').write_text(str(os.getpid()))",
        "time.sleep(30)",
    ])
    process = subprocess.Popen([
        sys.executable, str(HELPER), "supervise", "--grace", "1",
        "--evidence", str(evidence), "--repo", str(REPO), "--",
        sys.executable, "-c", program,
    ], env=dict(os.environ, PYTHONOPTIMIZE="1"), stdout=subprocess.PIPE,
       stderr=subprocess.PIPE, text=True, start_new_session=True)
    try:
        deadline = time.monotonic() + 3
        pid_file = evidence / "preparation-child.pid"
        while not pid_file.exists() and time.monotonic() < deadline:
            time.sleep(0.01)
        assert pid_file.exists()
        child = int(pid_file.read_text())
        process.send_signal(signal.SIGTERM)
        _, stderr = process.communicate(timeout=3)
        assert process.returncode == 143, stderr
        assert not live(child)
        report = json.loads((evidence / "result.json").read_text())
        assert report["runner_exit_code"] == 143
        assert report["phase"] == "source-preparation"
        assert report["comparator_semantic_status"] == "NOT_ESTABLISHED"
        assert_sealed(evidence)
    finally:
        if process.poll() is None:
            process.send_signal(signal.SIGTERM)
            process.wait(timeout=3)


def sleeping_preparation_command(evidence):
    return [sys.executable, "-c", "\n".join([
        "import os, pathlib, signal, time",
        "signal.signal(signal.SIGTERM, signal.SIG_IGN)",
        f"root = pathlib.Path({str(evidence)!r})",
        "root.mkdir()",
        "(root / 'phase.txt').write_text('source-preparation\\n')",
        "(root / 'runner.log').write_text('retained synthetic preparation log\\n')",
        "(root / 'preparation-child.pid').write_text(str(os.getpid()))",
        "time.sleep(30)",
    ])]


def fail_first_fixture_wait(monkeypatch, command, evidence):
    original_wait = subprocess.Popen.wait
    first = True

    def wait(process, *args, **kwargs):
        nonlocal first
        if first and process.args == command:
            first = False
            deadline = time.monotonic() + 3
            while not (evidence / "preparation-child.pid").exists() and time.monotonic() < deadline:
                time.sleep(0.01)
            raise OSError("injected unexpected wait failure")
        return original_wait(process, *args, **kwargs)

    monkeypatch.setattr(subprocess.Popen, "wait", wait)


def test_unexpected_wait_failure_still_kills_child_and_finalizes_evidence(tmp_path, monkeypatch):
    evidence = tmp_path / "evidence"
    command = sleeping_preparation_command(evidence)
    fail_first_fixture_wait(monkeypatch, command, evidence)
    started = time.monotonic()
    code = supervise_run(command, evidence, REPO, timeout=1, grace=0.1)
    assert code != 0
    assert time.monotonic() - started < 3
    assert not live(int((evidence / "preparation-child.pid").read_text()))
    report = json.loads((evidence / "result.json").read_text())
    assert report["phase"] == "source-preparation"
    assert report["runner_exit_code"] == code
    assert report["comparator_semantic_status"] == "NOT_ESTABLISHED"
    supervision = json.loads((evidence / "supervision.json").read_text())
    assert supervision["runner_exit_code"] == code
    assert supervision["supervision_error"]["type"] == "OSError"
    assert "unexpected wait failure" in supervision["supervision_error"]["message"]
    assert "retained synthetic preparation log" in (evidence / "runner.log").read_text()
    assert_sealed(evidence)


def test_term_cleanup_failure_does_not_skip_kill_or_reporting(tmp_path, monkeypatch):
    evidence = tmp_path / "evidence"
    command = sleeping_preparation_command(evidence)
    fail_first_fixture_wait(monkeypatch, command, evidence)
    original_signal = math_pilot_runner._signal_group
    observed_signals = []

    def group_signal(pid, signum):
        observed_signals.append(signum)
        if signum == signal.SIGTERM:
            raise OSError("injected TERM cleanup failure")
        original_signal(pid, signum)

    monkeypatch.setattr(math_pilot_runner, "_signal_group", group_signal)
    code = supervise_run(command, evidence, REPO, timeout=1, grace=0.1)
    assert code != 0
    assert observed_signals == [signal.SIGTERM, signal.SIGKILL]
    assert not live(int((evidence / "preparation-child.pid").read_text()))
    supervision = json.loads((evidence / "supervision.json").read_text())
    assert supervision["cleanup_errors"][0]["stage"] == "cleanup-term"
    assert "TERM cleanup failure" in supervision["cleanup_errors"][0]["message"]
    assert json.loads((evidence / "result.json").read_text())["runner_exit_code"] == code
    assert_sealed(evidence)


def test_cleanup_wait_failure_does_not_skip_kill_and_reap(tmp_path, monkeypatch):
    evidence = tmp_path / "evidence"
    command = sleeping_preparation_command(evidence)
    original_wait = subprocess.Popen.wait
    waits = []
    process_holder = []

    def wait(process, *args, **kwargs):
        if process.args == command:
            process_holder[:] = [process]
            waits.append(kwargs.get("timeout"))
            if len(waits) == 1:
                deadline = time.monotonic() + 3
                while not (evidence / "preparation-child.pid").exists() and time.monotonic() < deadline:
                    time.sleep(0.01)
                raise OSError("injected initial wait failure")
            if len(waits) == 2:
                raise RuntimeError("injected cleanup wait failure")
        return original_wait(process, *args, **kwargs)

    monkeypatch.setattr(subprocess.Popen, "wait", wait)
    code = supervise_run(command, evidence, REPO, timeout=1, grace=0.1)
    assert code != 0
    assert waits == [1, 0.1, 5]
    assert process_holder[0].returncode == -signal.SIGKILL
    assert not live(int((evidence / "preparation-child.pid").read_text()))
    supervision = json.loads((evidence / "supervision.json").read_text())
    assert supervision["cleanup_errors"][0]["stage"] == "cleanup-grace-wait"
    assert "cleanup wait failure" in supervision["cleanup_errors"][0]["message"]
    assert json.loads((evidence / "result.json").read_text())["comparator_semantic_status"] == "NOT_ESTABLISHED"
    assert_sealed(evidence)


def test_normal_exit_cleanup_error_downgrades_success_report(tmp_path, monkeypatch):
    proof = tmp_path / "proof-run"
    proof.mkdir()
    proof_fixture(proof)
    write_result(tmp_path, "complete", 0, "COMPARATOR_ACCEPTED_SELECTED_THEOREM", REPO, True)
    original_signal = math_pilot_runner._signal_group
    first = True

    def group_signal(pid, signum):
        nonlocal first
        if first:
            first = False
            raise OSError("injected completed-group cleanup failure")
        original_signal(pid, signum)

    monkeypatch.setattr(math_pilot_runner, "_signal_group", group_signal)
    code = supervise_run(["true"], tmp_path, REPO, timeout=1, grace=0.1)
    assert code != 0
    report = json.loads((tmp_path / "result.json").read_text())
    assert report["runner_exit_code"] == code
    assert report["comparator_semantic_status"] == "NOT_ESTABLISHED"
    supervision = json.loads((tmp_path / "supervision.json").read_text())
    assert supervision["cleanup_errors"][0]["stage"] == "completed-group-kill"
    assert_sealed(tmp_path)


@pytest.mark.parametrize("interrupted", [False, True])
def test_cleanup_error_preserves_timeout_or_interruption_status(tmp_path, monkeypatch, interrupted):
    evidence = tmp_path / "evidence"
    command = sleeping_preparation_command(evidence)
    original_wait = subprocess.Popen.wait
    original_signal = math_pilot_runner._signal_group
    first = True

    def wait(process, *args, **kwargs):
        nonlocal first
        if interrupted and first and process.args == command:
            first = False
            deadline = time.monotonic() + 3
            while not (evidence / "preparation-child.pid").exists() and time.monotonic() < deadline:
                time.sleep(0.01)
            raise SystemExit(143)
        return original_wait(process, *args, **kwargs)

    def group_signal(pid, signum):
        if signum == signal.SIGTERM:
            raise OSError("injected TERM cleanup failure")
        original_signal(pid, signum)

    monkeypatch.setattr(subprocess.Popen, "wait", wait)
    monkeypatch.setattr(math_pilot_runner, "_signal_group", group_signal)
    expected = 143 if interrupted else 124
    code = supervise_run(command, evidence, REPO, timeout=0.2, grace=0.1)
    assert code == expected
    assert not live(int((evidence / "preparation-child.pid").read_text()))
    supervision = json.loads((evidence / "supervision.json").read_text())
    assert supervision["runner_exit_code"] == expected
    assert supervision["whole_run_timed_out"] is (not interrupted)
    assert supervision["cleanup_errors"][0]["stage"] == "cleanup-term"
    report = json.loads((evidence / "result.json").read_text())
    assert report["runner_exit_code"] == expected
    assert report["comparator_semantic_status"] == "NOT_ESTABLISHED"
    assert_sealed(evidence)


@pytest.mark.parametrize("timeout", [float("nan"), float("inf"), 0, -1, 3301])
def test_invalid_deadline_never_starts_command(tmp_path, timeout):
    marker = tmp_path / "started"
    with pytest.raises(RunnerCheckError, match="Whole-run timeout"):
        supervise_run(["touch", str(marker)], tmp_path / "evidence", REPO, timeout=timeout)
    assert not marker.exists()
