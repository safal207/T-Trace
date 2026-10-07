"""Synthetic subprocess fixtures test receipt integrity, not Lean or Comparator."""

import json
import os
from pathlib import Path
import signal
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

from openpoc import math_pilot as pilot


class ReceiptIntegrityTests(unittest.TestCase):
    COMMIT = "a" * 40
    REPOSITORY = "https://example.invalid/synthetic-math-fixture"
    THEOREMS = ["Synthetic.unassessed_theorem"]
    RUN_ID = "fresh-test-nonce-0001"

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.bundle = self.root / "bundle"
        self.bundle.mkdir()
        (self.bundle / "source.lean").write_text("-- Synthetic source, not a proof\n")
        (self.bundle / "dependency.lock").write_text("synthetic-dependency-version=1\n")
        pilot.write_json(self.bundle / "config.json", {"theorem_names": self.THEOREMS})
        (self.bundle / "synthetic_checker.py").write_text(
            "import sys, time\n"
            "from pathlib import Path\n"
            "mode = sys.argv[2] if len(sys.argv) > 2 else 'zero'\n"
            "if mode == 'sleep': time.sleep(10)\n"
            "if mode == 'mutate': Path('source.lean').write_text('changed')\n"
            "if mode == 'mutate-restore':\n"
            "    original = Path('source.lean').read_bytes()\n"
            "    Path('source.lean').write_text('transient changed content')\n"
            "    Path('source.lean').write_bytes(original)\n"
            "print('SYNTHETIC subprocess only; no mathematical claim checked')\n"
            "print('synthetic diagnostic', file=sys.stderr)\n"
            "sys.exit(3 if mode == 'fail' else 0)\n"
        )
        self.manifest = pilot.create_manifest(
            self.bundle, self.REPOSITORY, self.COMMIT, self.THEOREMS,
            "config.json", ["source.lean"], ["dependency.lock"])
        self.manifest_path = self.root / "manifest.json"
        pilot.write_json(self.manifest_path, self.manifest)
        self.out = self.root / "run"

    def record(self, mode="zero", timeout=10):
        return pilot.run_record(
            self.bundle, self.manifest_path, self.out,
            [sys.executable, "synthetic_checker.py", "config.json", mode],
            self.RUN_ID, timeout)

    def verify(self, **overrides):
        kwargs = dict(expected_repository=self.REPOSITORY, expected_commit=self.COMMIT,
                      expected_theorems=self.THEOREMS, expected_config="config.json",
                      expected_run_id=self.RUN_ID,
                      expected_manifest_sha256=pilot.digest(pilot.canonical_bytes(self.manifest)))
        kwargs.update(overrides)
        return pilot.verify_receipt(self.bundle, self.manifest_path,
                                    self.out / "receipt.json", **kwargs)

    def mutate_receipt(self, change):
        path = self.out / "receipt.json"
        value = json.loads(path.read_text())
        change(value)
        pilot.write_json(path, value)

    def test_preflight_never_claims_execution_or_proof(self):
        result = pilot.preflight_manifest(self.bundle, self.manifest)
        self.assertEqual(result["execution_status"], "NOT_RUN")
        self.assertEqual(result["proof_semantic_status"], "NOT_ESTABLISHED")

    def test_actual_synthetic_process_exit_zero_is_semantically_unassessed(self):
        receipt = self.record()
        self.assertEqual(receipt["execution_status"], "EXIT_ZERO")
        self.assertEqual(receipt["proof_semantic_status"], "UNASSESSED")
        result = self.verify()
        self.assertEqual(result["receipt_integrity"], "VALID")
        self.assertEqual(result["authenticity"], "NOT_ASSESSED")
        self.assertIn("SYNTHETIC", (self.out / "stdout.log").read_text())

    def test_nonzero_execution_stays_failed_even_with_intact_receipt(self):
        self.record("fail")
        result = self.verify()
        self.assertEqual(result["execution_status"], "EXIT_NONZERO")
        self.assertEqual(result["proof_semantic_status"], "NOT_ESTABLISHED")

    def test_timeout_is_recorded_as_actual_failed_execution(self):
        self.record("sleep", timeout=0.1)
        self.assertEqual(self.verify()["execution_status"], "TIMEOUT")

    def _mock_owned_process(self, waits, returncode=None):
        process = mock.Mock(spec=subprocess.Popen)
        process.pid = 123456789
        process.returncode = returncode
        process.wait.side_effect = waits
        return process

    def test_unreaped_cleanup_timeout_does_not_seal_receipt(self):
        execution_timeout = subprocess.TimeoutExpired("synthetic-checker", 0.01)
        cleanup_timeout = subprocess.TimeoutExpired("synthetic-checker", pilot.CLEANUP_TIMEOUT_SECONDS)
        for first_wait in (execution_timeout, 0):
            with self.subTest(first_wait=first_wait):
                self.out = self.root / ("timed-out" if isinstance(first_wait, Exception) else "normal-exit")
                process = self._mock_owned_process([first_wait, cleanup_timeout])
                with mock.patch.object(pilot.subprocess, "Popen", return_value=process), \
                        mock.patch.object(pilot.os, "killpg"), \
                        mock.patch.object(pilot, "preflight_manifest", wraps=pilot.preflight_manifest) as preflight:
                    with self.assertRaisesRegex(pilot.PilotError, "could not be reaped"):
                        self.record(timeout=0.01)
                self.assertEqual(process.wait.call_args_list,
                    [mock.call(timeout=0.01), mock.call(timeout=pilot.CLEANUP_TIMEOUT_SECONDS)])
                self.assertIsNone(process.returncode)
                self.assertEqual(preflight.call_count, 1)
                self.assertFalse((self.out / "receipt.json").exists())

    def test_cleanup_timeout_preserves_original_interruption_or_postspawn_error(self):
        for original in (KeyboardInterrupt(), SystemExit(143), OSError("synthetic wait error")):
            with self.subTest(original=type(original).__name__):
                self.out = self.root / type(original).__name__
                process = self._mock_owned_process([original,
                    subprocess.TimeoutExpired("synthetic-checker", pilot.CLEANUP_TIMEOUT_SECONDS)])
                with mock.patch.object(pilot.subprocess, "Popen", return_value=process), \
                        mock.patch.object(pilot.os, "killpg"):
                    with self.assertRaises(type(original)) as raised:
                        self.record(timeout=0.01)
                self.assertIs(raised.exception, original)
                self.assertEqual(process.wait.call_args_list,
                    [mock.call(timeout=0.01), mock.call(timeout=pilot.CLEANUP_TIMEOUT_SECONDS)])
                self.assertFalse((self.out / "receipt.json").exists())

    def test_stop_error_still_attempts_bounded_reap_and_cannot_seal_success(self):
        original = OSError("synthetic group kill failure")
        process = self._mock_owned_process([0, 0], returncode=0)
        with mock.patch.object(pilot.subprocess, "Popen", return_value=process), \
                mock.patch.object(pilot.os, "killpg", side_effect=original):
            with self.assertRaises(OSError) as raised:
                self.record(timeout=0.01)
        self.assertIs(raised.exception, original)
        self.assertEqual(process.wait.call_args_list,
            [mock.call(timeout=0.01), mock.call(timeout=pilot.CLEANUP_TIMEOUT_SECONDS)])
        self.assertFalse((self.out / "receipt.json").exists())

    def test_cleanup_wait_return_without_reaped_exit_code_cannot_seal_success(self):
        for code in (None, True):
            with self.subTest(code=code):
                self.out = self.root / str(code)
                process = self._mock_owned_process([0, 0], returncode=code)
                with mock.patch.object(pilot.subprocess, "Popen", return_value=process), \
                        mock.patch.object(pilot.os, "killpg"):
                    with self.assertRaisesRegex(pilot.PilotError, "did not establish a reaped exit code"):
                        self.record(timeout=0.01)
                self.assertFalse((self.out / "receipt.json").exists())

    def test_zero_exit_during_cleanup_keeps_timed_out_verdict_and_actual_code(self):
        process = self._mock_owned_process([
            subprocess.TimeoutExpired("synthetic-checker", 0.01), 0], returncode=0)
        with mock.patch.object(pilot.subprocess, "Popen", return_value=process), \
                mock.patch.object(pilot.os, "killpg", side_effect=ProcessLookupError):
            receipt = self.record(timeout=0.01)
        self.assertEqual(receipt["exit_code"], 0)
        self.assertEqual(receipt["execution_status"], "TIMEOUT")
        result = self.verify()
        self.assertEqual(result["execution_status"], "TIMEOUT")
        self.assertEqual(result["proof_semantic_status"], "NOT_ESTABLISHED")

    def test_timeout_receipt_requires_actual_integer_exit_code(self):
        self.record("sleep", timeout=0.1)
        for code in (None, True):
            with self.subTest(code=code):
                self.mutate_receipt(lambda receipt: receipt.update(exit_code=code))
                with self.assertRaisesRegex(pilot.PilotError, "execution status disagrees with exit code"):
                    self.verify()

    def test_nonfinite_or_nonpositive_timeout_rejected_before_any_execution(self):
        for timeout in (float("nan"), float("inf"), float("-inf"), 0, -1):
            with self.subTest(timeout=timeout), mock.patch.object(pilot.subprocess, "Popen") as spawn:
                with self.assertRaisesRegex(pilot.PilotError, "finite and positive"):
                    self.record(timeout=timeout)
                spawn.assert_not_called()
                self.assertFalse(self.out.exists())

    def _process_group_fixture(self):
        (self.bundle / "process_group_checker.py").write_text(
            "import json, os, subprocess, sys, time\n"
            "from pathlib import Path\n"
            "child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'])\n"
            "Path('processes.json').write_text(json.dumps([os.getpid(), child.pid]))\n"
            "if len(sys.argv) > 2 and sys.argv[2] == 'exit': sys.exit(0)\n"
            "time.sleep(60)\n"
        )
        return [sys.executable, "process_group_checker.py", "config.json"]

    def _wait_for_process_group(self):
        deadline = time.monotonic() + 5
        path = self.bundle / "processes.json"
        while time.monotonic() < deadline:
            if path.exists():
                try:
                    return json.loads(path.read_text())
                except json.JSONDecodeError:
                    pass
            time.sleep(0.01)
        self.fail("process group fixture did not become ready")

    def _assert_process_group_stopped(self, pids):
        def running(pid):
            try:
                os.kill(pid, 0)
            except ProcessLookupError:
                return False
            # An orphan descendant may remain a zombie until init reaps it;
            # it cannot keep writing logs or running the checker.
            status = Path(f"/proc/{pid}/stat")
            try:
                return status.read_text().split(") ", 1)[1].split()[0] != "Z"
            except FileNotFoundError:
                return False

        deadline = time.monotonic() + 5
        while time.monotonic() < deadline and any(running(pid) for pid in pids):
            time.sleep(0.01)
        self.assertFalse(any(running(pid) for pid in pids), "owned checker group survived cleanup")

    @unittest.skipUnless(os.name == "posix" and Path("/proc").is_dir(), "POSIX process groups with procfs")
    def test_normal_exit_also_stops_remaining_descendants_before_sealing_logs(self):
        command = [*self._process_group_fixture(), "exit"]
        receipt = pilot.run_record(self.bundle, self.manifest_path, self.out, command, self.RUN_ID)
        pids = self._wait_for_process_group()
        try:
            self.assertEqual(receipt["execution_status"], "EXIT_ZERO")
            self.assertEqual(self.verify()["proof_semantic_status"], "UNASSESSED")
            self._assert_process_group_stopped(pids)
        finally:
            try:
                os.killpg(pids[0], signal.SIGKILL)
            except ProcessLookupError:
                pass

    @unittest.skipUnless(os.name == "posix" and Path("/proc").is_dir(), "POSIX process groups with procfs")
    def test_interruption_and_postspawn_errors_stop_group_and_preserve_error(self):
        command = self._process_group_fixture()
        real_spawn = subprocess.Popen
        for exception in (KeyboardInterrupt(), OSError("synthetic wait failure"), RuntimeError("unexpected wait failure")):
            with self.subTest(exception=type(exception).__name__):
                self.out = self.root / type(exception).__name__
                (self.bundle / "processes.json").unlink(missing_ok=True)
                processes = []
                pids = []

                def spawn(*args, **kwargs):
                    process = real_spawn(*args, **kwargs)
                    processes.append(process)
                    real_wait = process.wait
                    interrupted = False

                    def wait(timeout=None):
                        nonlocal interrupted
                        if not interrupted:
                            interrupted = True
                            pids.extend(self._wait_for_process_group())
                            raise exception
                        return real_wait(timeout=timeout)

                    process.wait = wait
                    return process

                try:
                    with mock.patch.object(pilot.subprocess, "Popen", side_effect=spawn):
                        with self.assertRaises(type(exception)) as raised:
                            pilot.run_record(self.bundle, self.manifest_path, self.out, command, self.RUN_ID)
                    self.assertIs(raised.exception, exception)
                    self.assertIsNotNone(processes[0].returncode)
                    self._assert_process_group_stopped(pids)
                    self.assertFalse((self.out / "receipt.json").exists())
                finally:
                    for process in processes:
                        try:
                            os.killpg(process.pid, signal.SIGKILL)
                        except ProcessLookupError:
                            pass
                        process.wait(timeout=pilot.CLEANUP_TIMEOUT_SECONDS)

    @unittest.skipUnless(os.name == "posix" and Path("/proc").is_dir(), "POSIX process groups with procfs")
    def test_record_cli_signals_clean_checker_group(self):
        command = self._process_group_fixture()
        for interruption in (signal.SIGINT, signal.SIGTERM):
            with self.subTest(signal=interruption):
                self.out = self.root / str(interruption)
                (self.bundle / "processes.json").unlink(missing_ok=True)
                cli = subprocess.Popen([sys.executable, "-m", "openpoc.math_pilot", "record",
                    "--bundle", str(self.bundle), "--manifest", str(self.manifest_path),
                    "--out", str(self.out), "--run-id", self.RUN_ID, "--", *command],
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
                pids = []
                try:
                    pids = self._wait_for_process_group()
                    cli.send_signal(interruption)
                    stdout, stderr = cli.communicate(timeout=5)
                    if interruption == signal.SIGTERM:
                        self.assertEqual(cli.returncode, 128 + interruption, (stdout, stderr))
                    else:
                        self.assertIn(cli.returncode, (-interruption, 128 + interruption), (stdout, stderr))
                    self._assert_process_group_stopped(pids)
                    self.assertFalse((self.out / "receipt.json").exists())
                finally:
                    if pids:
                        try:
                            os.killpg(pids[0], signal.SIGKILL)
                        except ProcessLookupError:
                            pass
                    if cli.poll() is None:
                        cli.kill()
                    cli.communicate(timeout=5)

    def test_record_cli_restores_sigterm_handler_after_error(self):
        previous_handler = signal.getsignal(signal.SIGTERM)
        with mock.patch.object(pilot, "run_record", side_effect=pilot.PilotError("synthetic error")):
            with mock.patch("builtins.print"):
                result = pilot.main(["record", "--bundle", str(self.bundle),
                    "--manifest", str(self.manifest_path), "--out", str(self.out),
                    "--run-id", self.RUN_ID, "--", sys.executable, "config.json"])
        self.assertEqual(result, 2)
        self.assertIs(signal.getsignal(signal.SIGTERM), previous_handler)

    def test_missing_executable_cannot_pass(self):
        receipt = pilot.run_record(self.bundle, self.manifest_path, self.out,
                                  ["nonexistent-synthetic-tool-91872", "config.json"], self.RUN_ID)
        self.assertEqual(receipt["execution_status"], "SPAWN_FAILED")
        self.assertEqual(self.verify()["proof_semantic_status"], "NOT_ESTABLISHED")

    def test_changed_solution_rejected(self):
        self.record()
        (self.bundle / "source.lean").write_text("-- Changed solution\n")
        with self.assertRaisesRegex(pilot.PilotError, "input changed"):
            self.verify()

    def test_missing_proof_source_rejected(self):
        self.record()
        (self.bundle / "source.lean").unlink()
        with self.assertRaisesRegex(pilot.PilotError, "missing regular file"):
            self.verify()

    def test_changed_dependency_rejected(self):
        self.record()
        (self.bundle / "dependency.lock").write_text("changed-version=2\n")
        with self.assertRaisesRegex(pilot.PilotError, "input changed"):
            self.verify()

    def test_changed_manifest_bytes_rejected_even_if_json_equivalent(self):
        self.record()
        with self.manifest_path.open("a") as stream:
            stream.write("\n")
        with self.assertRaisesRegex(pilot.PilotError, "manifest file bytes"):
            self.verify()

    def test_manifest_rehash_cannot_reuse_old_receipt(self):
        self.record()
        (self.bundle / "source.lean").write_text("new source\n")
        replacement = pilot.create_manifest(self.bundle, self.REPOSITORY, self.COMMIT,
            self.THEOREMS, "config.json", ["source.lean"], ["dependency.lock"])
        pilot.write_json(self.manifest_path, replacement)
        with self.assertRaisesRegex(pilot.PilotError, "pinned manifest digest"):
            self.verify()

    def test_replacing_both_manifest_and_receipt_rejected_by_independent_digest(self):
        self.record()
        (self.bundle / "source.lean").write_text("attacker replacement\n")
        replacement = pilot.create_manifest(self.bundle, self.REPOSITORY, self.COMMIT,
            self.THEOREMS, "config.json", ["source.lean"], ["dependency.lock"])
        pilot.write_json(self.manifest_path, replacement)
        self.mutate_receipt(lambda value: value.update(
            manifest=replacement,
            manifest_sha256=pilot.digest(pilot.canonical_bytes(replacement)),
            manifest_file_sha256=pilot.digest(self.manifest_path.read_bytes())))
        with self.assertRaisesRegex(pilot.PilotError, "pinned manifest digest"):
            self.verify()

    def test_wrong_expected_commit_rejected(self):
        self.record()
        with self.assertRaisesRegex(pilot.PilotError, "expected subject"):
            self.verify(expected_commit="b" * 40)

    def test_wrong_expected_theorem_rejected(self):
        self.record()
        with self.assertRaisesRegex(pilot.PilotError, "expected subject"):
            self.verify(expected_theorems=["Synthetic.weaker_theorem"])

    def test_wrong_expected_config_rejected(self):
        self.record()
        with self.assertRaisesRegex(pilot.PilotError, "expected subject"):
            self.verify(expected_config="different.json")

    def test_old_receipt_rejected_by_fresh_nonce(self):
        self.record()
        with self.assertRaisesRegex(pilot.PilotError, "different or stale run"):
            self.verify(expected_run_id="fresh-test-nonce-0002")

    def test_old_receipt_rejected_by_timestamp_bound(self):
        self.record()
        with self.assertRaisesRegex(pilot.PilotError, "freshness"):
            self.verify(not_before="2999-01-01T00:00:00+00:00")

    def test_missing_execution_log_rejected(self):
        self.record()
        (self.out / "stdout.log").unlink()
        with self.assertRaisesRegex(pilot.PilotError, "missing regular file"):
            self.verify()

    def test_changed_execution_log_rejected(self):
        self.record()
        (self.out / "stderr.log").write_text("fake success")
        with self.assertRaisesRegex(pilot.PilotError, "artifact bytes differ"):
            self.verify()

    def test_missing_artifact_entry_rejected(self):
        self.record()
        self.mutate_receipt(lambda value: value["artifacts"].pop())
        with self.assertRaisesRegex(pilot.PilotError, "missing required execution artifacts"):
            self.verify()

    def test_semantic_pass_overclaim_rejected(self):
        self.record()
        self.mutate_receipt(lambda value: value.update(proof_semantic_status="PASS"))
        with self.assertRaisesRegex(pilot.PilotError, "overstates proof semantics"):
            self.verify()

    def test_not_run_receipt_cannot_be_success(self):
        self.record()
        self.mutate_receipt(lambda value: value.update(execution_status="NOT_RUN"))
        with self.assertRaisesRegex(pilot.PilotError, "actual execution status"):
            self.verify()

    def test_observed_postrun_input_mismatch_rejected(self):
        receipt = self.record("mutate")
        self.assertEqual(receipt["inputs_after"], "POSTRUN_MISMATCH")
        (self.bundle / "source.lean").write_text("-- Synthetic source, not a proof\n")
        with self.assertRaisesRegex(pilot.PilotError, "postrun input snapshot mismatch"):
            self.verify()

    def test_transient_mutation_restored_before_snapshot_is_outside_coverage(self):
        receipt = self.record("mutate-restore")
        self.assertEqual(receipt["inputs_after"], "MATCHED_POSTRUN_SNAPSHOT")
        result = self.verify()
        self.assertEqual(result["receipt_integrity"], "VALID")
        self.assertEqual(result["proof_semantic_status"], "UNASSESSED")
        # This is an explicit limitation demonstration, not a security success:
        # read-only execution isolation is separate from snapshot comparison.

    def test_command_with_wrong_config_blocked_before_execution(self):
        with self.assertRaisesRegex(pilot.PilotError, "selected config"):
            pilot.run_record(self.bundle, self.manifest_path, self.out,
                [sys.executable, "synthetic_checker.py", "wrong.json"], self.RUN_ID)
        self.assertFalse(self.out.exists())

    def test_recorded_command_config_substitution_rejected(self):
        self.record()
        self.mutate_receipt(lambda value: value.update(command=[sys.executable, "wrong.json"]))
        with self.assertRaisesRegex(pilot.PilotError, "selected config"):
            self.verify()

    def test_recorded_cwd_substitution_rejected(self):
        self.record()
        self.mutate_receipt(lambda value: value.update(cwd=str(self.root / "other-bundle")))
        with self.assertRaisesRegex(pilot.PilotError, "cwd differs from independently expected cwd"):
            self.verify()

    def test_malformed_or_noncanonical_recorded_cwd_rejected(self):
        self.record()
        for cwd in (None, [], {}, 123, "", "relative/bundle", "/a/../bundle",
                    "/a/./bundle", "/a//bundle", "/bundle/", "//bundle", "/bundle\0"):
            with self.subTest(cwd=cwd):
                self.mutate_receipt(lambda value: value.update(cwd=cwd))
                with self.assertRaisesRegex(pilot.PilotError, "recorded cwd: expected a canonical absolute path"):
                    self.verify()

    def test_explicit_expected_cwd_is_validated_and_independently_matched(self):
        self.record()
        for expected in ("relative/bundle", "/original/../bundle", ""):
            with self.subTest(expected=expected):
                with self.assertRaisesRegex(pilot.PilotError, "independently expected cwd: expected a canonical absolute path"):
                    self.verify(expected_cwd=expected)
        with self.assertRaisesRegex(pilot.PilotError, "cwd differs from independently expected cwd"):
            self.verify(expected_cwd=str(self.root / "different-original-bundle"))

    def _relocate_execution_archive(self):
        original_cwd = str(self.bundle.resolve())
        archive = self.root / "archive"
        archive.mkdir()
        shutil.copytree(self.bundle, archive / "bundle")
        shutil.copytree(self.out, archive / "run")
        shutil.copyfile(self.manifest_path, archive / "manifest.json")
        shutil.rmtree(self.bundle)
        self.bundle = archive / "bundle"
        self.out = archive / "run"
        self.manifest_path = archive / "manifest.json"
        self.assertFalse(Path(original_cwd).exists())
        return original_cwd

    def test_relocated_archive_relative_config_binds_trusted_original_cwd(self):
        self.record()
        original_cwd = self._relocate_execution_archive()
        with self.assertRaisesRegex(pilot.PilotError, "cwd differs from independently expected cwd"):
            self.verify()
        result = self.verify(expected_cwd=original_cwd)
        self.assertEqual(result["receipt_integrity"], "VALID")
        self.assertEqual(result["authenticity"], "NOT_ASSESSED")

    def test_relocated_archive_absolute_config_binds_trusted_original_cwd(self):
        pilot.run_record(self.bundle, self.manifest_path, self.out,
            [sys.executable, "synthetic_checker.py", str(self.bundle / "config.json")], self.RUN_ID)
        original_cwd = self._relocate_execution_archive()
        result = self.verify(expected_cwd=original_cwd)
        self.assertEqual(result["receipt_integrity"], "VALID")
        self.assertEqual(result["authenticity"], "NOT_ASSESSED")
        self.mutate_receipt(lambda value: value["command"].__setitem__(2, str(self.bundle / "config.json")))
        with self.assertRaisesRegex(pilot.PilotError, "selected config"):
            self.verify(expected_cwd=original_cwd)

    def test_executable_identity_path_substitution_rejected(self):
        self.record()
        self.mutate_receipt(lambda value: value["tool_identity"].update(
            executable_path="/different-runtime/synthetic-checker"))
        with self.assertRaisesRegex(pilot.PilotError, "identity differs from recorded command"):
            self.verify()

    def test_recorded_executable_substitution_rejected(self):
        self.record()
        self.mutate_receipt(lambda value: value["command"].__setitem__(0, "/different-runtime/synthetic-checker"))
        with self.assertRaisesRegex(pilot.PilotError, "identity differs from recorded command"):
            self.verify()

    def test_archived_tool_identity_does_not_require_local_executable(self):
        self.record()
        archived = str(self.root / "unavailable-archived-runtime" / "synthetic-checker")

        def archive(value):
            value["command"][0] = archived
            value["tool_identity"]["executable_path"] = archived

        self.mutate_receipt(archive)
        self.assertFalse(Path(archived).exists())
        result = self.verify()
        self.assertEqual(result["receipt_integrity"], "VALID")
        self.assertEqual(result["authenticity"], "NOT_ASSESSED")

    def test_output_directory_cannot_reuse_stale_artifacts(self):
        self.record()
        with self.assertRaisesRegex(pilot.PilotError, "already exists"):
            self.record()

    def test_relative_path_resolves_and_records_actual_bundle_executable(self):
        parent_checker = self.root / "fixture-checker"
        bundle_checker = self.bundle / "fixture-checker"
        parent_checker.write_text("#!/bin/sh\necho parent-binary\n")
        bundle_checker.write_text("#!/bin/sh\necho bundle-binary\n")
        parent_checker.chmod(0o755)
        bundle_checker.chmod(0o755)
        parent_cwd = Path.cwd()
        try:
            os.chdir(self.root)
            with mock.patch.dict(os.environ, {"PATH": "."}):
                receipt = pilot.run_record(self.bundle, self.manifest_path, self.out,
                    ["fixture-checker", "config.json"], self.RUN_ID)
        finally:
            os.chdir(parent_cwd)
        self.assertEqual(receipt["command"][0], str(bundle_checker.resolve()))
        self.assertEqual(receipt["tool_identity"]["executable_path"], str(bundle_checker.resolve()))
        self.assertEqual(receipt["tool_identity"]["executable_sha256"], pilot.digest(bundle_checker.read_bytes()))
        self.assertNotEqual(receipt["tool_identity"]["executable_sha256"], pilot.digest(parent_checker.read_bytes()))
        self.assertEqual((self.out / "stdout.log").read_text().strip(), "bundle-binary")
        self.assertEqual(self.verify()["receipt_integrity"], "VALID")

    def test_executable_symlink_invocation_name_is_preserved(self):
        original = self.bundle / "launcher"
        alias = self.bundle / "launcher-alias"
        original.write_text('#!/bin/sh\necho "$0"\n')
        original.chmod(0o755)
        alias.symlink_to("launcher")
        receipt = pilot.run_record(self.bundle, self.manifest_path, self.out,
                                   ["./launcher-alias", "config.json"], self.RUN_ID)
        self.assertEqual(receipt["command"][0], str(alias.absolute()))
        self.assertEqual(receipt["tool_identity"]["executable_sha256"], pilot.digest(original.read_bytes()))
        self.assertEqual((self.out / "stdout.log").read_text().strip(), str(alias.absolute()))
        self.assertEqual(self.verify()["receipt_integrity"], "VALID")

    def test_manifest_unknown_field_rejected(self):
        value = dict(self.manifest, unexpected=True)
        with self.assertRaisesRegex(pilot.PilotError, "unexpected fields"):
            pilot.preflight_manifest(self.bundle, value)

    def test_receipt_unknown_field_rejected(self):
        self.record()
        self.mutate_receipt(lambda value: value.update(unexpected=True))
        with self.assertRaisesRegex(pilot.PilotError, "unexpected fields"):
            self.verify()

    def test_traversal_and_absolute_paths_rejected(self):
        for path in ("../source.lean", "/source.lean", "a/../source.lean", "./source.lean", "a//b"):
            with self.subTest(path=path), self.assertRaises(pilot.PilotError):
                pilot.safe_file(self.bundle, path)

    def test_duplicate_input_paths_rejected(self):
        with self.assertRaisesRegex(pilot.PilotError, "duplicate declared path"):
            pilot.create_manifest(self.bundle, self.REPOSITORY, self.COMMIT, self.THEOREMS,
                "config.json", ["source.lean", "source.lean"], ["dependency.lock"])

    def test_symlink_source_or_log_rejected(self):
        self.record()
        source = self.bundle / "source.lean"
        source.rename(self.bundle / "original.lean")
        source.symlink_to("original.lean")
        with self.assertRaisesRegex(pilot.PilotError, "symlink forbidden"):
            self.verify()

    def test_duplicate_json_key_rejected(self):
        self.manifest_path.write_text('{"schema":"x","schema":"y"}')
        with self.assertRaisesRegex(pilot.PilotError, "duplicate JSON key"):
            pilot._read_json(self.manifest_path)

    def test_wrong_config_theorem_cannot_be_rehashed_as_original_subject(self):
        pilot.write_json(self.bundle / "config.json", {"theorem_names": ["Synthetic.weaker"]})
        with self.assertRaisesRegex(pilot.PilotError, "config theorem_names"):
            pilot.create_manifest(self.bundle, self.REPOSITORY, self.COMMIT, self.THEOREMS,
                "config.json", ["source.lean"], ["dependency.lock"])

    def test_git_commit_and_blobs_checked_independently(self):
        def git(*args):
            return subprocess.run(["git", "-C", str(self.bundle), *args], capture_output=True,
                                  check=True).stdout.decode().strip()
        git("init", "-q")
        git("add", "source.lean", "config.json", "dependency.lock")
        git("-c", "user.name=Synthetic", "-c", "user.email=synthetic@example.invalid",
            "commit", "-qm", "Synthetic fixture")
        commit = git("rev-parse", "HEAD")
        manifest = pilot.create_manifest(self.bundle, self.REPOSITORY, commit, self.THEOREMS,
                "config.json", ["source.lean"], ["dependency.lock"], check_git=True)
        self.assertEqual(pilot.preflight_manifest(self.bundle, manifest)["input_integrity"], "VALID")
        (self.bundle / "source.lean").write_text("different current source\n")
        with self.assertRaisesRegex(pilot.PilotError, "not the Git blob"):
            pilot.create_manifest(self.bundle, self.REPOSITORY, commit, self.THEOREMS,
                "config.json", ["source.lean"], ["dependency.lock"], check_git=True)

    def test_git_replace_cannot_rebind_source_at_pinned_commit(self):
        def git(*args):
            return subprocess.run(["git", "-C", str(self.bundle), *args], capture_output=True,
                                  check=True).stdout.decode().strip()
        def commit(message):
            git("add", "source.lean", "config.json", "dependency.lock")
            git("-c", "user.name=Synthetic", "-c", "user.email=synthetic@example.invalid",
                "commit", "-qm", message)
            return git("rev-parse", "HEAD")
        git("init", "-q")
        original = commit("Original synthetic fixture")
        changed_bytes = "replacement source at old commit name\n"
        (self.bundle / "source.lean").write_text(changed_bytes)
        replacement = commit("Replacement synthetic fixture")
        git("replace", original, replacement)
        git("reset", "--hard", original)
        self.assertEqual(git("rev-parse", "HEAD"), original)
        self.assertEqual((self.bundle / "source.lean").read_text(), changed_bytes)
        with self.assertRaisesRegex(pilot.PilotError, "replacement refs are forbidden"):
            pilot.create_manifest(self.bundle, self.REPOSITORY, original, self.THEOREMS,
                "config.json", ["source.lean"], ["dependency.lock"], check_git=True)


if __name__ == "__main__":
    unittest.main()
