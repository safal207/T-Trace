"""Instrumentation rejection is a collection gate, not a speed assertion."""

import os
import platform
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from scripts import benchmark_artifact_handoff as driver

ROOT = Path(__file__).resolve().parents[1]
REPORTED = ("PYTHONTRACEMALLOC", "PYTHONMALLOC", "PYTHONPROFILEIMPORTTIME", "NODE_V8_COVERAGE")
RELATED = ("PYTHONDEVMODE", "PYTHONMALLOCSTATS", "PYTHONPERFSUPPORT", "PYTHON_PERF_JIT_SUPPORT",
           "PYTHONDEBUG", "PYTHONVERBOSE", "NODE_DEBUG", "NODE_DEBUG_NATIVE")


@pytest.fixture
def clean_environment(monkeypatch):
    # Test setup only. The production driver must reject, never silently clear.
    for name in list(os.environ):
        if name.upper() in REPORTED + RELATED:
            monkeypatch.delenv(name)


def forbid_collection(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("instrumented collection reached discovery, input generation or a child")
    monkeypatch.setattr(driver.shutil, "which", forbidden)
    monkeypatch.setattr(driver, "source_inventory", forbidden)
    monkeypatch.setattr(driver, "generated_input", forbidden)
    monkeypatch.setattr(driver, "run_json", forbidden)
    monkeypatch.setattr(driver.subprocess, "run", forbidden)


@pytest.mark.parametrize("mode", ["smoke", "baseline"])
@pytest.mark.parametrize("name", REPORTED + RELATED)
@pytest.mark.parametrize("value", ["", "0", "private-test-value"])
def test_instrumentation_rejected_before_work(tmp_path, monkeypatch, clean_environment, mode, name, value):
    forbid_collection(monkeypatch)
    monkeypatch.setenv(name, value)
    before = dict(os.environ)
    output = tmp_path / "never-created"
    with pytest.raises(ValueError, match="benchmark instrumentation") as error:
        driver.run_benchmark(output, "unused-node", mode=mode)
    assert name in str(error.value)
    assert "private-test-value" not in str(error.value)
    assert not output.exists()
    assert dict(os.environ) == before


@pytest.mark.parametrize("name", REPORTED + RELATED)
def test_instrumentation_names_are_case_insensitive(tmp_path, monkeypatch, clean_environment, name):
    forbid_collection(monkeypatch)
    monkeypatch.setenv(name.swapcase(), "private-test-value")
    with pytest.raises(ValueError, match=name):
        driver.run_benchmark(tmp_path / "never-created", "unused-node", mode="smoke")
    assert not (tmp_path / "never-created").exists()


def test_combined_diagnostic_is_sorted_name_only_and_preserves_existing_results(tmp_path, monkeypatch, clean_environment):
    forbid_collection(monkeypatch)
    for name in reversed(REPORTED):
        monkeypatch.setenv(name, "private-test-value")
    marker = tmp_path / "report.json"
    marker.write_bytes(b"preserve this evidence")
    with pytest.raises(ValueError) as error:
        driver.run_benchmark(tmp_path, "unused-node")
    assert str(error.value).endswith(", ".join(sorted(REPORTED)))
    assert "private-test-value" not in str(error.value)
    assert marker.read_bytes() == b"preserve this evidence"
    assert list(tmp_path.iterdir()) == [marker]


def test_clean_snapshot_preserves_platform_variables_without_mutating_parent(monkeypatch, clean_environment):
    for name in ("PYTHONPATH", "PYTHONHOME", "NODE_PATH", "NODE_OPTIONS", "pythonhashseed"):
        monkeypatch.setenv(name, "parent-only")
    monkeypatch.setenv("PYTHONHASHSEED", "17")
    for name in ("PATH", "SystemRoot", "TEMP", "TMP"):
        monkeypatch.setenv(name, "platform-value-" + name)
    before = dict(os.environ)
    env = driver.benchmark_environment()
    assert env is not os.environ
    assert not set(name.upper() for name in env) & set(REPORTED + RELATED)
    assert not set(name.upper() for name in env) & {"PYTHONPATH", "PYTHONHOME", "NODE_PATH", "NODE_OPTIONS"}
    assert [name for name in env if name.upper() == "PYTHONHASHSEED"] == ["PYTHONHASHSEED"]
    assert env["PYTHONHASHSEED"] == "0"
    normalized_env = {name.upper(): value for name, value in env.items()}
    normalized_before = {name.upper(): value for name, value in before.items()}
    for name in ("PATH", "SYSTEMROOT", "TEMP", "TMP"):
        assert normalized_env[name] == normalized_before[name]
    assert dict(os.environ) == before


@pytest.mark.parametrize("hook", ["gettrace", "getprofile"])
def test_active_parent_hooks_are_not_silently_disabled(tmp_path, monkeypatch, clean_environment, hook):
    forbid_collection(monkeypatch)
    marker = object()
    monkeypatch.setattr(driver.sys, hook, lambda: marker)
    with pytest.raises(ValueError, match="parent instrumentation"):
        driver.run_benchmark(tmp_path / "never-created", "unused-node")
    assert getattr(driver.sys, hook)() is marker
    assert not (tmp_path / "never-created").exists()


@pytest.mark.parametrize("flag", ["dev_mode", "debug", "verbose"])
def test_parent_runtime_flags_are_rejected(tmp_path, monkeypatch, clean_environment, flag):
    forbid_collection(monkeypatch)
    flags = SimpleNamespace(dev_mode=0, debug=0, verbose=0)
    setattr(flags, flag, 1)
    proxy = SimpleNamespace(**vars(sys))
    proxy.flags = flags
    monkeypatch.setattr(driver, "sys", proxy)
    with pytest.raises(ValueError, match="sys.flags." + flag):
        driver.run_benchmark(tmp_path / "never-created", "unused-node")


@pytest.mark.parametrize("option", ["tracemalloc", "importtime", "perf", "perf_jit", "showrefcount", "pystats"])
def test_parent_xoptions_are_rejected(tmp_path, monkeypatch, clean_environment, option):
    forbid_collection(monkeypatch)
    monkeypatch.setattr(driver.sys, "_xoptions", {option: "0"})
    with pytest.raises(ValueError, match="-X " + option):
        driver.run_benchmark(tmp_path / "never-created", "unused-node")


@pytest.mark.parametrize("tool_id", range(6))
def test_registered_monitoring_tools_are_rejected(tmp_path, monkeypatch, clean_environment, tool_id):
    forbid_collection(monkeypatch)
    monitor = SimpleNamespace(get_tool=lambda candidate: "private-tool-name" if candidate == tool_id else None)
    monkeypatch.setattr(driver.sys, "monitoring", monitor, raising=False)
    with pytest.raises(ValueError, match="sys.monitoring") as error:
        driver.run_benchmark(tmp_path / "never-created", "unused-node")
    assert "private-tool-name" not in str(error.value)


@pytest.mark.parametrize("name,value", [
    ("PYTHONTRACEMALLOC", "1"), ("PYTHONMALLOC", "debug"),
    ("PYTHONPROFILEIMPORTTIME", "1"), ("NODE_V8_COVERAGE", "coverage"),
])
def test_actual_instrumented_python_launch_produces_no_measurement(tmp_path, clean_environment, name, value):
    env = driver.benchmark_environment()
    env[name] = str(tmp_path / "coverage") if name == "NODE_V8_COVERAGE" else value
    output = tmp_path / "never-created"
    result = subprocess.run([sys.executable, str(ROOT / "scripts/benchmark_artifact_handoff.py"),
                             "smoke", str(output)], cwd=ROOT, env=env,
                            capture_output=True, text=True, timeout=30)
    assert result.returncode != 0
    assert "benchmark instrumentation is not allowed" in result.stderr
    assert name in result.stderr
    assert not output.exists()
    assert not (tmp_path / "coverage").exists()


def test_startup_tracing_survives_environment_deletion_and_is_rejected(tmp_path, clean_environment):
    env = driver.benchmark_environment()
    env["PYTHONTRACEMALLOC"] = "1"
    output = tmp_path / "never-created"
    code = (
        "import os, sys, tracemalloc; from pathlib import Path; "
        "os.environ.pop('PYTHONTRACEMALLOC'); assert tracemalloc.is_tracing(); "
        "from scripts import benchmark_artifact_handoff as driver; "
        "driver.run_benchmark(Path(sys.argv[1]), 'unused-node', mode='smoke')"
    )
    result = subprocess.run([sys.executable, "-c", code, str(output)], cwd=ROOT, env=env,
                            capture_output=True, text=True, timeout=30)
    assert result.returncode != 0
    assert "parent instrumentation is active" in result.stderr
    assert "tracemalloc" in result.stderr
    assert not output.exists()


def test_run_json_passes_the_prepared_snapshot(monkeypatch, clean_environment):
    env = driver.benchmark_environment()
    def child(command, **kwargs):
        assert kwargs["env"] is env
        assert kwargs["cwd"] == ROOT
        return SimpleNamespace(returncode=0, stdout='{"checked":true}', stderr="")
    monkeypatch.setattr(driver.subprocess, "run", child)
    report, duration = driver.run_json(["test-only-command"], env)
    assert report == {"checked": True}
    assert type(duration) is int and duration > 0


def test_every_measurement_launch_and_node_version_share_one_snapshot(tmp_path, monkeypatch, clean_environment):
    """Synthetic child samples remain test-local, never baseline evidence."""
    from ttrace.artifact_handoff import verify_artifact_handoff
    from scripts.handoff_benchmark_support import MEMORY_METHODS

    env = driver.benchmark_environment()
    child_calls, metadata_calls, snapshot_calls = [], [], []
    dependencies = {"cryptography": "test-only", "cffi": "test-only", "pycparser": "test-only"}
    def snapshot():
        snapshot_calls.append(True)
        return env
    monkeypatch.setattr(driver, "benchmark_environment", snapshot)
    monkeypatch.setattr(driver.shutil, "which", lambda name: sys.executable)
    def metadata(command, **kwargs):
        if command[-1] == "--version":
            assert kwargs["env"] is env
            metadata_calls.append(command)
            return SimpleNamespace(stdout="test-only-node")
        return SimpleNamespace(stdout="0" * 40)
    monkeypatch.setattr(driver.subprocess, "run", metadata)
    def child(command, child_env):
        assert child_env is env
        assert "TTRACE_AFTER_SNAPSHOT" not in child_env
        child_calls.append(command)
        monkeypatch.setenv("TTRACE_AFTER_SNAPSHOT", "parent-later-change")
        package = next(Path(item) for item in command if Path(item).name == "package")
        size = int(package.parent.name)
        files, context = driver.generated_input(size)
        report = verify_artifact_handoff(files, context)
        names = {Path(item).name for item in command}
        if names & {"benchmark_handoff_worker.py", "benchmark-artifact-handoff.mjs"}:
            impl = "python" if "benchmark_handoff_worker.py" in names else "node"
            worker = {"schema": "ttrace.handoff-benchmark-worker/v1", "implementation": impl,
                      "runtime_version": platform.python_version() if impl == "python" else "test-only-node",
                      "reference_checks": 1, "warmups": 1, "sample_count": 3, "samples_ns": [1, 2, 3],
                      "summary_ns": driver.summarize([1, 2, 3]),
                      "input_sha256": driver.input_description(files, context)["input_sha256"],
                      "full_report_sha256": driver.checked_report(report),
                      "peak_memory": {"bytes": 1048576, "method": MEMORY_METHODS[platform.system()][impl]}}
            if impl == "python":
                worker["receipt_dependencies"] = dict(dependencies)
            return worker, 123
        return report, 123
    monkeypatch.setattr(driver, "run_json", child)
    report = driver.run_benchmark(tmp_path / "test-only-result", "node", mode="smoke")
    assert len(snapshot_calls) == 1
    assert len(child_calls) == 15  # 3 preliminary reports + 6 API workers + 6 fresh CLIs.
    assert len(metadata_calls) == 1
    assert report["review_guardrails"] == []
    assert sum(len(run["worker"]["samples_ns"]) for run in report["runs"]) == 18
    assert sum(run["fresh_cli_reports_checked"] for run in report["runs"]) == 6
