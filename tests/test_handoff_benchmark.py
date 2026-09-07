import copy
import hashlib
import json
from pathlib import Path

import pytest

from scripts.benchmark_artifact_handoff import (
    PARAMETERS, SCHEMA, SIZES, artifact_for_size, derive_guardrails, generated_input,
    input_description, make_summary, measured_receipt_dependencies, render_markdown, run_benchmark, source_inventory, validate_report,
)
from scripts.handoff_benchmark_support import MEMORY_METHODS, checked_report, digest, process_peak_memory, summarize
from ttrace.artifact_handoff import verify_artifact_handoff

ROOT = Path(__file__).resolve().parents[1]


def fake_report(mode="smoke"):
    """Synthetic measurement values exist only inside this unit test."""
    parameters = copy.deepcopy(PARAMETERS[mode])
    dependencies = {"cryptography": "46.0.4", "cffi": "2.1.1", "pycparser": "3.0"}
    inputs = {}
    for size in SIZES:
        files, context = generated_input(size)
        inputs[str(size)] = input_description(files, context)
        inputs[str(size)]["full_report_sha256"] = checked_report(verify_artifact_handoff(files, context))
    runs = []
    for round_number in range(parameters["rounds"]):
        for size in (SIZES if round_number % 2 == 0 else tuple(reversed(SIZES))):
            for implementation in (("python", "node") if round_number % 2 == 0 else ("node", "python")):
                api = list(range(1, parameters["samples"] + 1))
                cli = list(range(10, 10 + parameters["fresh_cli_samples"]))
                worker = {"schema": "ttrace.handoff-benchmark-worker/v1", "implementation": implementation,
                          "runtime_version": "unit-test-values-not-measurements", "reference_checks": 1,
                          "warmups": parameters["warmups"], "sample_count": parameters["samples"],
                          "input_sha256": inputs[str(size)]["input_sha256"], "full_report_sha256": inputs[str(size)]["full_report_sha256"],
                          "samples_ns": api, "summary_ns": summarize(api),
                          "peak_memory": {"bytes": 10 * 1048576, "method": MEMORY_METHODS["Windows"][implementation]}}
                if implementation == "python":
                    worker["receipt_dependencies"] = dict(dependencies)
                runs.append({"round": round_number, "input": str(size), "implementation": implementation, "worker": worker,
                             "fresh_cli_samples_ns": cli, "fresh_cli_summary_ns": summarize(cli),
                             "fresh_cli_reports_checked": len(cli)})
    sources = source_inventory()
    return {"schema": SCHEMA, "mode": mode, "parameters": parameters, "inputs": inputs,
            "source_files": sources, "source_files_sha256": digest(sources), "runs": runs,
            "environment": {"os": "Windows", "architecture": "unit-test", "python": "unit-test-values-not-measurements",
                            "receipt_dependencies": dependencies,
                            "node": "unit-test-values-not-measurements"},
            "summary": make_summary(runs, inputs), "review_guardrails": derive_guardrails(runs, inputs) if mode == "baseline" else []}


def test_nearest_rank_percentile_and_even_median():
    assert summarize(list(range(1, 21))) == {"count": 20, "min": 1, "median": 10.5, "p95": 19, "max": 20}
    assert summarize([9]) == {"count": 1, "min": 9, "median": 9, "p95": 9, "max": 9}


@pytest.mark.parametrize("values", [[], [0], [-1], [True], [1.0], [float("nan")]],
                         ids=["empty", "zero", "negative", "boolean", "float", "nonfinite"])
def test_invalid_timer_samples_cannot_be_summarized(values):
    with pytest.raises(ValueError):
        summarize(values)


@pytest.mark.parametrize("size", SIZES)
def test_fixed_inputs_reproduce_exact_sizes_and_real_signatures(size):
    files, context = generated_input(size)
    assert generated_input(size) == (files, context)
    assert len(files["artifact.bin"]) == size
    if size != 75:
        assert files["artifact.bin"][:256] == bytes(range(256))
    info = input_description(files, context)
    assert info["package_bytes"] == sum(len(value) for value in files.values())
    assert info["receiver_context_bytes"] == len(context)
    assert info["input_files"]["artifact.bin"]["sha256"] == hashlib.sha256(files["artifact.bin"]).hexdigest()
    assert checked_report(verify_artifact_handoff(files, context))


def test_smallest_input_retains_the_existing_matching_fixture_bytes():
    files, context = generated_input(75)
    root = ROOT / "examples/artifact-handoff-v0.1"
    assert files == {path.name: path.read_bytes() for path in (root / "packages/p001").iterdir()}
    assert context == (root / "contexts/matching.json").read_bytes()


@pytest.mark.parametrize("size", [True, 0, 74, 1048577, 75.0])
def test_generator_does_not_silently_change_fixed_sizes(size):
    with pytest.raises(ValueError):
        artifact_for_size(size)


def test_real_process_peak_is_positive_with_explicit_supported_units():
    import platform
    value = process_peak_memory()
    assert type(value["bytes"]) is int and value["bytes"] > 0
    assert value["method"] == MEMORY_METHODS[platform.system()]["python"]


@pytest.mark.parametrize("mode", ["smoke", "baseline"])
def test_report_statistics_and_mode_are_reproducible(mode):
    report = fake_report(mode)
    validate_report(report, check_sources=True)
    human = render_markdown(report)
    assert "not production SLAs" in human
    assert "not a cold OS filesystem cache" in human
    assert (len(report["review_guardrails"]) == 6) == (mode == "baseline")


@pytest.mark.parametrize("mutate", [
    lambda r: r.update(mode="baseline"),
    lambda r: r["parameters"].update(rounds=True),
    lambda r: r["runs"].pop(),
    lambda r: r["runs"].reverse(),
    lambda r: r["runs"].__setitem__(1, copy.deepcopy(r["runs"][0])),
    lambda r: r["runs"][0].update(round=False),
    lambda r: r["runs"][0]["worker"].update(full_report_sha256="0" * 64),
    lambda r: r["runs"][0]["worker"]["samples_ns"].append(1),
    lambda r: r["runs"][0]["worker"]["summary_ns"].update(p95=9999),
    lambda r: r["runs"][0]["worker"]["peak_memory"].update(bytes=0),
    lambda r: r["runs"][0]["worker"]["peak_memory"].update(method="heap-only allocation tracker"),
    lambda r: r["runs"][0].update(fresh_cli_reports_checked=False),
    lambda r: r["runs"][0]["worker"].update(runtime_version="different-runtime"),
    lambda r: r["inputs"]["75"].update(package_bytes=75),
    lambda r: r["summary"][0]["api_ns"].update(median=123),
    lambda r: r.update(source_files_sha256="0" * 64),
    lambda r: r["review_guardrails"].append({"fake": "budget"}),
    lambda r: r["environment"].update(os="unsupported"),
], ids=["smoke-not-baseline", "bool-parameter", "missing-run", "wrong-order", "duplicate-run", "bool-round", "wrong-outcome",
        "missing-cardinality", "wrong-percentile", "missing-memory", "wrong-memory-scope", "unchecked-cli",
        "different-runtime", "artifact-not-package", "fake-summary", "source-digest", "invented-budget", "unknown-memory-units"])
def test_invalid_measurement_records_fail_closed(mutate):
    report = fake_report()
    mutate(report)
    with pytest.raises(ValueError):
        validate_report(report)


def test_guardrails_come_from_worst_round_not_an_invented_constant():
    report = fake_report("baseline")
    expected = report["review_guardrails"][0]
    assert expected["api_p95_review_trigger_ms"] == 1
    assert expected["fresh_cli_p95_review_trigger_ms"] == 10
    assert expected["worker_peak_review_trigger_mib"] == 20
    assert expected["package_bytes_exact"] == report["inputs"]["75"]["package_bytes"]
    report["review_guardrails"][0]["worker_peak_review_trigger_mib"] = 21
    with pytest.raises(ValueError, match="guardrails"):
        validate_report(report)


def test_negative_verification_is_not_a_fast_success():
    files, context = generated_input(75)
    context_document = json.loads(context)
    context_document["key_status"] = None
    report = verify_artifact_handoff(files, json.dumps(context_document).encode())
    with pytest.raises(ValueError, match="benchmark input"):
        checked_report(report)


def test_existing_results_are_not_overwritten(tmp_path):
    marker = tmp_path / "keep.txt"
    marker.write_text("keep original result", encoding="utf-8")
    with pytest.raises(ValueError, match="destination must be new"):
        run_benchmark(tmp_path, "not-a-real-node-executable")
    assert marker.read_text(encoding="utf-8") == "keep original result"


def test_missing_node_does_not_silently_skip_or_create_a_result(tmp_path):
    output = tmp_path / "new-result"
    with pytest.raises(RuntimeError, match="Node is required"):
        run_benchmark(output, "not-a-real-ttrace-node-executable")
    assert not output.exists()


def test_committed_baseline_reproduces_sources_inputs_statistics_and_human_report():
    root = ROOT / "docs/benchmarks/artifact-handoff-v0.1/windows"
    report = json.loads((root / "report.json").read_bytes())
    assert report["mode"] == "baseline"
    validate_report(report, check_sources=True)
    assert len(report["runs"]) == 12
    assert sum(len(run["worker"]["samples_ns"]) for run in report["runs"]) == 360
    assert sum(len(run["fresh_cli_samples_ns"]) for run in report["runs"]) == 60
    assert render_markdown(report) == (root / "report.md").read_text(encoding="utf-8")


@pytest.mark.parametrize("change", [
    lambda r: r["runs"][0]["worker"].pop("receipt_dependencies"),
    lambda r: r["runs"][0]["worker"]["receipt_dependencies"].update(cffi="different-worker"),
    lambda r: r["runs"][0]["worker"]["receipt_dependencies"].update(cffi=True),
    lambda r: r["environment"]["receipt_dependencies"].update(cffi="parent-override"),
], ids=["missing-worker", "inconsistent-workers", "wrong-type", "parent-metadata-substitution"])
def test_measured_dependency_identity_must_agree_in_every_worker(change):
    report = fake_report()
    change(report)
    with pytest.raises(ValueError):
        validate_report(report)


def test_driver_uses_sanitized_worker_versions_not_parent_lookup(tmp_path, monkeypatch):
    """Mock timings only in this unit test; do not publish these as measurements."""
    import importlib.metadata
    import platform
    import sys
    from types import SimpleNamespace
    from scripts import benchmark_artifact_handoff as driver

    fixture = fake_report()
    runtime = platform.python_version()
    monkeypatch.setattr(importlib.metadata, "version", lambda name: "parent-override")
    monkeypatch.setattr(driver.shutil, "which", lambda name: sys.executable)
    monkeypatch.setattr(driver.subprocess, "run", lambda command, **kwargs: SimpleNamespace(
        stdout="unit-test-values-not-measurements" if command[-1] == "--version" else "0" * 40))

    def fake_child(command, env):
        assert not any(name.upper() in {"PYTHONPATH", "PYTHONHOME", "NODE_PATH", "NODE_OPTIONS"} for name in env)
        size = next(size for size in SIZES if any(str(tmp_path / "result/inputs" / str(size) / "package") == item for item in command))
        if any("benchmark_handoff_worker.py" in item or "benchmark-artifact-handoff.mjs" in item for item in command):
            implementation = "python" if any("benchmark_handoff_worker.py" in item for item in command) else "node"
            worker = copy.deepcopy(next(run["worker"] for run in fixture["runs"]
                                        if run["input"] == str(size) and run["implementation"] == implementation))
            if implementation == "python":
                worker["runtime_version"] = runtime
            worker["peak_memory"]["method"] = MEMORY_METHODS[platform.system()][implementation]
            return worker, 123
        files, context = generated_input(size)
        return verify_artifact_handoff(files, context), 123

    monkeypatch.setenv("PYTHONPATH", "unit-test-parent-only-override")
    monkeypatch.setattr(driver, "run_json", fake_child)
    report = driver.run_benchmark(tmp_path / "result", "node", mode="smoke")
    assert report["environment"]["receipt_dependencies"] == measured_receipt_dependencies(fixture["runs"])
    assert "parent-override" not in report["environment"]["receipt_dependencies"].values()
