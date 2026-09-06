"""Reproducible source-backed API/CLI baseline on public fixed-size artifacts."""

from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
import math
import os
import platform
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

try:
    from .handoff_benchmark_support import MEMORY_METHODS, canonical, checked_report, digest, summarize
except ImportError:
    from handoff_benchmark_support import MEMORY_METHODS, canonical, checked_report, digest, summarize

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
SIZES = (75, 65_536, 1_048_576)
SCHEMA = "ttrace.handoff-benchmark/v1"
PARAMETERS = {"baseline": {"rounds": 2, "warmups": 5, "samples": 30, "fresh_cli_samples": 5},
              "smoke": {"rounds": 1, "warmups": 1, "samples": 3, "fresh_cli_samples": 1}}


def artifact_for_size(size: int) -> bytes:
    from openpoc.artifact_handoff_demo import ARTIFACT
    if type(size) is not int or size not in SIZES:
        raise ValueError("only the three declared benchmark sizes are supported")
    return ARTIFACT if size == 75 else bytes(range(256)) * (size // 256)


def generated_input(size: int) -> tuple[dict, bytes]:
    from openpoc.artifact_handoff_demo import BASE_TIME, encoded, make_context, make_manifest, make_receipt
    artifact = artifact_for_size(size)
    files = {"artifact.bin": artifact,
             "sender.jsonl": make_receipt("sender", artifact, ts_ms=BASE_TIME + 100),
             "receiver.jsonl": make_receipt("receiver", artifact, ts_ms=BASE_TIME + 1000)}
    files["manifest.json"] = make_manifest(files)
    return files, encoded(make_context(files))


def input_description(files: dict, context: bytes) -> dict:
    inventory = {name: {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()} for name, raw in files.items()}
    inventory["receiver-context.json"] = {"bytes": len(context), "sha256": hashlib.sha256(context).hexdigest()}
    return {"artifact_bytes": len(files["artifact.bin"]), "package_bytes": sum(map(len, files.values())),
            "receiver_context_bytes": len(context), "input_files": inventory, "input_sha256": digest(inventory)}


def source_inventory() -> dict:
    paths = [path for folder in ("ttrace", "openpoc") for path in (ROOT / folder).rglob("*.py")]
    paths += [ROOT / "scripts" / name for name in
              ("benchmark_artifact_handoff.py", "benchmark_handoff_worker.py", "handoff_benchmark_support.py")]
    paths += [ROOT / "verifiers/node" / name for name in ("artifact-handoff.mjs", "benchmark-artifact-handoff.mjs")]
    return {path.relative_to(ROOT).as_posix(): {"bytes": path.stat().st_size,
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest()} for path in sorted(paths)}


def run_json(command: list[str], env: dict) -> tuple[dict, int]:
    start = time.perf_counter_ns()
    result = subprocess.run(command, cwd=ROOT, env=env, capture_output=True, text=True,
                            encoding="utf-8", timeout=60, check=False)
    elapsed = time.perf_counter_ns() - start
    if result.returncode:
        raise RuntimeError(f"benchmark child failed: {result.stdout}\n{result.stderr}")
    # Parsing and checking captured stdout are outside fresh-process timing.
    return json.loads(result.stdout), elapsed


def make_summary(runs: list[dict], inputs: dict) -> list[dict]:
    result = []
    for size in SIZES:
        name = str(size)
        for implementation in ("python", "node"):
            selected = [run for run in runs if run["input"] == name and run["implementation"] == implementation]
            api = [value for run in selected for value in run["worker"]["samples_ns"]]
            cli = [value for run in selected for value in run["fresh_cli_samples_ns"]]
            peak = max(run["worker"]["peak_memory"]["bytes"] for run in selected)
            result.append({"input": name, "implementation": implementation,
                           "api_ns": summarize(api), "fresh_cli_ns": summarize(cli),
                           "maximum_worker_peak_bytes": peak, "package_bytes": inputs[name]["package_bytes"],
                           "receiver_context_bytes": inputs[name]["receiver_context_bytes"]})
    return result


def derive_guardrails(runs: list[dict], inputs: dict) -> list[dict]:
    result = []
    for size in SIZES:
        for implementation in ("python", "node"):
            selected = [run for run in runs if run["input"] == str(size) and run["implementation"] == implementation]
            worst_api = max(run["worker"]["summary_ns"]["p95"] for run in selected)
            worst_cli = max(run["fresh_cli_summary_ns"]["p95"] for run in selected)
            peak = max(run["worker"]["peak_memory"]["bytes"] for run in selected)
            result.append({"input": str(size), "implementation": implementation,
                "api_p95_review_trigger_ms": math.ceil(4 * worst_api / 1_000_000),
                "fresh_cli_p95_review_trigger_ms": 10 * math.ceil(4 * worst_cli / 10_000_000),
                "worker_peak_review_trigger_mib": math.ceil(2 * peak / 1_048_576),
                "package_bytes_exact": inputs[str(size)]["package_bytes"],
                "receiver_context_bytes_exact": inputs[str(size)]["receiver_context_bytes"]})
    return result


def validate_report(report: dict, *, check_sources: bool = False) -> None:
    if report.get("schema") != SCHEMA or report.get("mode") not in PARAMETERS:
        raise ValueError("unknown benchmark report")
    parameters = PARAMETERS[report["mode"]]
    if (report.get("parameters") != parameters
            or any(type(value) is not int for value in report["parameters"].values())):
        raise ValueError("incorrect sample cardinality for report mode")
    if report.get("environment", {}).get("os") not in MEMORY_METHODS:
        raise ValueError("unsupported memory measurement platform")
    expected_inputs = {}
    from ttrace.artifact_handoff import verify_artifact_handoff
    for size in SIZES:
        files, context = generated_input(size)
        description = input_description(files, context)
        description["full_report_sha256"] = checked_report(verify_artifact_handoff(files, context))
        expected_inputs[str(size)] = description
    if report.get("inputs") != expected_inputs:
        raise ValueError("benchmark input bytes, sizes or full report identity differ")
    sources = report.get("source_files", {})
    if not sources or report.get("source_files_sha256") != digest(sources):
        raise ValueError("unbound benchmark source inventory")
    if check_sources and sources != source_inventory():
        raise ValueError("measured source files differ from current implementation")
    expected_order = [(round_number, str(size), implementation) for round_number in range(parameters["rounds"])
                      for size in (SIZES if round_number % 2 == 0 else tuple(reversed(SIZES)))
                      for implementation in (("python", "node") if round_number % 2 == 0 else ("node", "python"))]
    runs = report.get("runs", [])
    if [(run["round"], run["input"], run["implementation"]) for run in runs] != expected_order:
        raise ValueError("missing, duplicate or misordered benchmark run")
    for run in runs:
        worker = run["worker"]
        if type(run["round"]) is not int:
            raise ValueError("run number must be a strict integer")
        if (worker.get("schema") != "ttrace.handoff-benchmark-worker/v1"
                or worker.get("implementation") != run["implementation"]
                or worker.get("reference_checks") != 1 or type(worker["reference_checks"]) is not int
                or worker.get("warmups") != parameters["warmups"] or type(worker["warmups"]) is not int
                or worker.get("sample_count") != parameters["samples"] or type(worker["sample_count"]) is not int):
            raise ValueError("worker parameters differ")
        expected = expected_inputs[run["input"]]
        if worker.get("input_sha256") != expected["input_sha256"] or worker.get("full_report_sha256") != expected["full_report_sha256"]:
            raise ValueError("worker did not measure the required input/result")
        if len(worker["samples_ns"]) != parameters["samples"] or worker["summary_ns"] != summarize(worker["samples_ns"]):
            raise ValueError("incorrect API sample statistics")
        if len(run["fresh_cli_samples_ns"]) != parameters["fresh_cli_samples"] or run["fresh_cli_summary_ns"] != summarize(run["fresh_cli_samples_ns"]):
            raise ValueError("incorrect CLI sample statistics")
        if (run.get("fresh_cli_reports_checked") != parameters["fresh_cli_samples"]
                or type(run["fresh_cli_reports_checked"]) is not int):
            raise ValueError("fresh CLI results were not all checked")
        peak = worker["peak_memory"]
        if (type(peak.get("bytes")) is not int or peak["bytes"] <= 0
                or peak.get("method") != MEMORY_METHODS.get(report["environment"]["os"], {}).get(run["implementation"])):
            raise ValueError("invalid whole-process memory measurement")
        if worker.get("runtime_version") != report["environment"].get(run["implementation"]):
            raise ValueError("worker runtime does not match recorded environment")
        for summary in (worker["summary_ns"], run["fresh_cli_summary_ns"]):
            if any(type(value) not in (int, float) for value in summary.values()):
                raise ValueError("statistics must be numeric, not coerced booleans")
    if report.get("summary") != make_summary(runs, expected_inputs):
        raise ValueError("summary does not reproduce from raw samples")
    expected_guardrails = derive_guardrails(runs, expected_inputs) if report["mode"] == "baseline" else []
    if report.get("review_guardrails") != expected_guardrails:
        raise ValueError("guardrails are not derived from the measured baseline")


def render_markdown(report: dict) -> str:
    validate_report(report)
    lines = ["# Artifact handoff performance baseline", "", f"Mode: **{report['mode']}**.", "",
             "These are source-backed byte-API and module/Node CLI measurements on public",
             "synthetic inputs, not production SLAs, installed-console startup measurements,",
             "external-user onboarding time or proof of an external deployment.", "",
             f"Environment: {report['environment']['os']} / {report['environment']['architecture']}; "
             f"Python {report['environment']['python']}; Node {report['environment']['node']}.",
             f"Measured source inventory SHA-256: `{report['source_files_sha256']}`.", "",
             "| Artifact bytes | Runtime | API median / p95 ms | Fresh CLI median / p95 ms | Worker peak MiB | Package / context bytes |",
             "|---:|---|---:|---:|---:|---:|"]
    for row in report["summary"]:
        api, cli = row["api_ns"], row["fresh_cli_ns"]
        lines.append(f"| {row['input']} | {row['implementation']} | {api['median']/1e6:.3f} / {api['p95']/1e6:.3f} | "
                     f"{cli['median']/1e6:.3f} / {cli['p95']/1e6:.3f} | {row['maximum_worker_peak_bytes']/1048576:.1f} | "
                     f"{row['package_bytes']} / {row['receiver_context_bytes']} |")
    lines += ["", "## Method and limitations", "",
              "Each implementation/input/round uses a fresh API worker and one unmeasured",
              "reference verification in addition to the stated warmups. Files are loaded before",
              "API timing; parsing, hashes, signatures and decision computation are timed.",
              "Per-call report serialization/comparison is outside that timer. Worker peak memory",
              "includes the runtime, imports, loaded data, checks, warmups and measured calls;",
              "it is neither incremental verifier heap nor the peak of the separate CLI runs.", "",
              "Fresh CLI measurements include process startup, file reads, verification, JSON",
              "output capture and process exit. A fresh process is not a cold OS filesystem cache.",
              "Round two reverses input/runtime order. Dependency acquisition and generation are",
              "excluded. Host load, CPU frequency, GC and OS caching are not controlled.", "",
              "Raw samples, all input sizes/hashes, full-result hashes, source-file identities and",
              "runtime/dependency versions are retained in report.json beside this generated file.",
              "Median/p95 in the table pool rounds; p95 uses the nearest-rank definition.", ""]
    lines += ["Report validation recomputes inputs, identities and statistics; it does not",
              "authenticate an unknown publisher or prove that supplied timing samples were",
              "honestly measured. These local results are backed by the actual recorded run.", ""]
    if report["mode"] == "baseline":
        lines += ["## Initial review triggers, not automatic approval gates", "",
                  "Time triggers are four times the worst per-round p95: API rounded up to 1 ms,",
                  "fresh CLI to 10 ms. Memory is twice the worst worker peak, rounded up to 1 MiB.",
                  "Package/context byte budgets are exact for these fixtures. These local-host",
                  "triggers require a comparable rerun and investigation; they are not universal",
                  "hardware limits or absolute-time CI assertions.", "",
                  "| Artifact bytes | Runtime | API p95 ms | Fresh CLI p95 ms | Worker peak MiB |",
                  "|---:|---|---:|---:|---:|"]
        for row in report["review_guardrails"]:
            lines.append(f"| {row['input']} | {row['implementation']} | {row['api_p95_review_trigger_ms']} | "
                         f"{row['fresh_cli_p95_review_trigger_ms']} | {row['worker_peak_review_trigger_mib']} |")
    else:
        lines += ["This smoke run checks measurement plumbing only. It does not establish a baseline or budgets."]
    return "\n".join(lines) + "\n"


def run_benchmark(destination: Path, node: str, *, mode: str = "baseline") -> dict:
    if mode not in PARAMETERS:
        raise ValueError("unknown measurement mode")
    if destination.exists() or destination.is_symlink():
        raise ValueError("benchmark destination must be new; existing results are preserved")
    executable = shutil.which(node)
    if not executable:
        raise RuntimeError("Node is required; no silent benchmark skip")
    executable = str(Path(executable).resolve(strict=True))
    parameters = PARAMETERS[mode]
    sources = source_inventory()
    destination.mkdir(parents=True, exist_ok=False)
    destination = destination.resolve()
    env = dict(os.environ)
    for key in list(env):
        if key.upper() in {"PYTHONPATH", "PYTHONHOME", "NODE_PATH", "NODE_OPTIONS"}:
            env.pop(key)
    env["PYTHONHASHSEED"] = "0"
    from ttrace.artifact_handoff import verify_artifact_handoff
    inputs = {}
    for size in SIZES:
        files, context = generated_input(size)
        package = destination / "inputs" / str(size) / "package"
        package.mkdir(parents=True)
        for name, raw in files.items():
            (package / name).write_bytes(raw)
        (package.parent / "receiver-context.json").write_bytes(context)
        inputs[str(size)] = input_description(files, context)
        inputs[str(size)]["full_report_sha256"] = checked_report(verify_artifact_handoff(files, context))
        # Compare complete reports before starting any measurements for this input.
        node_report, _ = run_json([executable, str(ROOT / "verifiers/node/artifact-handoff.mjs"), "verify", str(package),
                                  "--receiver-context", str(package.parent / "receiver-context.json")], env)
        if checked_report(node_report) != inputs[str(size)]["full_report_sha256"]:
            raise RuntimeError("implementations disagree before timing")
    runs = []
    for round_number in range(parameters["rounds"]):
        sizes = SIZES if round_number % 2 == 0 else tuple(reversed(SIZES))
        implementations = ("python", "node") if round_number % 2 == 0 else ("node", "python")
        for size in sizes:
            package = destination / "inputs" / str(size) / "package"
            context = package.parent / "receiver-context.json"
            for implementation in implementations:
                if implementation == "python":
                    command = [sys.executable, str(ROOT / "scripts/benchmark_handoff_worker.py"), str(package),
                               "--receiver-context", str(context), "--warmups", str(parameters["warmups"]), "--samples", str(parameters["samples"])]
                    cli = [sys.executable, "-m", "openpoc.verify_artifact_handoff", str(package), "--receiver-context", str(context)]
                else:
                    command = [executable, str(ROOT / "verifiers/node/benchmark-artifact-handoff.mjs"), str(package), str(context),
                               str(parameters["warmups"]), str(parameters["samples"])]
                    cli = [executable, str(ROOT / "verifiers/node/artifact-handoff.mjs"), "verify", str(package), "--receiver-context", str(context)]
                worker, _ = run_json(command, env)
                if worker["full_report_sha256"] != inputs[str(size)]["full_report_sha256"] or worker["input_sha256"] != inputs[str(size)]["input_sha256"]:
                    raise RuntimeError("worker measured different input bytes or outcome")
                cold = []
                for _ in range(parameters["fresh_cli_samples"]):
                    report, duration = run_json(cli, env)
                    if checked_report(report) != inputs[str(size)]["full_report_sha256"]:
                        raise RuntimeError("fresh CLI result differs")
                    cold.append(duration)
                runs.append({"round": round_number, "input": str(size), "implementation": implementation, "worker": worker,
                             "fresh_cli_samples_ns": cold, "fresh_cli_summary_ns": summarize(cold),
                             "fresh_cli_reports_checked": len(cold)})
    if source_inventory() != sources:
        raise RuntimeError("measured source changed during the benchmark")
    node_version = subprocess.run([executable, "--version"], capture_output=True, text=True, check=True, timeout=10).stdout.strip()
    commit = subprocess.run(["git", "-c", "safe.directory=" + ROOT.as_posix(), "rev-parse", "HEAD"], cwd=ROOT,
                            capture_output=True, text=True, check=True, timeout=10).stdout.strip()
    report = {"schema": SCHEMA, "mode": mode, "parameters": parameters, "recorded_at_utc": datetime.now(timezone.utc).isoformat(),
              "repository_base_commit": commit, "source_files": sources, "source_files_sha256": digest(sources),
              "environment": {"os": platform.system(), "os_release": platform.release(), "architecture": platform.machine(),
                              "logical_cpus": os.cpu_count(), "python": platform.python_version(), "node": node_version,
                              "python_hash_seed": 0, "project_loading": "source checkout; module CLI",
                              "receipt_dependencies": {name: importlib.metadata.version(name) for name in ("cryptography", "cffi", "pycparser")}},
              "inputs": inputs, "runs": runs, "summary": make_summary(runs, inputs),
              "review_guardrails": derive_guardrails(runs, inputs) if mode == "baseline" else [],
              "non_claims": ["production SLA", "cold disk cache", "incremental heap", "fresh CLI peak memory",
                             "installed-console startup", "external pilot", "first-time reviewer setup duration",
                             "measurement provenance authentication"]}
    validate_report(report, check_sources=True)
    (destination / "report.json").write_bytes(json.dumps(report, indent=2, sort_keys=True, allow_nan=False).encode() + b"\n")
    (destination / "report.md").write_bytes(render_markdown(report).encode("utf-8"))
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("run", "smoke", "validate"))
    parser.add_argument("path", type=Path)
    parser.add_argument("--node", default="node")
    args = parser.parse_args()
    if args.operation == "validate":
        report = json.loads(args.path.read_bytes())
        validate_report(report, check_sources=True)
    else:
        report = run_benchmark(args.path, args.node, mode="smoke" if args.operation == "smoke" else "baseline")
    print(json.dumps({"mode": report["mode"], "run_count": len(report["runs"]), "source_files_sha256": report["source_files_sha256"],
                      "all_result_checks_passed": True, "summary": report["summary"]}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
