"""One fresh Python worker for one fixed input; reads precede API timing."""

from __future__ import annotations

import argparse
import hashlib
import json
import platform
import sys
import time
from pathlib import Path

from handoff_benchmark_support import canonical, checked_report, digest, process_peak_memory, summarize

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import ttrace.artifact_handoff as implementation
from openpoc.verify_artifact_handoff import verify_directory


def run(package: Path, context: Path, *, warmups: int, samples: int) -> dict:
    if type(warmups) is not int or type(samples) is not int or not 1 <= warmups <= 100 or not 1 <= samples <= 2000:
        raise ValueError("worker call counts outside bounded measurement range")
    if not Path(implementation.__file__).resolve().is_relative_to(ROOT):
        raise RuntimeError("worker loaded a different project implementation")
    # The saved package is stable during a run. Use the bounded file boundary
    # before loading the byte-API buffers and use its result as the reference.
    baseline = verify_directory(package, context)
    files = {path.name: path.read_bytes() for path in package.iterdir()}
    context_bytes = context.read_bytes()
    report_digest = checked_report(baseline)
    reference = canonical(baseline)
    durations = []
    for index in range(warmups + samples):
        start = time.perf_counter_ns()
        report = implementation.verify_artifact_handoff(files, context_bytes)
        elapsed = time.perf_counter_ns() - start
        # Report checking/serialization are deliberately outside the API timing.
        if canonical(report) != reference:
            raise RuntimeError("API result changed during timing")
        if index >= warmups:
            durations.append(elapsed)
    inventory = {name: {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()} for name, raw in files.items()}
    inventory["receiver-context.json"] = {"bytes": len(context_bytes), "sha256": hashlib.sha256(context_bytes).hexdigest()}
    memory = process_peak_memory()
    return {"schema": "ttrace.handoff-benchmark-worker/v1", "implementation": "python",
            "runtime_version": platform.python_version(), "reference_checks": 1, "warmups": warmups, "sample_count": samples,
            "input_sha256": digest(inventory), "full_report_sha256": report_digest,
            "samples_ns": durations, "summary_ns": summarize(durations), "peak_memory": memory,
            "memory_scope": "whole fresh API worker including runtime, imports, input, checks and all calls"}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("package", type=Path)
    parser.add_argument("--receiver-context", required=True, type=Path)
    parser.add_argument("--warmups", required=True, type=int)
    parser.add_argument("--samples", required=True, type=int)
    args = parser.parse_args()
    print(json.dumps(run(args.package, args.receiver_context, warmups=args.warmups, samples=args.samples), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
