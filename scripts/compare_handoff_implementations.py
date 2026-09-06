"""Compare complete profile reports; the isolated Node verifier never calls Python."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from openpoc.verify_artifact_handoff import verify_directory
from ttrace.artifact_handoff import HandoffValidationError


def canonical(value) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def input_inventory(corpus: dict, root: Path) -> dict:
    root = root.resolve(strict=True)
    paths = {root / "corpus.json"}
    for case in corpus["cases"]:
        package = (root / case["package"]).resolve(strict=True)
        context = (root / case["context"]).resolve(strict=True)
        if not package.is_relative_to(root) or not context.is_relative_to(root):
            raise RuntimeError("corpus input outside selected root")
        paths.add(context)
        paths.update(package.iterdir())
    result = {}
    for path in sorted(paths):
        if path.is_symlink() or not path.is_file():
            raise RuntimeError("corpus inventory accepts only regular files")
        raw = path.read_bytes()
        result[path.relative_to(root).as_posix()] = {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}
    return result


def python_results(corpus: dict, root: Path) -> list[dict]:
    results = []
    for case in corpus["cases"]:
        try:
            report = verify_directory(root / case["package"], root / case["context"])
        except HandoffValidationError as exc:
            if exc.code != case["expected_error_code"]:
                raise RuntimeError(f"Python expectation mismatch: {case['id']}") from exc
            results.append({"id": case["id"], "status": "agree", "error_code": exc.code})
            continue
        if case["expected_error_code"] is not None:
            raise RuntimeError(f"Python omitted expected error: {case['id']}")
        for path, expected in case["expected"].items():
            actual = report
            for key in path.split("."):
                actual = actual[key]
            if canonical(actual) != canonical(expected):
                raise RuntimeError(f"Python expectation mismatch: {case['id']}: {path}")
        results.append({"id": case["id"], "status": "agree", "report": report})
    return results


def compare_results(expected_ids: list[str], python: list[dict], node: dict) -> list[dict]:
    if not expected_ids or len(set(expected_ids)) != len(expected_ids):
        raise RuntimeError("empty or duplicate case declarations")
    if node.get("schema") != "ttrace.handoff-node-corpus-report/v1":
        raise RuntimeError("unknown Node corpus report")
    if node.get("case_count") != len(expected_ids) or node.get("agree_count") != len(expected_ids):
        raise RuntimeError("Node case coverage mismatch")
    results = node.get("cases", [])
    if [case["id"] for case in results] != expected_ids or [case["id"] for case in python] != expected_ids:
        raise RuntimeError("case identity/order/coverage mismatch")
    summary = []
    for left, right in zip(python, results):
        if canonical(left) != canonical(right):
            raise RuntimeError(f"complete report or typed error differs: {left['id']}")
        item = {"id": left["id"], "status": "agree"}
        if "report" in left:
            item["full_report_sha256"] = hashlib.sha256(canonical(left["report"])).hexdigest()
        else:
            item["error_code"] = left["error_code"]
        summary.append(item)
    return summary


def compare(node: str, work_root: Path | None = None) -> dict:
    executable = shutil.which(node)
    if not executable:
        raise RuntimeError("Node executable is required; this gate must not silently skip")
    executable = str(Path(executable).resolve(strict=True))
    source = ROOT / "verifiers/node/artifact-handoff.mjs"
    corpus_root = ROOT / "examples/artifact-handoff-v0.1"
    corpus_bytes = (corpus_root / "corpus.json").read_bytes()
    corpus = json.loads(corpus_bytes)
    expected_ids = [case["id"] for case in corpus["cases"]]
    inventory = input_inventory(corpus, corpus_root)
    first = python_results(corpus, corpus_root)
    # Only the standalone JS file and public data are copied. No Python module,
    # node_modules, package metadata or first-verifier outputs are available there.
    with tempfile.TemporaryDirectory(prefix="ttrace-node-isolated-", dir=work_root) as raw:
        work = Path(raw).resolve()
        if work.is_relative_to(ROOT):
            raise RuntimeError("isolation directory must be outside the source checkout")
        shutil.copyfile(source, work / "artifact-handoff.mjs")
        shutil.copytree(corpus_root, work / "corpus")
        if any(path.suffix in {".py", ".pyc", ".whl"} for path in work.rglob("*")):
            raise RuntimeError("unexpected Python implementation in isolated input")
        # No Python/Node preload variables or useful PATH. Node's permission
        # mode permits reads only of the copied inputs; no subprocess permission.
        env = {key: value for key, value in os.environ.items()
               if key.upper() in {"SYSTEMROOT", "WINDIR", "TEMP", "TMP"}}
        env["PATH"] = str(work)
        command = [executable, "--permission", f"--allow-fs-read={work}",
                   str(work / "artifact-handoff.mjs"), "corpus", str(work / "corpus")]
        completed = subprocess.run(command, cwd=work, env=env, text=True, capture_output=True,
                                   encoding="utf-8", timeout=60, check=False)
        if completed.returncode:
            raise RuntimeError(f"isolated Node verification failed: {completed.stdout}\n{completed.stderr}")
        second = json.loads(completed.stdout)
        digest = hashlib.sha256(corpus_bytes).hexdigest()
        if second.get("corpus_sha256") != digest:
            raise RuntimeError("Node verified a different corpus manifest")
        inputs_digest = hashlib.sha256(canonical(inventory)).hexdigest()
        if second.get("input_files") != inventory or second.get("corpus_inputs_sha256") != inputs_digest:
            raise RuntimeError("Node verified different corpus fixture bytes")
        if input_inventory(corpus, corpus_root) != inventory:
            raise RuntimeError("source corpus changed during comparison")
        results = compare_results(expected_ids, first, second)
    version = subprocess.run([executable, "--version"], text=True, capture_output=True, check=True, timeout=10).stdout.strip()
    return {"schema": "ttrace.handoff-implementation-comparison/v1", "profile": "ttrace.artifact-handoff/v1",
            "corpus_sha256": digest, "node_verifier_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
            "corpus_inputs_sha256": inputs_digest, "input_files": inventory,
            "python_version": platform.python_version(), "node_version": version, "platform": platform.system(),
            "case_count": len(results), "agree_count": len(results), "full_report_comparison": True,
            "isolated_node_corpus": True, "node_reads_restricted_to_copied_inputs": True,
            "node_subprocess_permission": False, "cases": results,
            "non_claim": "separate implementation; not independent organizations, a separate cryptographic backend, or an external pilot"}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--node", default="node")
    parser.add_argument("--work-root", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    report = compare(args.node, args.work_root)
    output = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.write_bytes(output.encode("utf-8"))
        print(json.dumps({key: value for key, value in report.items() if key != "cases"}, sort_keys=True))
    else:
        print(output, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
