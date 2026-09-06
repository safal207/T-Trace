"""Verify the frozen handoff corpus from a non-editable offline installation."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import tempfile
import venv
from pathlib import Path

from verify_installed_verifiers import _run

ROOT = Path(__file__).resolve().parents[1]
DEPENDENCIES = ("cryptography==46.0.4", "cffi==2.1.1", "pycparser==3.0")


def verify(wheel: Path, dependency_wheels: Path, work_root: Path | None = None) -> dict:
    wheel = wheel.resolve(strict=True)
    dependency_wheels = dependency_wheels.resolve(strict=True)
    environment_variables = dict(os.environ)
    for name in ("PYTHONPATH", "PYTHONHOME"):
        environment_variables.pop(name, None)
    environment_variables["PIP_CONFIG_FILE"] = os.devnull
    with tempfile.TemporaryDirectory(prefix="ttrace-handoff-wheel-", dir=work_root) as raw:
        work = Path(raw).resolve()
        environment = work / "environment"
        venv.EnvBuilder(with_pip=True).create(environment)
        bin_directory = environment / ("Scripts" if os.name == "nt" else "bin")
        python = bin_directory / ("python.exe" if os.name == "nt" else "python")
        _run([str(python), "-I", "-m", "pip", "--isolated", "--disable-pip-version-check", "install",
              "--no-index", "--no-deps", "--no-cache-dir", "--find-links", str(dependency_wheels),
              str(wheel), *DEPENDENCIES], cwd=work, env=environment_variables)
        _run([str(python), "-I", "-m", "pip", "check"], cwd=work, env=environment_variables)
        probe = _run([str(python), "-I", "-c",
            "import json, sys, ttrace.artifact_handoff as a, openpoc.verify_artifact_handoff as b, "
            "openpoc.action_receipt_compat_v01 as c, cryptography; "
            "print(json.dumps({'python':sys.version,'paths':[a.__file__,b.__file__,c.__file__,cryptography.__file__]}))"],
            cwd=work, env=environment_variables)
        imported = json.loads(probe)
        for path in imported["paths"]:
            Path(path).resolve().relative_to(environment)
        corpus = work / "corpus"
        shutil.copytree(ROOT / "examples/artifact-handoff-v0.1", corpus)
        summary = json.loads(_run([str(python), "-I", "-m", "openpoc.artifact_handoff_corpus", "verify", str(corpus)],
                                  cwd=work, env=environment_variables))
        manifest = json.loads((corpus / "corpus.json").read_bytes())
        if summary["agree_count"] != len(manifest["cases"]) or summary["case_count"] != len(manifest["cases"]):
            raise RuntimeError("installed corpus coverage mismatch")
        baseline = next(case for case in manifest["cases"] if case["id"] == "matching")
        command = [str(corpus / baseline["package"]), "--receiver-context", str(corpus / baseline["context"])]
        module = _run([str(python), "-I", "-m", "openpoc.verify_artifact_handoff", *command], cwd=work, env=environment_variables)
        console = bin_directory / ("ttrace-handoff.exe" if os.name == "nt" else "ttrace-handoff")
        console_result = _run([str(console), *command], cwd=work, env=environment_variables)
        if json.loads(module) != json.loads(console_result):
            raise RuntimeError("installed module and console reports differ")
        human = _run([str(console), *command, "--format", "markdown"], cwd=work, env=environment_variables)
        if "supported-under-receiver-context" not in human or "## How to use this result" not in human:
            raise RuntimeError("installed human report is incomplete")
        return {"wheel_sha256": hashlib.sha256(wheel.read_bytes()).hexdigest(), "python": imported["python"],
                "dependencies": list(DEPENDENCIES), "offline_install": True,
                "installed_modules_inside_fresh_environment": True, "corpus_cases_agree": summary["agree_count"],
                "console_matches_module": True, "human_report_checked": True,
                "dependency_wheels": {path.name: hashlib.sha256(path.read_bytes()).hexdigest()
                                      for path in sorted(dependency_wheels.glob("*.whl"))},
                "non_claim": "internal installed verification; not an independent implementation or external pilot"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("wheel", type=Path)
    parser.add_argument("dependency_wheels", type=Path)
    parser.add_argument("--work-root", type=Path)
    args = parser.parse_args()
    report = verify(args.wheel, args.dependency_wheels, args.work_root)
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
