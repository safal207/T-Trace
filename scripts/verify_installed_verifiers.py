"""Exercise a built wheel in a fresh environment outside the source checkout."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import tempfile
import venv
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CASES = (
    ("base", "ttrace.validation", "minimal.ttrace.jsonl", None),
    ("capture", "openpoc.verify_assurance", "openpoc-01/bypass.scenario.json",
     {"trace_valid": True, "capture_status": "violated", "overall_assurance": "insufficient"}),
    ("replay-complete", "openpoc.verify_reproducibility",
     "openpoc-02/complete-replay.scenario.json",
     {"claim_verdict": "supported-under-stated-assumptions"}),
    ("replay-incomplete", "openpoc.verify_reproducibility",
     "openpoc-02/incomplete-but-reproducible.scenario.json",
     {"relation_satisfied": True, "capture_status": "violated", "claim_verdict": "violated"}),
    ("cross-source-missing", "openpoc.verify_cross_source",
     "openpoc-03/counterpart-omission.scenario.json",
     {"pairwise_consistency_status": "violated", "global_completeness_status": "unproven"}),
    ("cross-source-nonfinal", "openpoc.verify_cross_source",
     "openpoc-03/nonfinal-snapshots.scenario.json",
     {"pairwise_consistency_status": "insufficient-snapshot-finality",
      "global_completeness_status": "unproven"}),
    ("cross-source-delayed", "openpoc.verify_cross_source",
     "openpoc-03/delayed-observation.scenario.json",
     {"pairwise_consistency_status": "violated", "global_completeness_status": "unproven"}),
)
CONSOLES = (
    ("ttrace-validate", CASES[0]),
    ("ttrace-assurance", CASES[1]),
    ("ttrace-reproducibility", CASES[3]),
    ("ttrace-cross-source", CASES[5]),
)


def _run(command: list[str], *, cwd: Path, env: dict[str, str]) -> str:
    result = subprocess.run(
        command, cwd=cwd, env=env, capture_output=True, text=True,
        encoding="utf-8", errors="replace", timeout=120, check=False,
    )
    if result.returncode:
        raise RuntimeError(
            f"command failed ({result.returncode}): {command[0]}\n"
            f"{result.stdout}\n{result.stderr}"
        )
    return result.stdout


def _check_result(stdout: str, expected: dict | None) -> dict:
    if expected is None:
        if not stdout.startswith("PASS ") or "(3 records)" not in stdout:
            raise RuntimeError(f"unexpected base validation result: {stdout}")
        return {"base_trace_valid": True}
    actual = json.loads(stdout)
    observed = {key: actual.get(key) for key in expected}
    if json.dumps(observed, sort_keys=True) != json.dumps(expected, sort_keys=True):
        raise RuntimeError(f"installed verdict mismatch: {observed} != {expected}")
    return observed


def verify_wheel(wheel: Path, work_root: Path | None = None) -> dict:
    wheel = wheel.resolve(strict=True)
    if wheel.suffix != ".whl":
        raise ValueError("expected one built wheel file")
    clean_env = dict(os.environ)
    for name in ("PYTHONPATH", "PYTHONHOME"):
        clean_env.pop(name, None)
    clean_env["PIP_CONFIG_FILE"] = os.devnull

    with tempfile.TemporaryDirectory(prefix="ttrace-wheel-", dir=work_root) as raw:
        work = Path(raw).resolve()
        environment = work / "environment"
        venv.EnvBuilder(with_pip=True).create(environment)
        bin_dir = environment / ("Scripts" if os.name == "nt" else "bin")
        python = bin_dir / ("python.exe" if os.name == "nt" else "python")
        _run(
            [str(python), "-I", "-m", "pip", "--isolated",
             "--disable-pip-version-check", "install", "--no-index", "--no-deps",
             "--no-cache-dir", str(wheel)], cwd=work, env=clean_env,
        )
        probe = _run(
            [str(python), "-I", "-c",
             "import json, sys, ttrace.validation, openpoc.verify_assurance, "
             "openpoc.verify_cross_source; "
             "print(json.dumps({'python':sys.version,'paths':"
             "[ttrace.validation.__file__,openpoc.verify_assurance.__file__,"
             "openpoc.verify_cross_source.__file__],'search_path':sys.path}))"],
            cwd=work, env=clean_env,
        )
        imported = json.loads(probe)
        for path in imported["paths"]:
            Path(path).resolve().relative_to(environment)
        if str(ROOT) in imported["search_path"]:
            raise RuntimeError("source checkout leaked into the isolated search path")

        inputs = work / "inputs"
        inputs.mkdir()
        shutil.copyfile(ROOT / "examples" / "minimal.ttrace.jsonl", inputs / "minimal.ttrace.jsonl")
        for name in ("openpoc-01", "openpoc-02", "openpoc-03"):
            shutil.copytree(ROOT / "examples" / name, inputs / name)

        results = []
        for name, module, fixture, expected in CASES:
            stdout = _run(
                [str(python), "-I", "-m", module, str(inputs / fixture)],
                cwd=work, env=clean_env,
            )
            results.append({"entry": module, "case": name,
                            "observed": _check_result(stdout, expected)})
        for console, (_, _, fixture, expected) in CONSOLES:
            executable = bin_dir / (console + (".exe" if os.name == "nt" else ""))
            stdout = _run([str(executable), str(inputs / fixture)], cwd=work, env=clean_env)
            results.append({"entry": console, "observed": _check_result(stdout, expected)})

        return {
            "wheel": wheel.name,
            "wheel_sha256": hashlib.sha256(wheel.read_bytes()).hexdigest(),
            "python": imported["python"],
            "installed_modules_inside_fresh_environment": True,
            "isolated_module_runs": len(CASES),
            "console_entry_runs": len(CONSOLES),
            "install_from_local_wheel_without_dependencies": True,
            "results": results,
            "non_claims": [
                "not an independently operated external review",
                "not a cryptographic evidence-package validation",
                "fixture agreement does not prove production capture completeness",
            ],
        }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("wheel", type=Path)
    parser.add_argument("--work-root", type=Path)
    args = parser.parse_args()
    try:
        report = verify_wheel(args.wheel, args.work_root)
    except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired) as exc:
        print(json.dumps({"status": "error", "error": str(exc)}, indent=2))
        return 1
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
