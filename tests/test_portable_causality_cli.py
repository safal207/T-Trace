from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/verify_portable_causality.py"
EXAMPLE = ROOT / "examples/causal-portability/fork-reconciliation.json"


def _run(path: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SCRIPT), str(path)],
        cwd=ROOT,
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


def test_missing_fixture_returns_clean_fail_line(tmp_path: Path) -> None:
    result = _run(tmp_path / "missing.json")
    assert result.returncode == 1
    assert result.stdout.startswith("FAIL ")
    assert "missing.json" in result.stdout
    assert result.stderr == ""


def test_digest_drift_reports_mismatched_key_and_values(tmp_path: Path) -> None:
    fixture = json.loads(EXAMPLE.read_text(encoding="utf-8"))
    expected = fixture["expected"]
    original = expected["receipt_sha256"]
    expected["receipt_sha256"] = "0" * 64
    path = tmp_path / "digest-drift.json"
    path.write_text(json.dumps(fixture), encoding="utf-8")

    result = _run(path)
    assert result.returncode == 1
    assert "expected_digest_mismatch" in result.stdout
    assert "receipt_sha256" in result.stdout
    assert "0" * 64 in result.stdout
    assert original in result.stdout
    assert result.stderr == ""
