"""The agreement gate must compare all cases and every report member."""
import copy
import hashlib
import json
from pathlib import Path

import pytest

from scripts.compare_handoff_implementations import canonical, compare_results, input_inventory, python_results

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def results():
    left = [{"id": "matching", "status": "agree", "report": {"result": "bounded", "count": 1}},
            {"id": "invalid", "status": "agree", "error_code": "invalid-fields"}]
    right = {"schema": "ttrace.handoff-node-corpus-report/v1", "case_count": 2,
             "agree_count": 2, "cases": copy.deepcopy(left)}
    return ["matching", "invalid"], left, right


def test_full_comparison_gate_accepts_complete_equal_results(results):
    summary = compare_results(*results)
    assert summary[0]["full_report_sha256"] == hashlib.sha256(canonical(results[1][0]["report"])).hexdigest()
    assert summary[1]["error_code"] == "invalid-fields"


@pytest.mark.parametrize("mutation", [
    lambda r: r.update(case_count=1),
    lambda r: r.update(agree_count=1),
    lambda r: r.update(schema="unknown"),
    lambda r: r["cases"].pop(),
    lambda r: r["cases"].reverse(),
    lambda r: r["cases"][1].update(id="matching"),
    lambda r: r["cases"][1].update(error_code="invalid-json"),
    lambda r: r["cases"][0]["report"].update(extra="unexpected"),
    lambda r: r["cases"][0]["report"].pop("result"),
    lambda r: r["cases"][0]["report"].update(count=True),
], ids=["omitted-count", "incomplete-agreement", "unknown-schema", "missing-case", "order", "duplicate-id",
        "different-error", "extra-report-field", "missing-report-field", "bool-is-not-integer"])
def test_comparison_gate_rejects_incomplete_or_different_results(results, mutation):
    mutation(results[2])
    with pytest.raises(RuntimeError):
        compare_results(*results)


def test_empty_or_duplicate_declarations_cannot_pass(results):
    with pytest.raises(RuntimeError, match="empty or duplicate"):
        compare_results([], [], {})
    with pytest.raises(RuntimeError, match="empty or duplicate"):
        compare_results(["same", "same"], results[1], results[2])


def test_saved_comparison_covers_current_full_python_reports_and_node_source():
    root = ROOT / "examples/artifact-handoff-v0.1"
    raw = (root / "corpus.json").read_bytes()
    corpus = json.loads(raw)
    saved = json.loads((ROOT / "docs/artifact-handoff-implementation-comparison.json").read_bytes())
    first = python_results(corpus, root)
    normalized = {"schema": "ttrace.handoff-node-corpus-report/v1", "case_count": len(first),
                  "agree_count": len(first), "cases": first}
    assert saved["cases"] == compare_results([case["id"] for case in corpus["cases"]], first, normalized)
    assert saved["corpus_sha256"] == hashlib.sha256(raw).hexdigest()
    assert saved["node_verifier_sha256"] == hashlib.sha256((ROOT / "verifiers/node/artifact-handoff.mjs").read_bytes()).hexdigest()
    inventory = input_inventory(corpus, root)
    assert saved["input_files"] == inventory
    assert saved["corpus_inputs_sha256"] == hashlib.sha256(canonical(inventory)).hexdigest()
    assert saved["case_count"] == saved["agree_count"] == len(corpus["cases"]) == 59


def test_malformed_case_bytes_change_inventory_even_when_the_error_code_is_unchanged(tmp_path):
    from openpoc.artifact_handoff_corpus import generate_corpus
    root = tmp_path / "corpus"
    generate_corpus(root)
    corpus = json.loads((root / "corpus.json").read_bytes())
    before = input_inventory(corpus, root)
    first = python_results(corpus, root)
    (root / "contexts/duplicate-json-key.json").write_bytes(b'{"other":1,"other":2}')
    after = input_inventory(corpus, root)
    assert first == python_results(corpus, root)
    assert before != after
    assert hashlib.sha256(canonical(before)).digest() != hashlib.sha256(canonical(after)).digest()
