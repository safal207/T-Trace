import hashlib
import json
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from openpoc.action_receipt_compat_v01 import (
    signed_head_bytes,
    signed_receipt_bytes,
    verify_head_assertion,
    verify_log,
    verify_manifest,
    verify_receipt,
)


SEED = bytes.fromhex("01" * 32)
PRIVATE_KEY = Ed25519PrivateKey.from_private_bytes(SEED)
PUBLIC_KEY = PRIVATE_KEY.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()


def signed_receipt(**overrides):
    receipt = {
        "step_id": "step-0",
        "action_id": "tool.transfer",
        "params": {"effect_id": "effect-0", "amount": 100},
        "success": True,
        "ts_ms": 1,
        "seq": 0,
        "actor": {"agent": "agent-1", "user": "user-1"},
        "public_key": PUBLIC_KEY,
    }
    receipt.update(overrides)
    receipt["signature"] = PRIVATE_KEY.sign(signed_receipt_bytes(receipt)).hex()
    return receipt


def raw_json(receipt):
    return json.dumps(receipt, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def chained_receipts(specs):
    raw_lines = []
    receipts = []
    previous_hash = None
    for spec in specs:
        receipt = dict(spec)
        if previous_hash is not None:
            receipt["prev_hash"] = previous_hash
        signed = signed_receipt(**receipt)
        raw = raw_json(signed)
        receipts.append(signed)
        raw_lines.append(raw)
        previous_hash = hashlib.sha256(raw).hexdigest()
    return receipts, raw_lines


def write_log(path: Path, raw_lines):
    path.write_bytes(b"\n".join(raw_lines) + b"\n")


def signed_head(raw_lines):
    assertion = {
        "chain_id": hashlib.sha256(raw_lines[0]).hexdigest(),
        "count": len(raw_lines),
        "head_hash": hashlib.sha256(raw_lines[-1]).hexdigest(),
        "asserted_ts_ms": 99,
        "public_key": PUBLIC_KEY,
    }
    assertion["signature"] = PRIVATE_KEY.sign(signed_head_bytes(assertion)).hex()
    return assertion


def test_seq_is_signed_immediately_after_ts_ms():
    receipt = {
        "step_id": "s1",
        "action_id": "tool.call",
        "params": {"b": 2, "a": 1},
        "success": True,
        "ts_ms": 123,
        "seq": 7,
        "actor": {"agent": "a", "user": "u"},
    }

    assert signed_receipt_bytes(receipt) == (
        '{"step_id":"s1","action_id":"tool.call","params":{"a":1,"b":2},'
        '"success":true,"ts_ms":123,"seq":7,'
        '"actor":{"agent":"a","user":"u"}}'
    ).encode("utf-8")


def test_replayed_step_id_is_detected_while_signature_and_chain_stay_valid(tmp_path: Path):
    receipts, raw_lines = chained_receipts(
        [
            {"step_id": "A", "seq": None, "ts_ms": 1},
            {"step_id": "B", "seq": None, "ts_ms": 2},
            {"step_id": "C", "seq": None, "ts_ms": 3},
            {"step_id": "B", "seq": None, "ts_ms": 4},
        ]
    )
    path = tmp_path / "replayed.jsonl"
    write_log(path, raw_lines)

    result = verify_log(path)
    assert all(verify_receipt(receipt) is None for receipt in receipts)
    assert result.chain_break is None
    assert result.step_id_repeat == 4
    assert result.seq_gap is None
    assert result.seq_repeat is None


def test_seq_gap_and_repeat_are_distinct(tmp_path: Path):
    _, gap_lines = chained_receipts(
        [
            {"step_id": "A", "seq": 0, "ts_ms": 1},
            {"step_id": "B", "seq": 1, "ts_ms": 2},
            {"step_id": "C", "seq": 3, "ts_ms": 3},
        ]
    )
    _, repeat_lines = chained_receipts(
        [
            {"step_id": "A", "seq": 0, "ts_ms": 1},
            {"step_id": "B", "seq": 1, "ts_ms": 2},
            {"step_id": "C", "seq": 1, "ts_ms": 3},
        ]
    )

    gap = tmp_path / "gap.jsonl"
    repeat = tmp_path / "repeat.jsonl"
    write_log(gap, gap_lines)
    write_log(repeat, repeat_lines)

    gap_result = verify_log(gap)
    repeat_result = verify_log(repeat)

    assert gap_result.chain_break is None
    assert gap_result.seq_gap == 3
    assert gap_result.seq_repeat is None

    assert repeat_result.chain_break is None
    assert repeat_result.seq_gap is None
    assert repeat_result.seq_repeat == 3


def test_signed_head_matches_full_log_and_rejects_truncation(tmp_path: Path):
    _, raw_lines = chained_receipts(
        [
            {"step_id": "A", "seq": None, "ts_ms": 1},
            {"step_id": "B", "seq": None, "ts_ms": 2},
            {"step_id": "C", "seq": None, "ts_ms": 3},
        ]
    )
    full = tmp_path / "full.jsonl"
    truncated = tmp_path / "truncated.jsonl"
    assertion_path = tmp_path / "head.json"
    write_log(full, raw_lines)
    write_log(truncated, raw_lines[:2])
    assertion_path.write_text(
        json.dumps(signed_head(raw_lines), separators=(",", ":")),
        encoding="utf-8",
    )

    assert verify_head_assertion(assertion_path, full) == "match"
    assert verify_head_assertion(assertion_path, truncated) == "mismatch"


def test_bad_head_signature_is_invalid(tmp_path: Path):
    _, raw_lines = chained_receipts([{"step_id": "A", "seq": None, "ts_ms": 1}])
    log = tmp_path / "log.jsonl"
    assertion_path = tmp_path / "head.json"
    write_log(log, raw_lines)
    assertion = signed_head(raw_lines)
    assertion["signature"] = "00" * 64
    assertion_path.write_text(json.dumps(assertion), encoding="utf-8")

    assert verify_head_assertion(assertion_path, log) == "invalid"


def test_fresh_step_and_monotonic_seq_do_not_detect_semantic_effect_replay(tmp_path: Path):
    """Record-level checks cannot identify a repeated effect with fresh record identity."""

    _, raw_lines = chained_receipts(
        [
            {
                "step_id": "A",
                "seq": 0,
                "ts_ms": 1,
                "params": {"effect_id": "effect-approval", "amount": 100},
            },
            {
                "step_id": "B",
                "seq": 1,
                "ts_ms": 2,
                "params": {"effect_id": "effect-payment-1", "amount": 100},
            },
            {
                "step_id": "C",
                "seq": 2,
                "ts_ms": 3,
                "params": {"effect_id": "effect-audit", "amount": 100},
            },
            {
                "step_id": "D",
                "seq": 3,
                "ts_ms": 4,
                "params": {"effect_id": "effect-payment-1", "amount": 100},
            },
        ]
    )
    log = tmp_path / "fresh-id-replay.jsonl"
    write_log(log, raw_lines)

    result = verify_log(log)
    assert result.signature_failure_lines == ()
    assert result.chain_break is None
    assert result.step_id_repeat is None
    assert result.seq_gap is None
    assert result.seq_repeat is None


def test_manifest_runner_counts_log_and_head_checks(tmp_path: Path):
    vectors = tmp_path / "vectors"
    vectors.mkdir()

    _, raw_lines = chained_receipts(
        [
            {"step_id": "A", "seq": 0, "ts_ms": 1},
            {"step_id": "B", "seq": 1, "ts_ms": 2},
        ]
    )
    write_log(vectors / "valid.jsonl", raw_lines)
    (vectors / "head.json").write_text(
        json.dumps(signed_head(raw_lines), separators=(",", ":")),
        encoding="utf-8",
    )
    manifest = {
        "suite": "test",
        "draft": "draft-test-01",
        "vectors": [
            {
                "file": "valid.jsonl",
                "expect": {"sig_failures": [], "chain_break": None},
            }
        ],
        "head_vectors": [
            {
                "file": "head.json",
                "log": "valid.jsonl",
                "expect": "match",
            }
        ],
    }
    (tmp_path / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")

    report = verify_manifest(
        tmp_path,
        source_repository="example/vectors",
        source_commit="deadbeef",
    )

    assert report.check_count == 2
    assert report.agree_count == 2
    assert report.all_agree is True
