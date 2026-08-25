import hashlib
import json
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from openpoc.action_receipt_compat import (
    canonical_json,
    first_chain_break,
    signed_receipt_bytes,
    verify_log,
    verify_manifest,
    verify_receipt,
)


SEED = bytes.fromhex("01" * 32)
PRIVATE_KEY = Ed25519PrivateKey.from_private_bytes(SEED)
PUBLIC_KEY = PRIVATE_KEY.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()


def signed_receipt(**overrides):
    receipt = {
        "step_id": "step-1",
        "action_id": "tool.transfer",
        "params": {"amount": 100, "meta": {"b": 2, "a": "✓"}},
        "success": True,
        "ts_ms": 1,
        "actor": {"agent": "agent-1", "user": "user-1"},
        "public_key": PUBLIC_KEY,
    }
    receipt.update(overrides)
    receipt["signature"] = PRIVATE_KEY.sign(signed_receipt_bytes(receipt)).hex()
    return receipt


def raw_json(receipt):
    return json.dumps(receipt, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def test_canonical_signed_bytes_have_fixed_order_and_recursive_param_sorting():
    receipt = {
        "step_id": "s1",
        "action_id": "tool.call",
        "params": {"b": [2, 1], "a": {"z": "✓", "x": 1}},
        "success": True,
        "ts_ms": 123,
        "actor": {"agent": "a", "user": "u"},
    }

    assert signed_receipt_bytes(receipt) == (
        '{"step_id":"s1","action_id":"tool.call",'
        '"params":{"a":{"x":1,"z":"✓"},"b":[2,1]},'
        '"success":true,"ts_ms":123,'
        '"actor":{"agent":"a","user":"u"}}'
    ).encode("utf-8")


def test_canonical_json_rejects_floats():
    try:
        canonical_json({"ratio": 1.5})
    except ValueError as exc:
        assert "non-integer" in str(exc)
    else:
        raise AssertionError("float must be rejected")


def test_valid_signature_and_bad_key_encoding():
    receipt = signed_receipt()
    assert verify_receipt(receipt) is None

    bad = dict(receipt)
    bad["public_key"] = receipt["public_key"].upper()
    assert verify_receipt(bad) == "public_key must be 32 bytes of lowercase hex"


def test_extension_tampering_keeps_signature_valid_but_breaks_raw_chain():
    first = signed_receipt(vendor_ext={"route": "primary"})
    first_raw = raw_json(first)

    second = signed_receipt(
        step_id="step-2",
        ts_ms=2,
        prev_hash=hashlib.sha256(first_raw).hexdigest(),
    )
    second_raw = raw_json(second)

    tampered_first = dict(first)
    tampered_first["vendor_ext"] = {"route": "bypass"}
    tampered_raw = raw_json(tampered_first)

    assert verify_receipt(tampered_first) is None
    assert verify_receipt(second) is None
    assert first_chain_break([tampered_raw, second_raw]) == 2


def test_head_truncation_leaves_remaining_chain_clean():
    first = signed_receipt()
    first_raw = raw_json(first)
    second = signed_receipt(
        step_id="step-2",
        ts_ms=2,
        prev_hash=hashlib.sha256(first_raw).hexdigest(),
    )
    second_raw = raw_json(second)
    third = signed_receipt(
        step_id="step-3",
        ts_ms=3,
        prev_hash=hashlib.sha256(second_raw).hexdigest(),
    )
    third_raw = raw_json(third)

    assert first_chain_break([first_raw, second_raw, third_raw]) is None
    assert first_chain_break([first_raw, second_raw]) is None


def test_manifest_runner_reports_agreement(tmp_path: Path):
    vectors = tmp_path / "vectors"
    vectors.mkdir()

    receipt = signed_receipt()
    (vectors / "one.jsonl").write_bytes(raw_json(receipt) + b"\n")
    manifest = {
        "suite": "test",
        "draft": "draft-test",
        "vectors": [
            {
                "file": "one.jsonl",
                "expect": {"sig_failures": [], "chain_break": None},
                "note": "valid",
            }
        ],
    }
    (tmp_path / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")

    report = verify_manifest(
        tmp_path,
        source_repository="example/vectors",
        source_commit="deadbeef",
    )

    assert report.all_agree is True
    assert report.vectors[0].status == "agree"
    assert verify_log(vectors / "one.jsonl").manifest_shape() == manifest["vectors"][0]["expect"]
