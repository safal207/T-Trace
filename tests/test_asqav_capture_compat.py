import base64
import hashlib
import json
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from openpoc.asqav_capture_compat import (
    VECTOR_NAMES,
    canonical_json,
    render_markdown,
    verify_suite,
    verify_vector,
)


def _signed_document(
    private_key: Ed25519PrivateKey,
    payload: dict,
    *,
    kid: str = "test-key",
) -> dict:
    signature = private_key.sign(canonical_json(payload).encode("utf-8"))
    return {
        "payload": payload,
        "signature": {
            "alg": "Ed25519",
            "kid": kid,
            "sig": base64.b64encode(signature).decode("ascii"),
        },
        "anchors": [],
    }


def _write_vector(root: Path, vector_name: str) -> None:
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key().public_bytes(
        Encoding.Raw,
        PublicFormat.Raw,
    )

    predecessor_payload = {
        "type": "protectmcp:decision",
        "issued_at": "2026-08-30T12:00:00+00:00",
        "issuer_id": "Asqav Ltd",
        "agent_id": "agt_test_001",
        "action_ref": "act_1",
        "payload_digest": {
            "hash": hashlib.sha256(b"").hexdigest(),
            "size": 0,
        },
        "policy_digest": f"sha256:{hashlib.sha256(b'').hexdigest()}",
        "previousReceiptHash": "0" * 64,
        "decision": "allow",
        "tool_name": "demo.action",
    }
    predecessor = _signed_document(private_key, predecessor_payload)

    receipt_payload = {
        **predecessor_payload,
        "action_ref": "act_3",
        "previousReceiptHash": hashlib.sha256(
            canonical_json(predecessor_payload).encode("utf-8")
        ).hexdigest(),
    }
    if vector_name == "asqav-15-unsigned-gap":
        receipt_payload["unsigned_gap"] = {
            "count": 2,
            "from": "2026-08-30T11:58:00+00:00",
            "to": "2026-08-30T11:59:30+00:00",
        }
    elif vector_name == "asqav-16-chain-emission-blocked":
        receipt_payload.update(
            {
                "type": "protectmcp:lifecycle",
                "decision": "deny",
                "reason": "chain_emission_blocked",
            }
        )

    receipt = _signed_document(private_key, receipt_payload)
    vector_root = root / vector_name
    vector_root.mkdir(parents=True)
    (vector_root / "predecessor.json").write_text(
        json.dumps(predecessor, indent=2) + "\n",
        encoding="utf-8",
    )
    (vector_root / "receipt.json").write_text(
        json.dumps(receipt, indent=2) + "\n",
        encoding="utf-8",
    )
    (vector_root / "jwks.json").write_text(
        json.dumps(
            {
                "keys": [
                    {
                        "kid": "test-key",
                        "issuer_id": "Asqav Ltd",
                        "alg": "Ed25519",
                        "status": "active",
                        "public_key": base64.b64encode(public_key).decode("ascii"),
                    }
                ]
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    (vector_root / "expected.json").write_text(
        json.dumps(
            {
                "format": "asqav-native",
                "outcome": "verified",
                "reason_code": "",
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )


def _write_suite(root: Path) -> None:
    for vector_name in VECTOR_NAMES:
        _write_vector(root, vector_name)


def test_all_three_vectors_agree_and_render_deterministically(tmp_path: Path) -> None:
    _write_suite(tmp_path)
    report = verify_suite(
        tmp_path,
        source_repository="example/asqav",
        source_commit="a" * 40,
    )

    assert report.all_agree is True
    assert report.agree_count == 3
    assert report.disagree_count == 0
    assert report.unsupported_count == 0

    markdown = render_markdown(report)
    assert "**3/3 vectors agree; 0 disagree; 0 unsupported.**" in markdown
    assert "silent without external ground truth" in markdown
    assert "signer outage window declared" in markdown
    assert "blocked emission interval detectable after resume" in markdown


def test_tampered_receipt_signature_fails_closed(tmp_path: Path) -> None:
    vector_name = "asqav-14-omitted-action-chain"
    _write_vector(tmp_path, vector_name)
    path = tmp_path / vector_name / "receipt.json"
    document = json.loads(path.read_text(encoding="utf-8"))
    document["payload"]["decision"] = "deny"
    path.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")

    observation = verify_vector(tmp_path, vector_name)

    assert observation.status == "unsupported"
    assert observation.local_outcome == "unverified"
    assert "signature does not match" in (observation.error or "")


def test_valid_signature_with_wrong_chain_link_fails_closed(tmp_path: Path) -> None:
    vector_name = "asqav-14-omitted-action-chain"
    _write_vector(tmp_path, vector_name)

    vector_root = tmp_path / vector_name
    receipt_path = vector_root / "receipt.json"
    jwks_path = vector_root / "jwks.json"
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    jwks = json.loads(jwks_path.read_text(encoding="utf-8"))
    jwks["keys"][0]["public_key"] = base64.b64encode(public_key).decode("ascii")
    jwks_path.write_text(json.dumps(jwks, indent=2) + "\n", encoding="utf-8")

    predecessor_path = vector_root / "predecessor.json"
    predecessor = json.loads(predecessor_path.read_text(encoding="utf-8"))
    predecessor["signature"]["sig"] = base64.b64encode(
        private_key.sign(canonical_json(predecessor["payload"]).encode("utf-8"))
    ).decode("ascii")
    predecessor_path.write_text(
        json.dumps(predecessor, indent=2) + "\n",
        encoding="utf-8",
    )

    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    receipt["payload"]["previousReceiptHash"] = "f" * 64
    receipt["signature"]["sig"] = base64.b64encode(
        private_key.sign(canonical_json(receipt["payload"]).encode("utf-8"))
    ).decode("ascii")
    receipt_path.write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")

    observation = verify_vector(tmp_path, vector_name)

    assert observation.status == "unsupported"
    assert "previousReceiptHash does not match" in (observation.error or "")


def test_unsigned_gap_does_not_upgrade_action_semantics(tmp_path: Path) -> None:
    vector_name = "asqav-15-unsigned-gap"
    _write_vector(tmp_path, vector_name)

    observation = verify_vector(tmp_path, vector_name)

    assert observation.status == "agree"
    assert observation.marker == "unsigned_gap(count=2)"
    assert (
        observation.claim_ceiling
        == "does_not_prove_unsigned_actions_were_policy_evaluated"
    )
    assert "effect_binding=indeterminate" in observation.ttrace_mapping


def test_blocked_vector_requires_signed_lifecycle_deny(tmp_path: Path) -> None:
    vector_name = "asqav-16-chain-emission-blocked"
    _write_vector(tmp_path, vector_name)

    vector_root = tmp_path / vector_name
    receipt_path = vector_root / "receipt.json"
    jwks_path = vector_root / "jwks.json"
    predecessor_path = vector_root / "predecessor.json"

    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    jwks = json.loads(jwks_path.read_text(encoding="utf-8"))
    jwks["keys"][0]["public_key"] = base64.b64encode(public_key).decode("ascii")
    jwks_path.write_text(json.dumps(jwks, indent=2) + "\n", encoding="utf-8")

    predecessor = json.loads(predecessor_path.read_text(encoding="utf-8"))
    predecessor["signature"]["sig"] = base64.b64encode(
        private_key.sign(canonical_json(predecessor["payload"]).encode("utf-8"))
    ).decode("ascii")
    predecessor_path.write_text(
        json.dumps(predecessor, indent=2) + "\n",
        encoding="utf-8",
    )

    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    receipt["payload"]["decision"] = "allow"
    receipt["signature"]["sig"] = base64.b64encode(
        private_key.sign(canonical_json(receipt["payload"]).encode("utf-8"))
    ).decode("ascii")
    receipt_path.write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")

    observation = verify_vector(tmp_path, vector_name)

    assert observation.status == "unsupported"
    assert "lifecycle marker is required" in (observation.error or "")
