from __future__ import annotations

import argparse
import base64
import hashlib
import json
import re
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

UPSTREAM_COMMIT = "17c814f9e2e51f005faa707d44adec0316534da8"
FIRST_RECEIPT_SEED = "0" * 64
SELECTED_VECTOR_IDS = (
    "asqav-14-omitted-action-chain",
    "asqav-15-unsigned-gap",
    "asqav-16-chain-emission-blocked",
)
LOWER_HEX_40 = re.compile(r"^[0-9a-f]{40}$")
LOWER_HEX_64 = re.compile(r"^[0-9a-f]{64}$")


class CrosswalkError(ValueError):
    """Raised when a frozen input or semantic invariant does not match."""


@dataclass(frozen=True)
class VectorObservation:
    vector_id: str
    upstream_outcome: str
    signatures_valid: bool
    chain_valid: bool
    semantic: str
    observed_state: str
    claim_ceiling: str
    status: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class CrosswalkReport:
    schema: str
    source_repository: str
    source_commit: str
    pinned_file_count: int
    vectors: tuple[VectorObservation, ...]

    @property
    def agree_count(self) -> int:
        return sum(vector.status == "agree" for vector in self.vectors)

    @property
    def all_agree(self) -> bool:
        return self.agree_count == len(self.vectors)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": self.schema,
            "source_repository": self.source_repository,
            "source_commit": self.source_commit,
            "pinned_file_count": self.pinned_file_count,
            "agree_count": self.agree_count,
            "all_agree": self.all_agree,
            "vectors": [vector.to_dict() for vector in self.vectors],
            "non_claims": [
                "This is an independent verification of three frozen Asqav vectors, not the complete Asqav corpus.",
                "Wire-level receipt validity does not prove capture completeness.",
                "Absence from the selected two-receipt slice does not prove an action never reached any signer.",
                "A signed unsigned_gap marker does not independently prove a signer outage, policy evaluation, or execution.",
                "A blocked-emission receipt proves prevention only under a separately justified non-bypassable enforcement assumption.",
                "This report is interoperability evidence, not certification or endorsement.",
            ],
        }


def _load_json(path: Path) -> dict[str, Any]:
    try:
        parsed = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CrosswalkError(f"cannot load {path}: {exc}") from exc
    if not isinstance(parsed, dict):
        raise CrosswalkError(f"{path} must contain a JSON object")
    return parsed


def _reject_non_integer_numbers(value: Any, *, path: str = "$") -> None:
    if isinstance(value, float):
        raise CrosswalkError(
            f"{path} contains a non-integer number; selected-vector JCS "
            "canonicalization refuses to guess its representation"
        )
    if isinstance(value, list):
        for index, item in enumerate(value):
            _reject_non_integer_numbers(item, path=f"{path}[{index}]")
    elif isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise CrosswalkError(f"{path} contains a non-string object key")
            _reject_non_integer_numbers(item, path=f"{path}.{key}")


def canonical_payload(payload: dict[str, Any]) -> bytes:
    """Return JCS bytes for the selected ASCII/integer corpus.

    The frozen payloads contain objects, strings, booleans, nulls and integers.
    Floats are rejected rather than approximately canonicalized.
    """

    if not isinstance(payload, dict):
        raise CrosswalkError("signed payload must be a JSON object")
    _reject_non_integer_numbers(payload)
    return json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _git_blob_sha(raw: bytes) -> str:
    header = f"blob {len(raw)}\0".encode("ascii")
    return hashlib.sha1(header + raw).hexdigest()


def verify_frozen_files(root: Path, pins: dict[str, Any]) -> None:
    files = pins.get("files")
    if not isinstance(files, dict) or not files:
        raise CrosswalkError("pins.files must be a non-empty object")

    for relative_path, expected in sorted(files.items()):
        if not isinstance(relative_path, str) or not isinstance(expected, dict):
            raise CrosswalkError("malformed pins.files entry")
        path = root / relative_path
        try:
            raw = path.read_bytes()
        except OSError as exc:
            raise CrosswalkError(f"cannot read pinned file {relative_path}: {exc}") from exc

        expected_bytes = expected.get("bytes")
        expected_sha256 = expected.get("sha256")
        expected_blob = expected.get("git_blob")
        observed_sha256 = hashlib.sha256(raw).hexdigest()
        observed_blob = _git_blob_sha(raw)

        if len(raw) != expected_bytes:
            raise CrosswalkError(
                f"{relative_path}: expected {expected_bytes} bytes, got {len(raw)}"
            )
        if observed_sha256 != expected_sha256:
            raise CrosswalkError(
                f"{relative_path}: sha256 mismatch: {observed_sha256}"
            )
        if observed_blob != expected_blob:
            raise CrosswalkError(
                f"{relative_path}: git blob mismatch: {observed_blob}"
            )


def _resolve_key(jwks: dict[str, Any], *, kid: str, issuer_id: str) -> bytes:
    keys = jwks.get("keys")
    if not isinstance(keys, list):
        raise CrosswalkError("jwks.keys must be an array")

    matches = [
        entry
        for entry in keys
        if isinstance(entry, dict)
        and entry.get("kid") == kid
        and entry.get("issuer_id") == issuer_id
    ]
    if len(matches) != 1:
        raise CrosswalkError(
            f"expected exactly one key for kid={kid!r}, issuer={issuer_id!r}"
        )

    entry = matches[0]
    if entry.get("alg") != "Ed25519":
        raise CrosswalkError("resolved key is not Ed25519")
    if entry.get("status") != "active":
        raise CrosswalkError("resolved key is not active")

    encoded = entry.get("public_key")
    if not isinstance(encoded, str):
        raise CrosswalkError("resolved key has no public_key")
    try:
        raw = base64.b64decode(encoded, validate=True)
    except Exception as exc:
        raise CrosswalkError("public_key is not strict base64") from exc
    if len(raw) != 32:
        raise CrosswalkError(f"Ed25519 public key must be 32 bytes, got {len(raw)}")
    return raw


def verify_document_signature(document: dict[str, Any], jwks: dict[str, Any]) -> None:
    payload = document.get("payload")
    signature = document.get("signature")
    if not isinstance(payload, dict) or not isinstance(signature, dict):
        raise CrosswalkError("receipt must contain object payload and signature")

    if signature.get("alg") != "Ed25519":
        raise CrosswalkError("selected vector signature must use Ed25519")
    kid = signature.get("kid")
    issuer_id = payload.get("issuer_id")
    encoded_signature = signature.get("sig")
    if not isinstance(kid, str) or not isinstance(issuer_id, str):
        raise CrosswalkError("receipt is missing signed issuer or signature kid")
    if not isinstance(encoded_signature, str):
        raise CrosswalkError("receipt signature is missing")

    public_key = _resolve_key(jwks, kid=kid, issuer_id=issuer_id)
    try:
        signature_bytes = base64.b64decode(encoded_signature, validate=True)
    except Exception as exc:
        raise CrosswalkError("signature is not strict base64") from exc
    if len(signature_bytes) != 64:
        raise CrosswalkError(
            f"Ed25519 signature must be 64 bytes, got {len(signature_bytes)}"
        )

    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(
            signature_bytes,
            canonical_payload(payload),
        )
    except InvalidSignature as exc:
        raise CrosswalkError("signature does not match canonical payload") from exc


def verify_chain(predecessor: dict[str, Any], receipt: dict[str, Any]) -> None:
    predecessor_payload = predecessor.get("payload")
    receipt_payload = receipt.get("payload")
    if not isinstance(predecessor_payload, dict) or not isinstance(receipt_payload, dict):
        raise CrosswalkError("chain documents must contain object payloads")

    if predecessor_payload.get("previousReceiptHash") != FIRST_RECEIPT_SEED:
        raise CrosswalkError("selected predecessor is not the frozen genesis receipt")

    declared = receipt_payload.get("previousReceiptHash")
    expected = hashlib.sha256(canonical_payload(predecessor_payload)).hexdigest()
    if not isinstance(declared, str) or LOWER_HEX_64.fullmatch(declared) is None:
        raise CrosswalkError("successor previousReceiptHash is not lowercase sha256")
    if declared != expected:
        raise CrosswalkError(
            f"chain link mismatch: expected {expected}, got {declared}"
        )


def _verify_expected(expected: dict[str, Any]) -> str:
    if expected.get("format") != "asqav-native":
        raise CrosswalkError("selected vector format is not asqav-native")
    outcome = expected.get("outcome")
    if outcome != "verified":
        raise CrosswalkError(f"selected upstream outcome is {outcome!r}, not verified")
    if expected.get("reason_code") != "":
        raise CrosswalkError("verified vector must have an empty reason_code")
    return outcome


def _semantic_observation(
    vector: dict[str, Any],
    predecessor: dict[str, Any],
    receipt: dict[str, Any],
) -> str:
    vector_id = vector["id"]
    semantic = vector["semantic"]
    required = vector.get("required")
    if not isinstance(required, dict):
        raise CrosswalkError(f"{vector_id}: required semantic pins missing")

    predecessor_payload = predecessor["payload"]
    receipt_payload = receipt["payload"]

    if semantic == "silent-omission":
        if predecessor_payload.get("action_ref") != required.get(
            "predecessor_action_ref"
        ):
            raise CrosswalkError(f"{vector_id}: predecessor action_ref changed")
        if receipt_payload.get("action_ref") != required.get("receipt_action_ref"):
            raise CrosswalkError(f"{vector_id}: receipt action_ref changed")
        omitted = required.get("omitted_action_ref")
        if omitted in {
            predecessor_payload.get("action_ref"),
            receipt_payload.get("action_ref"),
        }:
            raise CrosswalkError(f"{vector_id}: omitted action is present")
        if "unsigned_gap" in receipt_payload or "reason" in receipt_payload:
            raise CrosswalkError(f"{vector_id}: silent omission gained an explicit marker")
        return "valid-selected-two-receipt-chain-without-act-2-receipt"

    if semantic == "signer-outage-observed":
        gap = receipt_payload.get("unsigned_gap")
        if not isinstance(gap, dict):
            raise CrosswalkError(f"{vector_id}: unsigned_gap missing")
        if gap.get("count") != required.get("gap_count"):
            raise CrosswalkError(f"{vector_id}: unsigned_gap count changed")
        if not isinstance(gap.get("from"), str) or not isinstance(gap.get("to"), str):
            raise CrosswalkError(f"{vector_id}: unsigned_gap interval malformed")
        return "verified-unsigned-gap-marker-without-policy-or-execution-claim"

    if semantic == "fail-closed-interval-observed":
        for key in ("type", "decision", "reason"):
            if receipt_payload.get(key) != required.get(key):
                raise CrosswalkError(f"{vector_id}: {key} changed")
        return "verified-lifecycle-denial-for-chain-emission-block"

    raise CrosswalkError(f"{vector_id}: unsupported semantic {semantic!r}")


def evaluate_bundle(root: Path) -> CrosswalkReport:
    pins = _load_json(root / "pins.json")
    if pins.get("schema") != "ttrace.asqav-selective-omission-pins/v1":
        raise CrosswalkError("unsupported pins schema")
    source_commit = pins.get("source_commit")
    if source_commit != UPSTREAM_COMMIT or not isinstance(source_commit, str):
        raise CrosswalkError("upstream commit pin changed")
    if LOWER_HEX_40.fullmatch(source_commit) is None:
        raise CrosswalkError("upstream commit is not a lowercase 40-hex SHA")

    verify_frozen_files(root, pins)

    jwks = _load_json(root / "jwks.json")
    vectors = pins.get("vectors")
    if not isinstance(vectors, list):
        raise CrosswalkError("pins.vectors must be an array")
    vector_ids = tuple(vector.get("id") for vector in vectors if isinstance(vector, dict))
    if vector_ids != SELECTED_VECTOR_IDS:
        raise CrosswalkError(
            f"selected vector order or membership changed: {vector_ids!r}"
        )

    observations: list[VectorObservation] = []
    for vector in vectors:
        if not isinstance(vector, dict):
            raise CrosswalkError("vector pin must be an object")
        vector_id = vector["id"]
        vector_root = root / vector_id
        expected = _load_json(vector_root / "expected.json")
        predecessor = _load_json(vector_root / "predecessor.json")
        receipt = _load_json(vector_root / "receipt.json")

        outcome = _verify_expected(expected)
        verify_document_signature(predecessor, jwks)
        verify_document_signature(receipt, jwks)
        verify_chain(predecessor, receipt)
        observed_state = _semantic_observation(vector, predecessor, receipt)

        claim_ceiling = vector.get("claim_ceiling")
        if not isinstance(claim_ceiling, str) or not claim_ceiling:
            raise CrosswalkError(f"{vector_id}: claim ceiling missing")

        observations.append(
            VectorObservation(
                vector_id=vector_id,
                upstream_outcome=outcome,
                signatures_valid=True,
                chain_valid=True,
                semantic=vector["semantic"],
                observed_state=observed_state,
                claim_ceiling=claim_ceiling,
                status="agree",
            )
        )

    return CrosswalkReport(
        schema="ttrace.asqav-selective-omission-crosswalk/v1",
        source_repository=pins["source_repository"],
        source_commit=source_commit,
        pinned_file_count=len(pins["files"]),
        vectors=tuple(observations),
    )


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Independently verify three frozen Asqav selective-omission vectors "
            "and preserve their distinct claim ceilings"
        )
    )
    parser.add_argument(
        "root",
        nargs="?",
        default="examples/asqav-selective-omission",
        help="directory containing pins.json and frozen selected vectors",
    )
    parser.add_argument(
        "--write",
        metavar="PATH",
        help="write the deterministic JSON report to PATH",
    )
    args = parser.parse_args()

    try:
        report = evaluate_bundle(Path(args.root))
    except CrosswalkError as exc:
        print(json.dumps({"status": "error", "error": str(exc)}, indent=2))
        return 1

    output = json.dumps(report.to_dict(), indent=2, sort_keys=True) + "\n"
    print(output, end="")
    if args.write:
        Path(args.write).write_text(output, encoding="utf-8")
    return 0 if report.all_agree else 1


if __name__ == "__main__":
    raise SystemExit(main())
