from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


def canonical_json(value: Any) -> str:
    """Canonicalize the restricted JSON profile used by these exact vectors.

    Object keys are ordered by Unicode code point, arrays preserve order, and
    non-integer JSON numbers fail closed rather than being normalized by guess.
    """

    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, int) and not isinstance(value, bool):
        return str(value)
    if isinstance(value, float):
        raise ValueError("non-integer JSON number is outside the supported profile")
    if isinstance(value, str):
        return json.dumps(value, ensure_ascii=False)
    if isinstance(value, list):
        return "[" + ",".join(canonical_json(item) for item in value) + "]"
    if isinstance(value, dict):
        if not all(isinstance(key, str) for key in value):
            raise ValueError("JSON object keys must be strings")
        return "{" + ",".join(
            f"{json.dumps(key, ensure_ascii=False)}:{canonical_json(value[key])}"
            for key in sorted(value)
        ) + "}"
    raise ValueError(f"unsupported JSON type: {type(value).__name__}")


VECTOR_NAMES = (
    "asqav-14-omitted-action-chain",
    "asqav-15-unsigned-gap",
    "asqav-16-chain-emission-blocked",
)

SEMANTIC_CONTRACT: dict[str, dict[str, str]] = {
    "asqav-14-omitted-action-chain": {
        "marker_kind": "none",
        "observability": "silent_without_external_ground_truth",
        "claim_ceiling": "integrity_of_presented_receipts_only",
        "ttrace_mapping": (
            "trace_valid=true; capture_status=violated_under_fixture_truth; "
            "overall_assurance=insufficient"
        ),
    },
    "asqav-15-unsigned-gap": {
        "marker_kind": "unsigned_gap",
        "observability": "signer_outage_window_declared",
        "claim_ceiling": "does_not_prove_unsigned_actions_were_policy_evaluated",
        "ttrace_mapping": (
            "trace_valid=true; capture_status=partially_observable; "
            "effect_binding=indeterminate"
        ),
    },
    "asqav-16-chain-emission-blocked": {
        "marker_kind": "chain_emission_blocked",
        "observability": "blocked_emission_interval_detectable_after_resume",
        "claim_ceiling": (
            "recorded_fail_closed_recovery_event_not_deployment_non_bypassability"
        ),
        "ttrace_mapping": (
            "trace_valid=true; fail_closed_recovery_evidence=present; "
            "gate_non_bypassability=assumption"
        ),
    },
}


@dataclass(frozen=True)
class VectorObservation:
    vector: str
    expected_outcome: str
    local_outcome: str
    predecessor_signature: str
    receipt_signature: str
    chain_link: str
    marker: str
    observability: str
    claim_ceiling: str
    ttrace_mapping: str
    status: str
    error: str | None = None


@dataclass(frozen=True)
class CompatibilityReport:
    source_repository: str
    source_commit: str
    observations: tuple[VectorObservation, ...]

    @property
    def agree_count(self) -> int:
        return sum(item.status == "agree" for item in self.observations)

    @property
    def disagree_count(self) -> int:
        return sum(item.status == "disagree" for item in self.observations)

    @property
    def unsupported_count(self) -> int:
        return sum(item.status == "unsupported" for item in self.observations)

    @property
    def all_agree(self) -> bool:
        return self.agree_count == len(self.observations)


def _load_object(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path.name} must contain a JSON object")
    return value


def _payload_of(document: dict[str, Any]) -> dict[str, Any]:
    payload = document.get("payload")
    if isinstance(payload, dict):
        return payload
    return document


def _decode_b64(value: Any, *, field: str) -> bytes:
    if not isinstance(value, str):
        raise ValueError(f"{field} must be a base64 string")
    try:
        return base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError, TypeError) as exc:
        raise ValueError(f"{field} is not valid base64") from exc


def _resolve_key(
    document: dict[str, Any],
    jwks: dict[str, Any],
) -> Ed25519PublicKey:
    signature = document.get("signature")
    if not isinstance(signature, dict):
        raise ValueError("signature object is required")
    if signature.get("alg") != "Ed25519":
        raise ValueError("only Ed25519 vectors are supported")

    kid = signature.get("kid")
    entries = jwks.get("keys")
    if not isinstance(entries, list):
        raise ValueError("jwks.keys must be an array")

    matches = [
        entry
        for entry in entries
        if isinstance(entry, dict) and entry.get("kid") == kid
    ]
    if len(matches) != 1:
        raise ValueError(f"expected exactly one JWKS entry for kid {kid!r}")

    entry = matches[0]
    if entry.get("alg") != "Ed25519":
        raise ValueError("JWKS algorithm does not match Ed25519")
    if entry.get("status") != "active":
        raise ValueError("JWKS key is not active")
    if entry.get("issuer_id") != _payload_of(document).get("issuer_id"):
        raise ValueError("signed issuer does not match the resolved JWKS entry")

    public_key = _decode_b64(entry.get("public_key"), field="public_key")
    if len(public_key) != 32:
        raise ValueError("Ed25519 public key must be 32 bytes")
    return Ed25519PublicKey.from_public_bytes(public_key)


def _verify_signature(
    document: dict[str, Any],
    jwks: dict[str, Any],
) -> None:
    signature = document["signature"]
    encoded = _decode_b64(signature.get("sig"), field="signature.sig")
    if len(encoded) != 64:
        raise ValueError("Ed25519 signature must be 64 bytes")

    key = _resolve_key(document, jwks)
    message = canonical_json(_payload_of(document)).encode("utf-8")
    try:
        key.verify(encoded, message)
    except InvalidSignature as exc:
        raise ValueError("Ed25519 signature does not match canonical payload") from exc


def _verify_chain_link(
    predecessor: dict[str, Any],
    receipt: dict[str, Any],
) -> None:
    expected = hashlib.sha256(
        canonical_json(_payload_of(predecessor)).encode("utf-8")
    ).hexdigest()
    declared = _payload_of(receipt).get("previousReceiptHash")
    if declared != expected:
        raise ValueError(
            "receipt previousReceiptHash does not match the canonical predecessor payload"
        )


def _inspect_marker(
    vector_name: str,
    payload: dict[str, Any],
) -> str:
    if vector_name == "asqav-14-omitted-action-chain":
        if "unsigned_gap" in payload or payload.get("reason") == "chain_emission_blocked":
            raise ValueError("silent-omission vector carries an unexpected gap marker")
        return "none"

    if vector_name == "asqav-15-unsigned-gap":
        gap = payload.get("unsigned_gap")
        if not isinstance(gap, dict):
            raise ValueError("unsigned_gap object is required")
        count = gap.get("count")
        if not isinstance(count, int) or isinstance(count, bool) or count <= 0:
            raise ValueError("unsigned_gap.count must be a positive integer")
        if not isinstance(gap.get("from"), str) or not isinstance(gap.get("to"), str):
            raise ValueError("unsigned_gap requires string from/to bounds")
        return f"unsigned_gap(count={count})"

    if vector_name == "asqav-16-chain-emission-blocked":
        if (
            payload.get("type") != "protectmcp:lifecycle"
            or payload.get("decision") != "deny"
            or payload.get("reason") != "chain_emission_blocked"
        ):
            raise ValueError("fail-closed chain-emission lifecycle marker is required")
        return "chain_emission_blocked"

    raise ValueError(f"unsupported semantic vector: {vector_name}")


def _marker_agrees(marker: str, marker_kind: str) -> bool:
    if marker_kind == "none":
        return marker == "none"
    return marker == marker_kind or marker.startswith(f"{marker_kind}(")


def verify_vector(root: Path, vector_name: str) -> VectorObservation:
    semantic = SEMANTIC_CONTRACT[vector_name]

    try:
        vector_root = root / vector_name
        predecessor = _load_object(vector_root / "predecessor.json")
        receipt = _load_object(vector_root / "receipt.json")
        jwks = _load_object(vector_root / "jwks.json")
        expected = _load_object(vector_root / "expected.json")

        if expected.get("format") != "asqav-native":
            raise ValueError("expected.json does not declare asqav-native")
        expected_outcome = expected.get("outcome")
        if not isinstance(expected_outcome, str):
            raise ValueError("expected.json outcome must be a string")

        _verify_signature(predecessor, jwks)
        _verify_signature(receipt, jwks)
        _verify_chain_link(predecessor, receipt)
        marker = _inspect_marker(vector_name, _payload_of(receipt))

        local_outcome = "verified"
        status = (
            "agree"
            if expected_outcome == local_outcome
            and _marker_agrees(marker, semantic["marker_kind"])
            else "disagree"
        )
        return VectorObservation(
            vector=vector_name,
            expected_outcome=expected_outcome,
            local_outcome=local_outcome,
            predecessor_signature="valid",
            receipt_signature="valid",
            chain_link="valid",
            marker=marker,
            observability=semantic["observability"],
            claim_ceiling=semantic["claim_ceiling"],
            ttrace_mapping=semantic["ttrace_mapping"],
            status=status,
        )
    except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        return VectorObservation(
            vector=vector_name,
            expected_outcome="unknown",
            local_outcome="unverified",
            predecessor_signature="unknown",
            receipt_signature="unknown",
            chain_link="unknown",
            marker="unknown",
            observability=semantic["observability"],
            claim_ceiling=semantic["claim_ceiling"],
            ttrace_mapping=semantic["ttrace_mapping"],
            status="unsupported",
            error=str(exc),
        )


def verify_suite(
    root: Path,
    *,
    source_repository: str,
    source_commit: str,
) -> CompatibilityReport:
    return CompatibilityReport(
        source_repository=source_repository,
        source_commit=source_commit,
        observations=tuple(verify_vector(root, name) for name in VECTOR_NAMES),
    )


def report_as_json(report: CompatibilityReport) -> dict[str, Any]:
    return {
        "source_repository": report.source_repository,
        "source_commit": report.source_commit,
        "summary": {
            "total": len(report.observations),
            "agree": report.agree_count,
            "disagree": report.disagree_count,
            "unsupported": report.unsupported_count,
        },
        "observations": [asdict(item) for item in report.observations],
        "claim_boundary": {
            "independent_checks": [
                "Ed25519 signature over the canonical predecessor payload",
                "Ed25519 signature over the canonical receipt payload",
                "SHA-256 previousReceiptHash linkage",
                "presence and shape of the vector-specific observability marker",
            ],
            "not_proved": [
                "global capture completeness",
                "deployment-level non-bypassability",
                "policy evaluation of unsigned actions",
                "absence of effects outside the receipt path",
                "endorsement by the upstream author",
            ],
        },
    }


def _human(value: str) -> str:
    return value.replace("_", " ")


def render_markdown(report: CompatibilityReport) -> str:
    rows = []
    for item in report.observations:
        rows.append(
            "| `{vector}` | {crypto} | `{marker}` | {observable} | {ceiling} | "
            "**{status}** |".format(
                vector=item.vector,
                crypto=(
                    "signatures + link valid"
                    if item.local_outcome == "verified"
                    else f"unverified: {item.error}"
                ),
                marker=item.marker,
                observable=_human(item.observability),
                ceiling=_human(item.claim_ceiling),
                status=item.status.upper(),
            )
        )

    return "\n".join(
        [
            "# Asqav omission and recovery compatibility report",
            "",
            f"- Upstream: `{report.source_repository}`",
            f"- Pinned commit: `{report.source_commit}`",
            "- Vectors: `asqav-14`, `asqav-15`, `asqav-16`",
            "- Verifier: `openpoc/asqav_capture_compat.py`",
            "- Upstream verifier execution: **disabled**; only pinned vector data is read.",
            "",
            "## Result",
            "",
            f"**{report.agree_count}/{len(report.observations)} vectors agree; "
            f"{report.disagree_count} disagree; "
            f"{report.unsupported_count} unsupported.**",
            "",
            "| Vector | Independent crypto/link check | Marker | What becomes observable | "
            "Claim ceiling | Result |",
            "|---|---|---|---|---|---|",
            *rows,
            "",
            "## T-Trace / OpenPoC reading",
            "",
            "### 14 — omitted action, intact chain",
            "",
            "Both receipts and their link verify. The missing action leaves no in-band "
            "evidence because it never reached the signer. Under the vector's external "
            "fixture truth, capture is violated while record integrity still passes. "
            "This matches OpenPoC-01: `trace_valid=true` does not raise the capture "
            "claim above `overall_assurance=insufficient`.",
            "",
            "### 15 — signed `unsigned_gap`",
            "",
            "The next valid receipt carries a signed outage window. This makes a signer "
            "failure observable, but it does not identify the omitted actions or prove "
            "that they were policy-evaluated. The honest state is partial observability "
            "with effect binding left indeterminate.",
            "",
            "### 16 — `chain_emission_blocked` lifecycle receipt",
            "",
            "Emission failure causes a recorded deny, and the lifecycle receipt links "
            "into the chain after recovery. This is stronger than a silent gap because "
            "the blocked interval becomes inspectable. It is still not proof that every "
            "production effect path was non-bypassable; that remains a deployment "
            "assumption or a separately attested property.",
            "",
            "## Independent method",
            "",
            "For each pinned vector, this repository independently:",
            "",
            "1. resolves the exact active Ed25519 key by `kid` and signed issuer;",
            "2. canonicalizes only the signed payload with the repository's restricted "
            "deterministic JSON implementation;",
            "3. verifies predecessor and receipt signatures;",
            "4. re-derives `previousReceiptHash` from SHA-256 of the predecessor's "
            "canonical payload;",
            "5. checks the semantic marker without executing upstream code.",
            "",
            "## Non-claims",
            "",
            "This report is bounded interoperability and claim-ceiling evidence. It does "
            "not prove global capture completeness, deployment non-bypassability, "
            "policy evaluation of unsigned actions, absence of effects outside the "
            "receipt path, or endorsement in either direction.",
            "",
        ]
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Independently check Asqav omission/recovery vectors and map their "
            "claim ceilings to T-Trace/OpenPoC."
        )
    )
    parser.add_argument("--vectors-root", required=True, type=Path)
    parser.add_argument(
        "--source-repository",
        default="jagmarques/asqav-sdk",
    )
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--json-out", type=Path)
    parser.add_argument("--markdown-out", type=Path)
    args = parser.parse_args(argv)

    report = verify_suite(
        args.vectors_root,
        source_repository=args.source_repository,
        source_commit=args.source_commit,
    )

    for item in report.observations:
        detail = item.error or item.marker
        print(f"{item.status.upper():11} {item.vector}: {detail}")
    print(
        f"\n{len(report.observations)} vectors: {report.agree_count} agree, "
        f"{report.disagree_count} disagree, "
        f"{report.unsupported_count} unsupported"
    )

    if args.json_out is not None:
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        args.json_out.write_text(
            json.dumps(report_as_json(report), indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

    if args.markdown_out is not None:
        args.markdown_out.parent.mkdir(parents=True, exist_ok=True)
        args.markdown_out.write_text(render_markdown(report), encoding="utf-8")

    return 0 if report.all_agree else 1


if __name__ == "__main__":
    raise SystemExit(main())
