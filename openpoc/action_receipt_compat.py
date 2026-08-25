from __future__ import annotations

import argparse
import hashlib
import json
import re
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Iterable

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

LOWER_HEX_32 = re.compile(r"^[0-9a-f]{64}$")
LOWER_HEX_64 = re.compile(r"^[0-9a-f]{128}$")


@dataclass(frozen=True)
class SignatureFailure:
    line: int
    reason: str


@dataclass(frozen=True)
class LogVerification:
    signature_failures: tuple[SignatureFailure, ...]
    chain_break: int | None
    line_count: int

    @property
    def signature_failure_lines(self) -> tuple[int, ...]:
        return tuple(item.line for item in self.signature_failures)

    def manifest_shape(self) -> dict[str, Any]:
        return {
            "sig_failures": list(self.signature_failure_lines),
            "chain_break": self.chain_break,
        }


@dataclass(frozen=True)
class VectorResult:
    file: str
    note: str
    expected: dict[str, Any]
    observed: dict[str, Any] | None
    status: str
    error: str | None = None


@dataclass(frozen=True)
class CompatibilityReport:
    suite: str
    draft: str
    source_repository: str
    source_commit: str
    vectors: tuple[VectorResult, ...]

    @property
    def agree_count(self) -> int:
        return sum(item.status == "agree" for item in self.vectors)

    @property
    def disagree_count(self) -> int:
        return sum(item.status == "disagree" for item in self.vectors)

    @property
    def unsupported_count(self) -> int:
        return sum(item.status == "unsupported" for item in self.vectors)

    @property
    def all_agree(self) -> bool:
        return self.agree_count == len(self.vectors)


def _json_string(value: str) -> str:
    return json.dumps(value, ensure_ascii=False)


def canonical_json(value: Any) -> str:
    """Canonicalize the draft's signed `params` member.

    Object keys are ordered by Unicode code point, arrays preserve order, and
    non-integer JSON numbers are rejected instead of being guessed.
    """

    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        raise ValueError("non-integer number in signed members")
    if isinstance(value, str):
        return _json_string(value)
    if isinstance(value, list):
        return "[" + ",".join(canonical_json(item) for item in value) + "]"
    if isinstance(value, dict):
        if not all(isinstance(key, str) for key in value):
            raise ValueError("JSON object keys must be strings")
        return "{" + ",".join(
            f"{_json_string(key)}:{canonical_json(value[key])}"
            for key in sorted(value)
        ) + "}"
    raise ValueError(f"unsupported JSON type: {type(value).__name__}")


def signed_receipt_bytes(receipt: dict[str, Any]) -> bytes:
    """Build the fixed-order byte sequence covered by the Ed25519 signature."""

    parts = [
        f'"step_id":{_json_string(receipt["step_id"])}',
        f'"action_id":{_json_string(receipt["action_id"])}',
        f'"params":{canonical_json(receipt["params"])}',
        '"success":' + ("true" if receipt["success"] else "false"),
        f'"ts_ms":{receipt["ts_ms"]}',
    ]

    actor = receipt.get("actor")
    if actor is not None:
        parts.append(
            '"actor":{"agent":'
            + _json_string(actor["agent"])
            + ',"user":'
            + _json_string(actor["user"])
            + "}"
        )

    prev_hash = receipt.get("prev_hash")
    if prev_hash is not None:
        parts.append(f'"prev_hash":{_json_string(prev_hash)}')

    return ("{" + ",".join(parts) + "}").encode("utf-8")


def verify_receipt(receipt: dict[str, Any]) -> str | None:
    """Return None for a valid receipt, otherwise a stable failure reason."""

    try:
        if not isinstance(receipt.get("step_id"), str):
            return "step_id must be a string"
        if not isinstance(receipt.get("action_id"), str):
            return "action_id must be a string"
        if "params" not in receipt:
            return "params is required"
        if not isinstance(receipt.get("success"), bool):
            return "success must be a boolean"

        ts_ms = receipt.get("ts_ms")
        if not isinstance(ts_ms, int) or isinstance(ts_ms, bool) or ts_ms < 0:
            return "ts_ms must be a non-negative integer"

        actor = receipt.get("actor")
        if actor is not None:
            if (
                not isinstance(actor, dict)
                or not isinstance(actor.get("agent"), str)
                or not isinstance(actor.get("user"), str)
            ):
                return "malformed actor"

        prev_hash = receipt.get("prev_hash")
        if prev_hash is not None and not isinstance(prev_hash, str):
            return "prev_hash must be a string"

        public_key = receipt.get("public_key")
        signature = receipt.get("signature")
        if not isinstance(public_key, str) or LOWER_HEX_32.fullmatch(public_key) is None:
            return "public_key must be 32 bytes of lowercase hex"
        if not isinstance(signature, str) or LOWER_HEX_64.fullmatch(signature) is None:
            return "signature must be 64 bytes of lowercase hex"

        message = signed_receipt_bytes(receipt)
        key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_key))
        key.verify(bytes.fromhex(signature), message)
        return None
    except InvalidSignature:
        return "signature does not match"
    except (KeyError, TypeError, ValueError) as exc:
        return f"malformed receipt: {exc}"


def _nonblank_raw_lines(path: Path) -> list[bytes]:
    return [line for line in path.read_bytes().split(b"\n") if line.strip()]


def first_chain_break(raw_lines: Iterable[bytes]) -> int | None:
    """Return the 1-based first broken link.

    Links are checked against SHA-256 of the exact previous transmitted line
    bytes. The receipt is never re-serialized for chain validation.
    """

    previous_digest: str | None = None
    for index, raw_line in enumerate(raw_lines, start=1):
        try:
            receipt = json.loads(raw_line.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return index

        if not isinstance(receipt, dict):
            return index

        declared = receipt.get("prev_hash")
        if not isinstance(declared, str):
            declared = None

        if declared != previous_digest:
            return index

        previous_digest = hashlib.sha256(raw_line).hexdigest()

    return None


def verify_log(path: Path) -> LogVerification:
    raw_lines = _nonblank_raw_lines(path)
    failures: list[SignatureFailure] = []

    for index, raw_line in enumerate(raw_lines, start=1):
        try:
            parsed = json.loads(raw_line.decode("utf-8"))
            if not isinstance(parsed, dict):
                reason = "receipt must be a JSON object"
            else:
                reason = verify_receipt(parsed)
        except UnicodeDecodeError as exc:
            reason = f"UTF-8 decode error: {exc}"
        except json.JSONDecodeError as exc:
            reason = f"JSON parse error: {exc.msg}"

        if reason is not None:
            failures.append(SignatureFailure(index, reason))

    return LogVerification(
        signature_failures=tuple(failures),
        chain_break=first_chain_break(raw_lines),
        line_count=len(raw_lines),
    )


def verify_manifest(
    root: Path,
    *,
    source_repository: str,
    source_commit: str,
) -> CompatibilityReport:
    manifest = json.loads((root / "manifest.json").read_text(encoding="utf-8"))
    results: list[VectorResult] = []

    for vector in manifest["vectors"]:
        file_name = vector["file"]
        expected = vector["expect"]
        note = vector.get("note", "")
        path = root / "vectors" / file_name

        try:
            observed = verify_log(path).manifest_shape()
            status = "agree" if observed == expected else "disagree"
            error = None
        except (OSError, ValueError, TypeError, KeyError) as exc:
            observed = None
            status = "unsupported"
            error = str(exc)

        results.append(
            VectorResult(
                file=file_name,
                note=note,
                expected=expected,
                observed=observed,
                status=status,
                error=error,
            )
        )

    return CompatibilityReport(
        suite=manifest.get("suite", ""),
        draft=manifest.get("draft", ""),
        source_repository=source_repository,
        source_commit=source_commit,
        vectors=tuple(results),
    )


def _display_lines(lines: list[int] | tuple[int, ...] | None) -> str:
    if not lines:
        return "—"
    return ", ".join(str(line) for line in lines)


def _display_break(value: int | None) -> str:
    return "—" if value is None else str(value)


def render_markdown(report: CompatibilityReport) -> str:
    rows = []
    for item in report.vectors:
        observed = item.observed or {}
        rows.append(
            "| `{file}` | {expected_sig} | {observed_sig} | {expected_break} | "
            "{observed_break} | **{status}** |".format(
                file=item.file,
                expected_sig=_display_lines(item.expected.get("sig_failures")),
                observed_sig=_display_lines(observed.get("sig_failures")),
                expected_break=_display_break(item.expected.get("chain_break")),
                observed_break=_display_break(observed.get("chain_break")),
                status=item.status.upper(),
            )
        )

    return "\n".join(
        [
            "# Governex action-receipt compatibility report",
            "",
            f"- Upstream: `{report.source_repository}`",
            f"- Pinned commit: `{report.source_commit}`",
            f"- Draft profile: `{report.draft}`",
            "- Verifier: `openpoc/action_receipt_compat.py`",
            "- Upstream verifier execution: **disabled**; CI reads only the manifest and vector data.",
            "",
            "## Result",
            "",
            f"**{report.agree_count}/{len(report.vectors)} vectors agree; "
            f"{report.disagree_count} disagree; {report.unsupported_count} unsupported.**",
            "",
            "| Vector | Expected signature failures | Observed signature failures | "
            "Expected chain break | Observed chain break | Result |",
            "|---|---:|---:|---:|---:|---|",
            *rows,
            "",
            "## Boundary cases",
            "",
            "- `14-head-truncated.jsonl` verifies clean. This is expected: a self-anchored "
            "chain has no internal evidence that an omitted final record ever existed.",
            "- `18-tampered-extension.jsonl` keeps every signature valid while the chain "
            "breaks at line 2. The link covers the previous record's exact transmitted "
            "octets, including extension members outside the signed subset.",
            "",
            "## Method",
            "",
            "The T-Trace/OpenPoC verifier separately computes:",
            "",
            "1. the fixed-order signed receipt byte sequence;",
            "2. recursive canonicalization of `params` with integer-only numbers;",
            "3. Ed25519 signature validity and strict lowercase key/signature encoding;",
            "4. the first hash-chain break using SHA-256 of the previous raw JSONL line.",
            "",
            "The upstream repository is checked out at the pinned commit in CI. Its "
            "`verify.py` is not imported or executed.",
            "",
            "## Non-claims",
            "",
            "Agreement with the manifest is interoperability evidence only. It does not:",
            "",
            "- prove that the draft is correct or complete;",
            "- prove that every real-world action entered the receipt path;",
            "- turn a self-anchored chain into proof against head truncation;",
            "- constitute endorsement by the upstream authors.",
            "",
        ]
    )


def report_as_json(report: CompatibilityReport) -> dict[str, Any]:
    return {
        "suite": report.suite,
        "draft": report.draft,
        "source_repository": report.source_repository,
        "source_commit": report.source_commit,
        "summary": {
            "total": len(report.vectors),
            "agree": report.agree_count,
            "disagree": report.disagree_count,
            "unsupported": report.unsupported_count,
        },
        "vectors": [asdict(item) for item in report.vectors],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Check action-receipt vectors against a separate T-Trace/OpenPoC verifier."
    )
    parser.add_argument("--manifest-root", required=True, type=Path)
    parser.add_argument(
        "--source-repository",
        default="governex/agent-action-receipts-vectors",
    )
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--json-out", type=Path)
    parser.add_argument("--markdown-out", type=Path)
    args = parser.parse_args(argv)

    report = verify_manifest(
        args.manifest_root,
        source_repository=args.source_repository,
        source_commit=args.source_commit,
    )

    for item in report.vectors:
        observed = item.observed if item.observed is not None else {"error": item.error}
        print(f"{item.status.upper():11} {item.file}: {json.dumps(observed, sort_keys=True)}")

    print(
        f"\n{len(report.vectors)} vectors: {report.agree_count} agree, "
        f"{report.disagree_count} disagree, {report.unsupported_count} unsupported"
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
