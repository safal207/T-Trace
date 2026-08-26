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
HEAD_DOMAIN = b"agent-receipt-head-v1:"

VECTOR_FIELDS = (
    "sig_failures",
    "chain_break",
    "step_id_repeat",
    "seq_gap",
    "seq_repeat",
)
VECTOR_DEFAULTS: dict[str, Any] = {
    "sig_failures": [],
    "chain_break": None,
    "step_id_repeat": None,
    "seq_gap": None,
    "seq_repeat": None,
}


@dataclass(frozen=True)
class SignatureFailure:
    line: int
    reason: str


@dataclass(frozen=True)
class LogVerification:
    signature_failures: tuple[SignatureFailure, ...]
    chain_break: int | None
    step_id_repeat: int | None
    seq_gap: int | None
    seq_repeat: int | None
    line_count: int

    @property
    def signature_failure_lines(self) -> tuple[int, ...]:
        return tuple(item.line for item in self.signature_failures)

    def manifest_shape(self) -> dict[str, Any]:
        return {
            "sig_failures": list(self.signature_failure_lines),
            "chain_break": self.chain_break,
            "step_id_repeat": self.step_id_repeat,
            "seq_gap": self.seq_gap,
            "seq_repeat": self.seq_repeat,
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
class HeadResult:
    file: str
    log: str
    note: str
    expected: str
    observed: str | None
    status: str
    error: str | None = None


@dataclass(frozen=True)
class CompatibilityReport:
    suite: str
    draft: str
    source_repository: str
    source_commit: str
    vectors: tuple[VectorResult, ...]
    head_vectors: tuple[HeadResult, ...]

    @property
    def check_count(self) -> int:
        return len(self.vectors) + len(self.head_vectors)

    @property
    def agree_count(self) -> int:
        return (
            sum(item.status == "agree" for item in self.vectors)
            + sum(item.status == "agree" for item in self.head_vectors)
        )

    @property
    def disagree_count(self) -> int:
        return (
            sum(item.status == "disagree" for item in self.vectors)
            + sum(item.status == "disagree" for item in self.head_vectors)
        )

    @property
    def unsupported_count(self) -> int:
        return (
            sum(item.status == "unsupported" for item in self.vectors)
            + sum(item.status == "unsupported" for item in self.head_vectors)
        )

    @property
    def all_agree(self) -> bool:
        return self.agree_count == self.check_count


def _json_string(value: str) -> str:
    return json.dumps(value, ensure_ascii=False)


def canonical_json(value: Any) -> str:
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
    """Build the -01 fixed-order signed byte sequence.

    The optional `seq` profile is covered immediately after `ts_ms`.
    """

    parts = [
        f'"step_id":{_json_string(receipt["step_id"])}',
        f'"action_id":{_json_string(receipt["action_id"])}',
        f'"params":{canonical_json(receipt["params"])}',
        '"success":' + ("true" if receipt["success"] else "false"),
        f'"ts_ms":{receipt["ts_ms"]}',
    ]

    seq = receipt.get("seq")
    if seq is not None:
        parts.append(f'"seq":{seq}')

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

        seq = receipt.get("seq")
        if seq is not None and (
            not isinstance(seq, int) or isinstance(seq, bool) or seq < 0
        ):
            return "seq must be a non-negative integer"

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


def profile_violations(
    raw_lines: Iterable[bytes],
) -> tuple[int | None, int | None, int | None]:
    """Return first repeated step id, seq gap, and seq repeat/regression.

    A log enters the optional seq profile when any receipt contains `seq`.
    Once active, every position must carry a signed non-negative integer,
    the first position must be 0, and each next position must be exactly +1.
    """

    parsed_records: list[dict[str, Any] | None] = []
    seen_step_ids: set[str] = set()
    step_id_repeat: int | None = None

    for index, raw_line in enumerate(raw_lines, start=1):
        try:
            parsed = json.loads(raw_line.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            parsed_records.append(None)
            continue

        if not isinstance(parsed, dict):
            parsed_records.append(None)
            continue

        parsed_records.append(parsed)
        step_id = parsed.get("step_id")
        if isinstance(step_id, str):
            if step_id in seen_step_ids and step_id_repeat is None:
                step_id_repeat = index
            seen_step_ids.add(step_id)

    seq_profile_active = any(
        record is not None and "seq" in record and record.get("seq") is not None
        for record in parsed_records
    )
    if not seq_profile_active:
        return step_id_repeat, None, None

    seq_gap: int | None = None
    seq_repeat: int | None = None
    previous: int | None = None

    for index, record in enumerate(parsed_records, start=1):
        value = None if record is None else record.get("seq")
        valid = isinstance(value, int) and not isinstance(value, bool) and value >= 0

        if not valid:
            if seq_gap is None:
                seq_gap = index
            previous = None
            continue

        if index == 1:
            if value != 0 and seq_gap is None:
                seq_gap = 1
        elif previous is None:
            if seq_gap is None:
                seq_gap = index
        elif value <= previous:
            if seq_repeat is None:
                seq_repeat = index
        elif value != previous + 1:
            if seq_gap is None:
                seq_gap = index

        previous = value

    return step_id_repeat, seq_gap, seq_repeat


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

    step_id_repeat, seq_gap, seq_repeat = profile_violations(raw_lines)
    return LogVerification(
        signature_failures=tuple(failures),
        chain_break=first_chain_break(raw_lines),
        step_id_repeat=step_id_repeat,
        seq_gap=seq_gap,
        seq_repeat=seq_repeat,
        line_count=len(raw_lines),
    )


def signed_head_bytes(assertion: dict[str, Any]) -> bytes:
    payload = (
        '{"chain_id":'
        + _json_string(assertion["chain_id"])
        + ',"count":'
        + str(assertion["count"])
        + ',"head_hash":'
        + _json_string(assertion["head_hash"])
        + ',"asserted_ts_ms":'
        + str(assertion["asserted_ts_ms"])
        + "}"
    )
    return HEAD_DOMAIN + payload.encode("utf-8")


def verify_head_assertion(assertion_path: Path, log_path: Path) -> str:
    """Return `match`, `mismatch`, or `invalid`."""

    try:
        assertion = json.loads(assertion_path.read_text(encoding="utf-8"))
        if not isinstance(assertion, dict):
            return "invalid"

        chain_id = assertion.get("chain_id")
        count = assertion.get("count")
        head_hash = assertion.get("head_hash")
        asserted_ts_ms = assertion.get("asserted_ts_ms")
        public_key = assertion.get("public_key")
        signature = assertion.get("signature")

        if (
            not isinstance(chain_id, str)
            or LOWER_HEX_32.fullmatch(chain_id) is None
            or not isinstance(count, int)
            or isinstance(count, bool)
            or count <= 0
            or not isinstance(head_hash, str)
            or LOWER_HEX_32.fullmatch(head_hash) is None
            or not isinstance(asserted_ts_ms, int)
            or isinstance(asserted_ts_ms, bool)
            or asserted_ts_ms < 0
            or not isinstance(public_key, str)
            or LOWER_HEX_32.fullmatch(public_key) is None
            or not isinstance(signature, str)
            or LOWER_HEX_64.fullmatch(signature) is None
        ):
            return "invalid"

        key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_key))
        key.verify(bytes.fromhex(signature), signed_head_bytes(assertion))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, InvalidSignature, ValueError, KeyError, TypeError):
        return "invalid"

    raw_lines = _nonblank_raw_lines(log_path)
    if not raw_lines:
        return "mismatch"

    observed_chain_id = hashlib.sha256(raw_lines[0]).hexdigest()
    observed_head_hash = hashlib.sha256(raw_lines[-1]).hexdigest()

    if (
        chain_id == observed_chain_id
        and count == len(raw_lines)
        and head_hash == observed_head_hash
    ):
        return "match"
    return "mismatch"


def _normalized_expectation(expected: dict[str, Any]) -> dict[str, Any]:
    return {field: expected.get(field, VECTOR_DEFAULTS[field]) for field in VECTOR_FIELDS}


def verify_manifest(
    root: Path,
    *,
    source_repository: str,
    source_commit: str,
) -> CompatibilityReport:
    manifest = json.loads((root / "manifest.json").read_text(encoding="utf-8"))
    vector_results: list[VectorResult] = []
    head_results: list[HeadResult] = []

    for vector in manifest["vectors"]:
        file_name = vector["file"]
        expected = _normalized_expectation(vector["expect"])
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

        vector_results.append(
            VectorResult(
                file=file_name,
                note=note,
                expected=expected,
                observed=observed,
                status=status,
                error=error,
            )
        )

    for head_vector in manifest.get("head_vectors", []):
        file_name = head_vector["file"]
        log_name = head_vector["log"]
        expected = head_vector["expect"]
        note = head_vector.get("note", "")
        try:
            observed = verify_head_assertion(
                root / "vectors" / file_name,
                root / "vectors" / log_name,
            )
            status = "agree" if observed == expected else "disagree"
            error = None
        except (OSError, ValueError, TypeError, KeyError) as exc:
            observed = None
            status = "unsupported"
            error = str(exc)

        head_results.append(
            HeadResult(
                file=file_name,
                log=log_name,
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
        vectors=tuple(vector_results),
        head_vectors=tuple(head_results),
    )


def _display_lines(value: list[int] | tuple[int, ...] | None) -> str:
    if not value:
        return "—"
    return ", ".join(str(item) for item in value)


def _display_line(value: int | None) -> str:
    return "—" if value is None else str(value)


def render_markdown(report: CompatibilityReport) -> str:
    vector_rows: list[str] = []
    for item in report.vectors:
        observed = item.observed or {}
        vector_rows.append(
            "| `{file}` | {esig} | {osig} | {ecb} | {ocb} | {esid} | {osid} | "
            "{egap} | {ogap} | {erep} | {orep} | **{status}** |".format(
                file=item.file,
                esig=_display_lines(item.expected.get("sig_failures")),
                osig=_display_lines(observed.get("sig_failures")),
                ecb=_display_line(item.expected.get("chain_break")),
                ocb=_display_line(observed.get("chain_break")),
                esid=_display_line(item.expected.get("step_id_repeat")),
                osid=_display_line(observed.get("step_id_repeat")),
                egap=_display_line(item.expected.get("seq_gap")),
                ogap=_display_line(observed.get("seq_gap")),
                erep=_display_line(item.expected.get("seq_repeat")),
                orep=_display_line(observed.get("seq_repeat")),
                status=item.status.upper(),
            )
        )

    head_rows = [
        "| `{file}` | `{log}` | `{expected}` | `{observed}` | **{status}** |".format(
            file=item.file,
            log=item.log,
            expected=item.expected,
            observed=item.observed or "—",
            status=item.status.upper(),
        )
        for item in report.head_vectors
    ]

    return "\n".join(
        [
            "# Governex action-receipt -01 compatibility report",
            "",
            f"- Upstream: `{report.source_repository}`",
            f"- Pinned commit: `{report.source_commit}`",
            f"- Draft profile: `{report.draft}`",
            "- Verifier: `openpoc/action_receipt_compat_v01.py`",
            "- Upstream verifier execution: **disabled**; CI reads only the pinned manifest and vector data.",
            "- Prior `01–18` / `-00` report: remains pinned and unchanged.",
            "",
            "## Result",
            "",
            f"**{report.agree_count}/{report.check_count} checks agree; "
            f"{report.disagree_count} disagree; {report.unsupported_count} unsupported.**",
            "",
            "### Receipt-log vectors",
            "",
            "| Vector | Exp. sig fail | Obs. sig fail | Exp. chain | Obs. chain | "
            "Exp. step repeat | Obs. step repeat | Exp. seq gap | Obs. seq gap | "
            "Exp. seq repeat | Obs. seq repeat | Result |",
            "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---|",
            *vector_rows,
            "",
            "### Signed head-assertion checks",
            "",
            "| Assertion | Log | Expected | Observed | Result |",
            "|---|---|---|---|---|",
            *head_rows,
            "",
            "## Capture-side reading",
            "",
            "- `19-replayed-step-id` isolates semantic record repetition: signatures and "
            "raw-octet linkage remain valid, while repeated `step_id` is rejected.",
            "- `20-seq-gap` and `21-seq-repeat` distinguish a missing signed position "
            "from a reused/regressed signed position inside the optional per-chain sequence profile.",
            "- `30-head-assertion.json` detects presentation of the truncated vector relative "
            "to a particular signed external head state.",
            "",
            "These mechanisms separate record repetition, recorder-issued positional anomalies, "
            "and head truncation. They do **not** by themselves prove that every real effect was "
            "captured. In particular:",
            "",
            "- a repeated real-world effect with a fresh `step_id` and the next valid `seq` remains "
            "record-valid unless a stable effect identity, authorization nonce, request digest, "
            "or idempotency binding is also signed;",
            "- a `seq` gap proves a gap in the recorder's signed numbering, not an unrecorded effect, "
            "unless sequence allocation is itself non-bypassable and occurs before the effect;",
            "- a head assertion proves consistency against that assertion; preventing equivocation "
            "between multiple valid assertions still requires witness, gossip, transparency, or "
            "another monotonic external state.",
            "",
            "## Non-claims",
            "",
            "Agreement is interoperability evidence only. It does not:",
            "",
            "- prove the draft correct or complete;",
            "- prove real-world capture completeness;",
            "- prove that the head signer cannot equivocate;",
            "- turn `step_id` or `seq` into effect-level anti-replay binding;",
            "- constitute endorsement in either direction.",
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
            "total": report.check_count,
            "agree": report.agree_count,
            "disagree": report.disagree_count,
            "unsupported": report.unsupported_count,
        },
        "vectors": [asdict(item) for item in report.vectors],
        "head_vectors": [asdict(item) for item in report.head_vectors],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Check Governex -01 action-receipt vectors with a separate T-Trace/OpenPoC verifier."
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
    for item in report.head_vectors:
        observed = item.observed if item.observed is not None else item.error
        print(
            f"{item.status.upper():11} {item.file} vs {item.log}: "
            f"{json.dumps(observed)}"
        )

    print(
        f"\n{report.check_count} checks: {report.agree_count} agree, "
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
