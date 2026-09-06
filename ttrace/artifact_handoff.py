"""Bounded artifact handoff and temporal authority under receiver-selected context."""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from typing import Any

PROFILE = "ttrace.artifact-handoff/v1"
PACKAGE_SCHEMA = "ttrace.artifact-handoff-package/v1"
CONTEXT_SCHEMA = "ttrace.handoff-receiver-context/v1"
REPORT_SCHEMA = "ttrace.artifact-handoff-report/v1"
ROLES = ("sender", "receiver")
MAX_ARTIFACT_BYTES = 1_048_576
MAX_RECEIPT_BYTES = 16_384
MAX_METADATA_BYTES = 131_072
MAX_TIME_MS = 4_102_444_800_000
MAX_INTEGER = 9_007_199_254_740_991
ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,63}\Z")
POLICY_FIELDS = {"epoch", "valid_from_ms", "valid_until_ms", "roles"}
CONTEXT_FIELDS = {"schema", "expected", "evaluation_time_ms", "historical_policies",
                  "current_policy", "key_status", "observations"}


class HandoffValidationError(ValueError):
    def __init__(self, code: str, message: str):
        self.code = code
        super().__init__(message)


def _require(condition: bool, code: str, message: str) -> None:
    if not condition:
        raise HandoffValidationError(code, message)


def _fields(value: Any, fields: set[str], label: str) -> None:
    _require(isinstance(value, dict) and set(value) == fields, "invalid-fields", f"{label}: unexpected fields")


def _integer(value: Any, minimum: int, maximum: int, label: str) -> None:
    _require(type(value) is int and minimum <= value <= maximum, "invalid-integer", f"{label}: integer outside bounds")


def _identifier(value: Any, label: str) -> None:
    _require(isinstance(value, str) and ID.fullmatch(value) is not None, "invalid-identifier", f"{label}: invalid identifier")


def _hex(value: Any, width: int, label: str) -> None:
    _require(isinstance(value, str) and re.fullmatch(r"[0-9a-f]{" + str(width) + "}", value) is not None,
             "invalid-hex", f"{label}: expected lowercase hexadecimal bytes")


def _time(value: Any, label: str) -> None:
    _integer(value, 0, MAX_TIME_MS, label)


def parse_handoff_json(raw: bytes, label: str = "input", maximum: int = MAX_METADATA_BYTES) -> Any:
    _require(isinstance(raw, bytes) and len(raw) <= maximum, "input-limit", f"{label}: invalid bytes or size limit")

    def pairs(items):
        result = {}
        for key, value in items:
            _require(key not in result, "duplicate-json-key", f"{label}: duplicate JSON key")
            result[key] = value
        return result

    def reject_number(value):
        raise HandoffValidationError("invalid-number", f"{label}: fractional, exponent or nonfinite number")

    try:
        parsed = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs,
                            parse_float=reject_number, parse_constant=reject_number)
    except HandoffValidationError:
        raise
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise HandoffValidationError("invalid-json", f"{label}: invalid JSON") from exc

    def walk(value, depth=0):
        _require(depth <= 12, "input-limit", f"{label}: nesting limit")
        if type(value) is int:
            _integer(value, 0, MAX_INTEGER, label)
        elif isinstance(value, dict):
            for child in value.values():
                walk(child, depth + 1)
        elif isinstance(value, list):
            for child in value:
                walk(child, depth + 1)
    walk(parsed)
    return parsed


def _policy(policy: Any, *, current: bool = False) -> None:
    _fields(policy, POLICY_FIELDS | ({"as_of_ms", "next_update_ms"} if current else set()), "policy")
    _integer(policy["epoch"], 1, 2_147_483_647, "policy epoch")
    _time(policy["valid_from_ms"], "policy start")
    _time(policy["valid_until_ms"], "policy end")
    _require(policy["valid_from_ms"] < policy["valid_until_ms"], "invalid-interval", "empty policy interval")
    _fields(policy["roles"], set(ROLES), "policy roles")
    for role, binding in policy["roles"].items():
        _fields(binding, {"source_id", "public_key", "not_before_ms", "not_after_ms"}, "role binding")
        _identifier(binding["source_id"], "source ID")
        _hex(binding["public_key"], 64, "role key")
        _time(binding["not_before_ms"], "key start")
        _time(binding["not_after_ms"], "key end")
        _require(binding["not_before_ms"] < binding["not_after_ms"], "invalid-interval", "empty key interval")
    for field in ("source_id", "public_key"):
        _require(len({policy["roles"][role][field] for role in ROLES}) == 2,
                 "ambiguous-roles", "roles must use distinct sources and keys")
    if current:
        _freshness_fields(policy)


def _freshness_fields(value: dict) -> None:
    _time(value["as_of_ms"], "status as-of")
    _time(value["next_update_ms"], "status next update")
    _require(value["as_of_ms"] < value["next_update_ms"], "invalid-interval", "empty status interval")


def _context(raw: bytes) -> dict:
    context = parse_handoff_json(raw, "receiver context")
    _fields(context, CONTEXT_FIELDS, "receiver context")
    _require(context["schema"] == CONTEXT_SCHEMA, "unsupported-schema", "unsupported receiver context")
    expected = context["expected"]
    _fields(expected, {"correlation_id", "artifact_sha256", "artifact_bytes", "roles", "window_start_ms",
                       "audit_cutoff_ms", "snapshots_final_at_cutoff"}, "expected handoff")
    _identifier(expected["correlation_id"], "expected correlation")
    _hex(expected["artifact_sha256"], 64, "expected artifact")
    _integer(expected["artifact_bytes"], 1, MAX_ARTIFACT_BYTES, "expected artifact size")
    _fields(expected["roles"], set(ROLES), "expected roles")
    for source in expected["roles"].values():
        _identifier(source, "expected source")
    _require(len(set(expected["roles"].values())) == 2, "ambiguous-roles", "expected sources must differ")
    for value in (expected["window_start_ms"], expected["audit_cutoff_ms"], context["evaluation_time_ms"]):
        _time(value, "context time")
    _require(expected["window_start_ms"] <= expected["audit_cutoff_ms"] <= context["evaluation_time_ms"],
             "invalid-interval", "context window/cutoff/evaluation order")
    _require(type(expected["snapshots_final_at_cutoff"]) is bool, "invalid-boolean", "snapshot finality must be boolean")
    policies = context["historical_policies"]
    _require(isinstance(policies, list) and len(policies) <= 16, "input-limit", "historical policy array limit")
    epochs = set()
    for policy in policies:
        _policy(policy)
        _require(policy["epoch"] not in epochs, "ambiguous-policy", "duplicate historical policy epoch")
        epochs.add(policy["epoch"])
    if context["current_policy"] is not None:
        _policy(context["current_policy"], current=True)
        current_body = {key: context["current_policy"][key] for key in POLICY_FIELDS}
        for archived in policies:
            if archived["epoch"] == current_body["epoch"]:
                _require(archived == current_body, "policy-epoch-conflict", "same policy epoch has different content")
    status = context["key_status"]
    if status is not None:
        _fields(status, {"as_of_ms", "next_update_ms", "events"}, "key status")
        _freshness_fields(status)
        _require(isinstance(status["events"], list) and len(status["events"]) <= 32, "input-limit", "key-event array limit")
        keys = set()
        for event in status["events"]:
            _fields(event, {"public_key", "kind", "effective_at_ms"}, "key event")
            _hex(event["public_key"], 64, "event key")
            _require(event["kind"] in ("revoked", "compromised"), "invalid-event", "unsupported key event")
            _time(event["effective_at_ms"], "event time")
            _require(event["effective_at_ms"] <= status["as_of_ms"], "invalid-interval", "event after status as-of")
            _require(event["public_key"] not in keys, "ambiguous-key-event", "multiple events for one key")
            keys.add(event["public_key"])
    observations = context["observations"]
    _require(isinstance(observations, list) and len(observations) <= 2, "input-limit", "observation array limit")
    hashes = set()
    for observation in observations:
        _fields(observation, {"receipt_sha256", "observed_at_ms"}, "observation")
        _hex(observation["receipt_sha256"], 64, "observed digest")
        _time(observation["observed_at_ms"], "observation time")
        _require(observation["observed_at_ms"] <= context["evaluation_time_ms"], "invalid-interval", "observation after evaluation")
        _require(observation["receipt_sha256"] not in hashes, "ambiguous-observation", "duplicate receipt observation")
        hashes.add(observation["receipt_sha256"])
    return context


def _receipt(raw: bytes, role: str) -> dict:
    _require(raw.endswith(b"\n") and raw.count(b"\n") == 1 and b"\r" not in raw,
             "invalid-receipt-line", "receipt must be one original JSON line with final LF")
    receipt = parse_handoff_json(raw, role + " receipt", MAX_RECEIPT_BYTES)
    _fields(receipt, {"step_id", "action_id", "params", "success", "ts_ms", "seq", "public_key", "signature"}, "receipt")
    _identifier(receipt["step_id"], "step ID")
    _require(receipt["action_id"] == ("artifact.send" if role == "sender" else "artifact.receive"),
             "invalid-action", "receipt action does not match role")
    _require(type(receipt["success"]) is bool, "invalid-boolean", "success must be boolean")
    _time(receipt["ts_ms"], "receipt time")
    _integer(receipt["seq"], 0, 0, "genesis seq")
    _hex(receipt["public_key"], 64, "receipt key")
    _hex(receipt["signature"], 128, "receipt signature")
    params = receipt["params"]
    _fields(params, {"profile", "role", "source_id", "correlation_id", "artifact_sha256", "artifact_bytes", "policy_epoch"}, "signed params")
    _require(params["profile"] == PROFILE, "unsupported-schema", "unsupported signed profile")
    _require(params["role"] == role, "role-path-mismatch", "signed role does not match receipt path")
    _identifier(params["source_id"], "signed source")
    _identifier(params["correlation_id"], "signed correlation")
    _hex(params["artifact_sha256"], 64, "signed artifact")
    _integer(params["artifact_bytes"], 1, MAX_ARTIFACT_BYTES, "signed artifact size")
    _integer(params["policy_epoch"], 1, 2_147_483_647, "signed policy epoch")
    return receipt


def _fresh(value: dict | None, now: int) -> bool:
    return value is not None and value["as_of_ms"] <= now < value["next_update_ms"]


def _binding_matches(policy: dict, role: str, receipt: dict, expected: dict) -> bool:
    binding = policy["roles"][role]
    return (binding["public_key"] == receipt["public_key"]
            and binding["source_id"] == receipt["params"]["source_id"] == expected["roles"][role])


def _within(policy: dict, role: str, at: int) -> bool:
    binding = policy["roles"][role]
    return (policy["valid_from_ms"] <= at < policy["valid_until_ms"]
            and binding["not_before_ms"] <= at < binding["not_after_ms"])


def _event(context: dict, key: str, at: int) -> str | None:
    for event in context["key_status"]["events"]:
        if event["public_key"] == key and event["effective_at_ms"] <= at:
            return event["kind"]
    return None


def _historical(context: dict, role: str, receipt: dict, observed: int | None, signature: bool) -> str:
    if not signature:
        return "not-evaluable-signature"
    policy = next((item for item in context["historical_policies"] if item["epoch"] == receipt["params"]["policy_epoch"]), None)
    if policy is None:
        return "insufficient-policy-archive"
    if not _binding_matches(policy, role, receipt, context["expected"]):
        return "not-authorized-role-binding"
    if observed is None:
        return "insufficient-trusted-observation"
    if observed < receipt["ts_ms"]:
        return "contradictory-observation-time"
    if not _fresh(context["key_status"], context["evaluation_time_ms"]):
        return "insufficient-fresh-key-status"
    event = _event(context, receipt["public_key"], observed)
    if event == "compromised":
        return "indeterminate-after-compromise"
    if event == "revoked":
        return "not-authorized-revoked"
    if not _within(policy, role, observed):
        return "not-authorized-at-observation"
    return "authorized-at-observation"


def _current(context: dict, role: str, receipt: dict, signature: bool) -> str:
    if not signature:
        return "not-evaluable-signature"
    now = context["evaluation_time_ms"]
    policy = context["current_policy"]
    if not _fresh(policy, now):
        return "insufficient-fresh-current-policy"
    if not _fresh(context["key_status"], now):
        return "insufficient-fresh-key-status"
    if _event(context, receipt["public_key"], now) is not None:
        return "not-authorized-key-event"
    if policy["epoch"] != receipt["params"]["policy_epoch"] or not _binding_matches(policy, role, receipt, context["expected"]):
        return "not-authorized-current-policy"
    if not _within(policy, role, now):
        return "not-authorized-at-evaluation"
    return "authorized-for-current-policy"


def _iso(milliseconds: int) -> str:
    instant = datetime.fromtimestamp(milliseconds // 1000, timezone.utc).replace(microsecond=milliseconds % 1000 * 1000)
    return instant.isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _at_cutoff(context: dict, receipt: dict, details: dict) -> bool:
    expected = context["expected"]
    observed = details["observed_at_ms"]
    return (observed is not None and observed <= expected["audit_cutoff_ms"]
            and expected["window_start_ms"] <= receipt["ts_ms"] <= expected["audit_cutoff_ms"])


def _projection(context: dict, receipts: dict, details: dict) -> dict:
    from openpoc.verify_cross_source import assess_cross_source

    result = {"status": "insufficient-authenticated-projection", "matched_correlations": [],
              "missing_sides": [], "conflicting_digests": False, "excluded_sides": []}
    if any(details[role]["historical_authority"] != "authorized-at-observation" for role in receipts):
        return result
    expected = context["expected"]
    # A wrong correlation/source is a signed claim mismatch, not a different
    # expected handoff to silently compare. Artifact differences remain visible.
    if any(receipt["params"]["correlation_id"] != expected["correlation_id"]
           and _at_cutoff(context, receipt, details[role]) for role, receipt in receipts.items()):
        result["status"] = "not-evaluable-claim-binding"
        return result
    records = [{"id": receipt["step_id"], "type": "sense", "ts": _iso(receipt["ts_ms"]),
                "thread_id": receipt["params"]["source_id"], "source_id": receipt["params"]["source_id"],
                "side": role, "correlation_id": receipt["params"]["correlation_id"],
                "action_digest": "sha256:" + receipt["params"]["artifact_sha256"],
                "observed_at": _iso(details[role]["observed_at_ms"])} for role, receipt in receipts.items()]
    report = assess_cross_source(records, required_sides=expected["roles"], window_start=_iso(expected["window_start_ms"]),
                                 audit_cutoff=_iso(expected["audit_cutoff_ms"]),
                                 snapshots_final_at_cutoff=expected["snapshots_final_at_cutoff"])
    result.update(status=report.pairwise_consistency_status,
                  matched_correlations=list(report.matched_in_supplied_snapshots),
                  missing_sides=sorted({side for item in report.missing_counterparts for side in item["missing_sides"]}),
                  conflicting_digests=bool(report.digest_conflicts),
                  excluded_sides=sorted(item["side"] for item in report.out_of_scope_records))
    return result


def verify_artifact_handoff(files: dict[str, bytes], receiver_context: bytes) -> dict:
    """Verify immutable supplied bytes; context provenance remains the caller's responsibility."""
    _require(isinstance(files, dict) and {"manifest.json", "artifact.bin"} <= set(files)
             and set(files) <= {"manifest.json", "artifact.bin", "sender.jsonl", "receiver.jsonl"},
             "invalid-package-files", "unexpected or missing package files")
    _require(all(isinstance(raw, bytes) for raw in files.values()), "invalid-bytes", "package values must be original bytes")
    context = _context(receiver_context)
    manifest = parse_handoff_json(files["manifest.json"], "package manifest")
    _fields(manifest, {"schema", "profile", "correlation_id", "files"}, "package manifest")
    _require(manifest["schema"] == PACKAGE_SCHEMA and manifest["profile"] == PROFILE,
             "unsupported-schema", "unsupported package/profile")
    _identifier(manifest["correlation_id"], "manifest correlation")
    _fields(manifest["files"], set(files) - {"manifest.json"}, "manifest files")
    for name, entry in manifest["files"].items():
        _fields(entry, {"bytes", "sha256"}, "file entry")
        limit = MAX_ARTIFACT_BYTES if name == "artifact.bin" else MAX_RECEIPT_BYTES
        _integer(entry["bytes"], 1, limit, "file size")
        _hex(entry["sha256"], 64, "file digest")
        _require(len(files[name]) == entry["bytes"] and hashlib.sha256(files[name]).hexdigest() == entry["sha256"],
                 "integrity-mismatch", "file bytes do not match transport manifest")
    expected = context["expected"]
    artifact_hash = hashlib.sha256(files["artifact.bin"]).hexdigest()
    artifact_match = artifact_hash == expected["artifact_sha256"] and len(files["artifact.bin"]) == expected["artifact_bytes"]
    manifest_match = manifest["correlation_id"] == expected["correlation_id"]
    try:
        from openpoc.action_receipt_compat_v01 import verify_receipt
    except ImportError as exc:
        raise HandoffValidationError("missing-dependency", "install the receipts dependency extra") from exc
    receipts, details, seen_ids = {}, {}, set()
    observations = {item["receipt_sha256"]: item["observed_at_ms"] for item in context["observations"]}
    for role in ROLES:
        if role + ".jsonl" not in files:
            details[role] = {"present": False, "signature": "absent", "claim_binding": "absent",
                             "receipt_sha256": None, "observed_at_ms": None, "time_binding": "absent",
                             "historical_authority": "absent", "current_authority": "absent"}
            continue
        raw = files[role + ".jsonl"]
        receipt = _receipt(raw, role)
        _require(receipt["step_id"] not in seen_ids, "duplicate-step-id", "handoff receipt IDs must be distinct")
        seen_ids.add(receipt["step_id"])
        receipts[role] = receipt
        signature = verify_receipt(receipt) is None
        digest = hashlib.sha256(raw).hexdigest()
        observed = observations.get(digest)
        params = receipt["params"]
        claim = (manifest_match and artifact_match and params["correlation_id"] == expected["correlation_id"]
                 and params["source_id"] == expected["roles"][role] and params["artifact_sha256"] == artifact_hash
                 and params["artifact_bytes"] == len(files["artifact.bin"]) and receipt["success"] is True)
        details[role] = {"present": True, "signature": "valid" if signature else "invalid",
                         "claim_binding": "matches-expected-handoff" if claim else "mismatch",
                         "receipt_sha256": digest, "observed_at_ms": observed,
                         "time_binding": "missing" if observed is None else
                         "contradictory" if observed < receipt["ts_ms"] else
                         "observed-after-cutoff" if observed > expected["audit_cutoff_ms"] else "observed-by-cutoff",
                         "historical_authority": _historical(context, role, receipt, observed, signature),
                         "current_authority": _current(context, role, receipt, signature)}
    projection = _projection(context, receipts, details)
    authenticated_mismatch = any(details[role]["claim_binding"] == "mismatch" and
                                 details[role]["historical_authority"] == "authorized-at-observation" and
                                 _at_cutoff(context, receipt, details[role])
                                 for role, receipt in receipts.items())
    if not artifact_match or not manifest_match or authenticated_mismatch:
        handoff = "violated-expected-claim"
    elif projection["status"] == "violated":
        handoff = "violated-supplied-snapshot-contract"
    elif projection["status"] == "consistent-in-supplied-snapshots":
        handoff = "supported-under-receiver-context"
    else:
        handoff = "insufficient-evidence"
    return {"schema": REPORT_SCHEMA, "profile": PROFILE,
            "receiver_context_sha256": hashlib.sha256(receiver_context).hexdigest(),
            "package_manifest_sha256": hashlib.sha256(files["manifest.json"]).hexdigest(),
            "transport_integrity": "matches-declared-manifest",
            "expected_artifact_binding": "match" if artifact_match else "mismatch",
            "expected_correlation_binding": "match" if manifest_match else "mismatch",
            "evaluation_time_ms": context["evaluation_time_ms"], "audit_cutoff_ms": expected["audit_cutoff_ms"],
            "receipts": details, "cross_source": projection, "handoff_at_cutoff": handoff,
            "global_capture_completeness": "unproven",
            "trust_basis": "receiver independently accepts policy archives, status completeness, observations and finality",
            "historical_time_basis": "authority at accepted observation, not independently proved execution/signing time",
            "non_claims": ["real-world effect truth", "production non-bypassability", "automatic authority from bundled keys",
                           "permission to execute a new action", "external pilot or independent organizations"]}
