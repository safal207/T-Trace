"""Generate/freeze declared handoff cases; expected outcomes are written by hand."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from ttrace.artifact_handoff import HandoffValidationError, verify_artifact_handoff
from .action_receipt_compat_v01 import signed_receipt_bytes
from .artifact_handoff_demo import ARTIFACT, BASE_TIME, TEST_SEEDS, encoded, make_context, make_manifest, make_receipt

CORPUS_SCHEMA = "ttrace.artifact-handoff-corpus/v1"


def _base():
    files = {"artifact.bin": ARTIFACT, "sender.jsonl": make_receipt("sender", ARTIFACT, ts_ms=BASE_TIME + 100),
             "receiver.jsonl": make_receipt("receiver", ARTIFACT, ts_ms=BASE_TIME + 1_000)}
    files["manifest.json"] = make_manifest(files)
    return files, make_context(files)


def _receipt_edit(files, context, role, mutate, *, resign=True, seed=None):
    name = role + ".jsonl"
    old = hashlib.sha256(files[name]).hexdigest()
    document = json.loads(files[name])
    mutate(document)
    if resign:
        key = Ed25519PrivateKey.from_private_bytes(seed or TEST_SEEDS[role])
        document["public_key"] = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
        document["signature"] = key.sign(signed_receipt_bytes(document)).hex()
    files[name] = json.dumps(document, separators=(",", ":")).encode() + b"\n"
    files["manifest.json"] = make_manifest(files)
    for observation in context["observations"]:
        if observation["receipt_sha256"] == old:
            observation["receipt_sha256"] = hashlib.sha256(files[name]).hexdigest()


def declared_cases():
    cases = []
    def add(name, change, expected=None, error=None):
        files, context = _base()
        raw_context = change(files, context)
        cases.append((name, files, raw_context if isinstance(raw_context, bytes) else encoded(context),
                      expected or {}, error))

    add("matching", lambda f, c: None, {"handoff_at_cutoff": "supported-under-receiver-context",
        "receipts.sender.historical_authority": "authorized-at-observation",
        "receipts.sender.current_authority": "authorized-for-current-policy", "cross_source.status": "consistent-in-supplied-snapshots"})
    def rotate(files, context):
        context["current_policy"]["epoch"] = 2
        for index, role in enumerate(("sender", "receiver"), 51):
            key = Ed25519PrivateKey.from_private_bytes(bytes([index]) * 32)
            context["current_policy"]["roles"][role]["public_key"] = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
    add("policy-key-rotation", rotate, {"handoff_at_cutoff": "supported-under-receiver-context",
        "receipts.sender.historical_authority": "authorized-at-observation", "receipts.sender.current_authority": "not-authorized-current-policy"})
    add("policy-epoch-rotation-same-key", lambda f, c: c["current_policy"].update(epoch=2), {
        "handoff_at_cutoff": "supported-under-receiver-context", "receipts.receiver.current_authority": "not-authorized-current-policy"})
    for kind in ("revoked", "compromised"):
        for position, suffix in ((300, "at-observation"), (500, "after-observation")):
            def event(files, context, kind=kind, position=position):
                context["key_status"]["events"] = [{"public_key": json.loads(files["sender.jsonl"])["public_key"],
                    "kind": kind, "effective_at_ms": BASE_TIME + position}]
            historical = "authorized-at-observation" if position == 500 else (
                "not-authorized-revoked" if kind == "revoked" else "indeterminate-after-compromise")
            add(kind + "-" + suffix, event, {"receipts.sender.historical_authority": historical,
                "receipts.sender.current_authority": "not-authorized-key-event",
                "handoff_at_cutoff": "supported-under-receiver-context" if position == 500 else "insufficient-evidence"})
    for position, suffix in ((300, "at-observation"), (500, "after-observation")):
        def expiry(files, context, position=position):
            for policy in (context["historical_policies"][0], context["current_policy"]):
                policy["roles"]["sender"]["not_after_ms"] = BASE_TIME + position
        add("key-expired-" + suffix, expiry, {"receipts.sender.historical_authority":
            "not-authorized-at-observation" if position == 300 else "authorized-at-observation",
            "receipts.sender.current_authority": "not-authorized-at-evaluation"})
    def policy_expiry(files, context):
        for policy in (context["historical_policies"][0], context["current_policy"]):
            policy["valid_until_ms"] = BASE_TIME + 2_000
    add("policy-expired-now", policy_expiry, {"handoff_at_cutoff": "supported-under-receiver-context",
        "receipts.receiver.current_authority": "not-authorized-at-evaluation"})
    add("missing-archive", lambda f, c: c.update(historical_policies=[]), {
        "handoff_at_cutoff": "insufficient-evidence", "receipts.sender.historical_authority": "insufficient-policy-archive",
        "receipts.sender.current_authority": "authorized-for-current-policy"})
    add("missing-observation", lambda f, c: c["observations"].pop(), {
        "handoff_at_cutoff": "insufficient-evidence", "receipts.receiver.historical_authority": "insufficient-trusted-observation",
        "cross_source.missing_sides": []})
    for field in ("current_policy", "key_status"):
        for mode in ("missing", "stale", "future"):
            def status(files, context, field=field, mode=mode):
                if mode == "missing": context[field] = None
                elif mode == "stale": context[field]["next_update_ms"] = context["evaluation_time_ms"]
                else: context[field]["as_of_ms"] = context["evaluation_time_ms"] + 1
            add(mode + "-" + field.replace("_", "-"), status, {
                "receipts.sender.current_authority": "insufficient-fresh-current-policy" if field == "current_policy" else "insufficient-fresh-key-status",
                "handoff_at_cutoff": "supported-under-receiver-context" if field == "current_policy" else "insufficient-evidence"})
    for final in (True, False):
        def missing(files, context, final=final):
            del files["receiver.jsonl"]
            files["manifest.json"] = make_manifest(files)
            context["expected"]["snapshots_final_at_cutoff"] = final
        add("missing-receiver-" + ("final" if final else "nonfinal"), missing, {
            "handoff_at_cutoff": "violated-supplied-snapshot-contract" if final else "insufficient-evidence",
            "cross_source.missing_sides": ["receiver"]})
    add("matching-nonfinal", lambda f, c: c["expected"].update(snapshots_final_at_cutoff=False), {
        "handoff_at_cutoff": "insufficient-evidence", "cross_source.status": "insufficient-snapshot-finality"})
    add("late-receiver", lambda f, c: c["observations"][1].update(observed_at_ms=BASE_TIME + 2_001), {
        "handoff_at_cutoff": "violated-supplied-snapshot-contract", "cross_source.excluded_sides": ["receiver"],
        "receipts.receiver.historical_authority": "authorized-at-observation"})
    add("receiver-at-cutoff", lambda f, c: c["observations"][1].update(observed_at_ms=BASE_TIME + 2_000), {
        "handoff_at_cutoff": "supported-under-receiver-context"})
    add("clock-contradiction", lambda f, c: _receipt_edit(f, c, "sender", lambda r: r.update(ts_ms=BASE_TIME + 301)), {
        "handoff_at_cutoff": "insufficient-evidence", "receipts.sender.historical_authority": "contradictory-observation-time"})
    add("before-window", lambda f, c: _receipt_edit(f, c, "sender", lambda r: r.update(ts_ms=BASE_TIME - 1)), {
        "handoff_at_cutoff": "violated-supplied-snapshot-contract", "cross_source.excluded_sides": ["sender"]})
    add("signed-conflict", lambda f, c: _receipt_edit(f, c, "receiver", lambda r: r["params"].update(artifact_sha256="0" * 64)), {
        "handoff_at_cutoff": "violated-expected-claim", "cross_source.conflicting_digests": True,
        "receipts.receiver.signature": "valid"})
    add("unsigned-conflict", lambda f, c: _receipt_edit(f, c, "receiver", lambda r: r["params"].update(artifact_sha256="0" * 64), resign=False), {
        "handoff_at_cutoff": "insufficient-evidence", "cross_source.conflicting_digests": False, "receipts.receiver.signature": "invalid"})
    add("wrong-correlation", lambda f, c: _receipt_edit(f, c, "sender", lambda r: r["params"].update(correlation_id="different")), {
        "handoff_at_cutoff": "violated-expected-claim", "cross_source.status": "not-evaluable-claim-binding"})
    add("declared-failure", lambda f, c: _receipt_edit(f, c, "receiver", lambda r: r.update(success=False)), {
        "handoff_at_cutoff": "violated-expected-claim", "receipts.receiver.signature": "valid"})
    add("untrusted-key", lambda f, c: _receipt_edit(f, c, "sender", lambda r: None, seed=b"\x55" * 32), {
        "handoff_at_cutoff": "insufficient-evidence", "receipts.sender.signature": "valid",
        "receipts.sender.historical_authority": "not-authorized-role-binding"})
    add("wrong-expected-artifact", lambda f, c: c["expected"].update(artifact_sha256="0" * 64), {
        "handoff_at_cutoff": "violated-expected-claim", "expected_artifact_binding": "mismatch"})
    add("bool-epoch", lambda f, c: _receipt_edit(f, c, "sender", lambda r: r["params"].update(policy_epoch=True)), error="invalid-integer")
    add("bool-finality", lambda f, c: c["expected"].update(snapshots_final_at_cutoff=1), error="invalid-boolean")
    add("policy-epoch-conflict", lambda f, c: c["current_policy"].update(valid_until_ms=BASE_TIME + 99_999), error="policy-epoch-conflict")
    add("duplicate-json-key", lambda f, c: b'{"schema":1,"schema":2}', error="duplicate-json-key")
    add("exponent-number", lambda f, c: b'{"schema":1e0}', error="invalid-number")
    add("nonfinite-number", lambda f, c: b'{"schema":NaN}', error="invalid-number")
    add("unsafe-integer", lambda f, c: b'{"schema":9007199254740992}', error="invalid-integer")
    add("unknown-context-version", lambda f, c: c.update(schema="unknown/v2"), error="unsupported-schema")
    add("raw-artifact-drift", lambda f, c: f.update({"artifact.bin": ARTIFACT + b"!"}), error="integrity-mismatch")
    return cases


def generate_corpus(destination: Path) -> dict:
    if destination.exists() or destination.is_symlink():
        raise ValueError("corpus destination must be new")
    destination.mkdir(parents=True, exist_ok=False)
    manifest = {"schema": CORPUS_SCHEMA, "time_basis": "synthetic-fixture", "keys": "public-test-keys-only", "cases": []}
    packages = {}
    for name, files, context, expected, error in declared_cases():
        # Deduplicate complete original-byte packages, not merely manifest hashes.
        identity = tuple(sorted(files.items()))
        package = packages.get(identity)
        if package is None:
            package = "packages/p" + str(len(packages) + 1).zfill(3)
            packages[identity] = package
            directory = destination / package
            directory.mkdir(parents=True)
            for filename, raw in files.items():
                (directory / filename).write_bytes(raw)
        context_path = "contexts/" + name + ".json"
        (destination / "contexts").mkdir(exist_ok=True)
        (destination / context_path).write_bytes(context)
        manifest["cases"].append({"id": name, "package": package, "context": context_path,
                                  "expected": expected, "expected_error_code": error})
    (destination / "corpus.json").write_bytes(encoded(manifest))
    return {"case_count": len(manifest["cases"]), "unique_packages": len(packages)}


def _contained(root: Path, relative: str) -> Path:
    path = (root / relative).resolve(strict=True)
    if not path.is_relative_to(root.resolve()):
        raise ValueError("corpus input escapes corpus root")
    return path


def evaluate_corpus(root: Path) -> dict:
    manifest = json.loads((root / "corpus.json").read_bytes())
    if manifest["schema"] != CORPUS_SCHEMA:
        raise ValueError("unsupported corpus schema")
    results = []
    for case in manifest["cases"]:
        package = _contained(root, case["package"])
        context = _contained(root, case["context"]).read_bytes()
        files = {path.name: path.read_bytes() for path in package.iterdir()}
        try:
            report = verify_artifact_handoff(files, context)
        except HandoffValidationError as exc:
            if exc.code != case["expected_error_code"]:
                raise ValueError(f"{case['id']}: unexpected error {exc.code}") from exc
            results.append({"id": case["id"], "status": "agree", "error_code": exc.code})
            continue
        if case["expected_error_code"] is not None:
            raise ValueError(f"{case['id']}: expected error was not raised")
        for path, expected in case["expected"].items():
            value = report
            for part in path.split("."):
                value = value[part]
            if json.dumps(value, sort_keys=True) != json.dumps(expected, sort_keys=True):
                raise ValueError(f"{case['id']}: {path} differs from declared expectation")
        if report["global_capture_completeness"] != "unproven":
            raise ValueError("corpus result exceeds capture claim boundary")
        results.append({"id": case["id"], "status": "agree", "handoff_at_cutoff": report["handoff_at_cutoff"]})
    return {"schema": CORPUS_SCHEMA, "case_count": len(results), "agree_count": len(results), "cases": results,
            "non_claim": "corpus agreement is not an external pilot or a proof for all possible inputs"}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("generate", "verify"))
    parser.add_argument("directory", type=Path)
    args = parser.parse_args(argv)
    try:
        result = generate_corpus(args.directory) if args.operation == "generate" else evaluate_corpus(args.directory)
    except (OSError, ValueError) as exc:
        print(json.dumps({"status": "error", "error": str(exc)}))
        return 1
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
