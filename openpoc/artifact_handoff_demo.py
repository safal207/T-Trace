"""Controlled file handoff; public deterministic test keys, never production keys."""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
from copy import deepcopy
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from ttrace.artifact_handoff import CONTEXT_SCHEMA, PACKAGE_SCHEMA, PROFILE, ROLES
from .action_receipt_compat_v01 import signed_receipt_bytes
from .verify_artifact_handoff import render_markdown, verify_directory

BASE_TIME = 1_788_694_200_000
ARTIFACT = b"T-Trace controlled handoff: public synthetic artifact, no external effect.\n"
CORRELATION = "controlled-handoff-001"
# Deliberately public fixture seeds. They establish no real-world identity.
TEST_SEEDS = {"sender": b"\x31" * 32, "receiver": b"\x32" * 32}


def encoded(value: dict) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")


def make_receipt(role: str, artifact: bytes, *, ts_ms: int, epoch: int = 1, **overrides) -> bytes:
    key = Ed25519PrivateKey.from_private_bytes(TEST_SEEDS[role])
    document = {
        "step_id": role + "-step-001", "action_id": "artifact.send" if role == "sender" else "artifact.receive",
        "params": {"profile": PROFILE, "role": role, "source_id": role + "-demo",
                   "correlation_id": CORRELATION, "artifact_sha256": hashlib.sha256(artifact).hexdigest(),
                   "artifact_bytes": len(artifact), "policy_epoch": epoch},
        "success": True, "ts_ms": ts_ms, "seq": 0,
        "public_key": key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex(),
    }
    document.update(overrides)
    document["signature"] = key.sign(signed_receipt_bytes(document)).hex()
    return json.dumps(document, separators=(",", ":"), ensure_ascii=True).encode("ascii") + b"\n"


def make_manifest(files: dict[str, bytes]) -> bytes:
    return encoded({"schema": PACKAGE_SCHEMA, "profile": PROFILE, "correlation_id": CORRELATION,
                    "files": {name: {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}
                              for name, raw in files.items() if name != "manifest.json"}})


def make_context(files: dict[str, bytes]) -> dict:
    roles = {}
    for role in ROLES:
        key = Ed25519PrivateKey.from_private_bytes(TEST_SEEDS[role])
        roles[role] = {"source_id": role + "-demo", "public_key": key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex(),
                       "not_before_ms": BASE_TIME, "not_after_ms": BASE_TIME + 100_000}
    policy = {"epoch": 1, "valid_from_ms": BASE_TIME, "valid_until_ms": BASE_TIME + 100_000, "roles": roles}
    current = {**deepcopy(policy), "as_of_ms": BASE_TIME + 3_000, "next_update_ms": BASE_TIME + 100_000}
    return {"schema": CONTEXT_SCHEMA,
            "expected": {"correlation_id": CORRELATION, "artifact_sha256": hashlib.sha256(files["artifact.bin"]).hexdigest(),
                         "artifact_bytes": len(files["artifact.bin"]), "roles": {role: role + "-demo" for role in ROLES},
                         "window_start_ms": BASE_TIME, "audit_cutoff_ms": BASE_TIME + 2_000, "snapshots_final_at_cutoff": True},
            "evaluation_time_ms": BASE_TIME + 4_000, "historical_policies": [policy], "current_policy": current,
            "key_status": {"as_of_ms": BASE_TIME + 3_000, "next_update_ms": BASE_TIME + 100_000, "events": []},
            "observations": [{"receipt_sha256": hashlib.sha256(files[role + ".jsonl"]).hexdigest(),
                              "observed_at_ms": BASE_TIME + (300 if role == "sender" else 1_300)}
                             for role in ROLES if role + ".jsonl" in files]}


def run_demo(destination: Path) -> dict:
    if destination.exists() or destination.is_symlink():
        raise ValueError("demo destination must be new; existing work is never overwritten")
    destination.mkdir(parents=True, exist_ok=False)
    sender = destination / "sender"
    receiver = destination / "receiver"
    package = destination / "package"
    reviewer = destination / "reviewer"
    for directory in (sender, receiver, package, reviewer):
        directory.mkdir()
    # An actual controlled copy happens; signatures cover bytes read separately
    # in the two roles, not merely two claims over one in-memory constant.
    (sender / "artifact.bin").write_bytes(ARTIFACT)
    sent = (sender / "artifact.bin").read_bytes()
    sender_receipt = make_receipt("sender", sent, ts_ms=BASE_TIME + 100)
    (sender / "sender.jsonl").write_bytes(sender_receipt)
    shutil.copyfile(sender / "artifact.bin", receiver / "artifact.bin")
    received = (receiver / "artifact.bin").read_bytes()
    receiver_receipt = make_receipt("receiver", received, ts_ms=BASE_TIME + 1_000)
    (receiver / "receiver.jsonl").write_bytes(receiver_receipt)
    files = {"artifact.bin": received, "sender.jsonl": sender_receipt, "receiver.jsonl": receiver_receipt}
    files["manifest.json"] = make_manifest(files)
    for name, raw in files.items():
        (package / name).write_bytes(raw)
    context = make_context(files)
    context_path = reviewer / "context.json"
    context_path.write_bytes(encoded(context))
    result = verify_directory(package, context_path)
    (reviewer / "report.json").write_bytes(encoded(result))
    (reviewer / "report.md").write_text(render_markdown(result), encoding="utf-8")
    # This note is outside the exact package; the verifier does not trust it as evidence.
    (destination / "DEMO-NOTICE.txt").write_text(
        "Controlled local file handoff with public deterministic TEST signing keys.\n"
        "All observation/status times are synthetic fixture values accepted only for this demo.\n"
        "No external timestamp authority, independent organization, or external pilot was used.\n"
        "Do not use these keys or this receiver context as production trust material.\n", encoding="utf-8",
    )
    return {"status": "controlled-demo-completed", "artifact_bytes_equal": sent == received,
            "artifact_sha256": hashlib.sha256(received).hexdigest(),
            "handoff_at_cutoff": result["handoff_at_cutoff"],
            "time_basis": "synthetic-fixture", "external_pilot": False}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("destination", type=Path)
    args = parser.parse_args(argv)
    try:
        result = run_demo(args.destination)
    except (OSError, ValueError) as exc:
        print(json.dumps({"status": "error", "error": str(exc)}))
        return 1
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
