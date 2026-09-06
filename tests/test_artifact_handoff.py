import copy
import hashlib
import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from openpoc.action_receipt_compat_v01 import signed_receipt_bytes
from openpoc.artifact_handoff_demo import (
    ARTIFACT, BASE_TIME, CORRELATION, TEST_SEEDS, encoded, make_context, make_manifest, make_receipt, run_demo,
)
from openpoc.verify_artifact_handoff import main, render_markdown, verify_directory
from ttrace.artifact_handoff import (
    HandoffValidationError, MAX_ARTIFACT_BYTES, MAX_METADATA_BYTES, MAX_TIME_MS, verify_artifact_handoff,
)

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def bundle():
    files = {"artifact.bin": ARTIFACT,
             "sender.jsonl": make_receipt("sender", ARTIFACT, ts_ms=BASE_TIME + 100),
             "receiver.jsonl": make_receipt("receiver", ARTIFACT, ts_ms=BASE_TIME + 1_000)}
    files["manifest.json"] = make_manifest(files)
    return files, make_context(files)


def verify(bundle):
    return verify_artifact_handoff(bundle[0], encoded(bundle[1]))


def change_receipt(bundle, role, mutate, *, resign=True, seed=None):
    files, context = bundle
    name = role + ".jsonl"
    old_hash = hashlib.sha256(files[name]).hexdigest()
    document = json.loads(files[name])
    mutate(document)
    if resign:
        key = Ed25519PrivateKey.from_private_bytes(seed or TEST_SEEDS[role])
        document["public_key"] = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
        document["signature"] = key.sign(signed_receipt_bytes(document)).hex()
    files[name] = json.dumps(document, separators=(",", ":")).encode() + b"\n"
    files["manifest.json"] = make_manifest(files)
    for observation in context["observations"]:
        if observation["receipt_sha256"] == old_hash:
            observation["receipt_sha256"] = hashlib.sha256(files[name]).hexdigest()


def policy_change(context, mutate):
    mutate(context["historical_policies"][0])
    mutate(context["current_policy"])


def key_event(bundle, kind, effective):
    files, context = bundle
    key = json.loads(files["sender.jsonl"])["public_key"]
    context["key_status"]["events"] = [{"public_key": key, "kind": kind, "effective_at_ms": effective}]


def test_matching_handoff_exposes_independent_dimensions(bundle):
    report = verify(bundle)
    assert report["handoff_at_cutoff"] == "supported-under-receiver-context"
    assert report["transport_integrity"] == "matches-declared-manifest"
    assert report["expected_artifact_binding"] == "match"
    assert report["global_capture_completeness"] == "unproven"
    assert report["cross_source"] == {"status": "consistent-in-supplied-snapshots",
        "matched_correlations": [CORRELATION], "missing_sides": [], "conflicting_digests": False, "excluded_sides": []}
    for role in ("sender", "receiver"):
        assert report["receipts"][role]["signature"] == "valid"
        assert report["receipts"][role]["historical_authority"] == "authorized-at-observation"
        assert report["receipts"][role]["current_authority"] == "authorized-for-current-policy"
    assert "not an independently proved" in render_markdown(report)


def test_actual_controlled_copy_and_separate_receiver_context(tmp_path):
    destination = tmp_path / "demo"
    result = run_demo(destination)
    assert result["artifact_bytes_equal"] is True
    assert result["external_pilot"] is False
    assert (destination / "sender/artifact.bin").read_bytes() == (destination / "receiver/artifact.bin").read_bytes()
    assert (destination / "sender/sender.jsonl").read_bytes() == (destination / "package/sender.jsonl").read_bytes()
    assert (destination / "receiver/receiver.jsonl").read_bytes() == (destination / "package/receiver.jsonl").read_bytes()
    assert json.loads((destination / "reviewer/report.json").read_bytes()) == verify_directory(destination / "package", destination / "reviewer/context.json")
    with pytest.raises(ValueError, match="must be new"):
        run_demo(destination)


def test_policy_and_key_rotation_preserve_history_without_current_authorization(bundle):
    _, context = bundle
    context["current_policy"]["epoch"] = 2
    for index, role in enumerate(("sender", "receiver"), 51):
        key = Ed25519PrivateKey.from_private_bytes(bytes([index]) * 32)
        context["current_policy"]["roles"][role]["public_key"] = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
    report = verify(bundle)
    assert report["handoff_at_cutoff"] == "supported-under-receiver-context"
    for item in report["receipts"].values():
        assert item["historical_authority"] == "authorized-at-observation"
        assert item["current_authority"] == "not-authorized-current-policy"


@pytest.mark.parametrize("kind", ["revoked", "compromised"])
def test_key_event_after_observation_preserves_prior_context_but_denies_current_use(bundle, kind):
    key_event(bundle, kind, BASE_TIME + 500)
    report = verify(bundle)
    assert report["receipts"]["sender"]["historical_authority"] == "authorized-at-observation"
    assert report["receipts"]["sender"]["current_authority"] == "not-authorized-key-event"
    assert report["handoff_at_cutoff"] == "supported-under-receiver-context"


@pytest.mark.parametrize("kind,expected", [("revoked", "not-authorized-revoked"), ("compromised", "indeterminate-after-compromise")])
def test_effective_key_event_at_observation_cannot_be_backdated_away(bundle, kind, expected):
    key_event(bundle, kind, BASE_TIME + 300)
    report = verify(bundle)
    assert report["receipts"]["sender"]["historical_authority"] == expected
    assert report["receipts"]["sender"]["current_authority"] == "not-authorized-key-event"
    assert report["handoff_at_cutoff"] == "insufficient-evidence"
    assert report["cross_source"]["status"] == "insufficient-authenticated-projection"


@pytest.mark.parametrize("position,historical", [(300, "not-authorized-at-observation"), (500, "authorized-at-observation")])
def test_key_expiry_uses_observation_and_exclusive_upper_bound(bundle, position, historical):
    policy_change(bundle[1], lambda policy: policy["roles"]["sender"].update(not_after_ms=BASE_TIME + position))
    report = verify(bundle)
    assert report["receipts"]["sender"]["historical_authority"] == historical
    assert report["receipts"]["sender"]["current_authority"] == "not-authorized-at-evaluation"


def test_policy_expiry_keeps_past_authority_separate(bundle):
    policy_change(bundle[1], lambda policy: policy.update(valid_until_ms=BASE_TIME + 2_000))
    report = verify(bundle)
    assert report["handoff_at_cutoff"] == "supported-under-receiver-context"
    assert report["receipts"]["receiver"]["current_authority"] == "not-authorized-at-evaluation"


def test_policy_not_yet_valid_at_observation_is_not_historical_authority(bundle):
    policy_change(bundle[1], lambda policy: policy.update(valid_from_ms=BASE_TIME + 500))
    report = verify(bundle)
    assert report["receipts"]["sender"]["historical_authority"] == "not-authorized-at-observation"


def test_missing_archive_does_not_inherit_current_policy(bundle):
    bundle[1]["historical_policies"] = []
    report = verify(bundle)
    assert report["receipts"]["sender"]["historical_authority"] == "insufficient-policy-archive"
    assert report["receipts"]["sender"]["current_authority"] == "authorized-for-current-policy"
    assert report["handoff_at_cutoff"] == "insufficient-evidence"


def test_missing_observation_does_not_use_signer_timestamp(bundle):
    bundle[1]["observations"].pop()
    report = verify(bundle)
    assert report["receipts"]["receiver"]["signature"] == "valid"
    assert report["receipts"]["receiver"]["historical_authority"] == "insufficient-trusted-observation"
    assert report["cross_source"]["missing_sides"] == []
    assert report["handoff_at_cutoff"] == "insufficient-evidence"


@pytest.mark.parametrize("field", ["current_policy", "key_status"])
@pytest.mark.parametrize("mode", ["missing", "stale", "future"])
def test_missing_stale_and_future_status_never_grant_current_authority(bundle, field, mode):
    context = bundle[1]
    if mode == "missing":
        context[field] = None
    elif mode == "stale":
        context[field]["next_update_ms"] = context["evaluation_time_ms"]
    else:
        context[field]["as_of_ms"] = context["evaluation_time_ms"] + 1
    report = verify(bundle)
    item = report["receipts"]["sender"]
    expected = "insufficient-fresh-current-policy" if field == "current_policy" else "insufficient-fresh-key-status"
    assert item["current_authority"] == expected
    if field == "key_status":
        assert item["historical_authority"] == "insufficient-fresh-key-status"
        assert report["handoff_at_cutoff"] == "insufficient-evidence"
    else:
        assert item["historical_authority"] == "authorized-at-observation"


@pytest.mark.parametrize("final,verdict,status", [(True, "violated-supplied-snapshot-contract", "violated"),
    (False, "insufficient-evidence", "insufficient-snapshot-finality")])
def test_missing_receiver_under_final_and_nonfinal_snapshots(bundle, final, verdict, status):
    files, context = bundle
    del files["receiver.jsonl"]
    files["manifest.json"] = make_manifest(files)
    context["expected"]["snapshots_final_at_cutoff"] = final
    report = verify(bundle)
    assert report["handoff_at_cutoff"] == verdict
    assert report["cross_source"]["status"] == status
    assert report["cross_source"]["missing_sides"] == ["receiver"]


def test_nonfinal_matching_snapshots_remain_insufficient(bundle):
    bundle[1]["expected"]["snapshots_final_at_cutoff"] = False
    report = verify(bundle)
    assert report["cross_source"]["matched_correlations"] == [CORRELATION]
    assert report["handoff_at_cutoff"] == "insufficient-evidence"


def test_delayed_receipt_does_not_repair_the_earlier_cutoff(bundle):
    bundle[1]["observations"][1]["observed_at_ms"] = BASE_TIME + 2_001
    report = verify(bundle)
    assert report["receipts"]["receiver"]["historical_authority"] == "authorized-at-observation"
    assert report["receipts"]["receiver"]["time_binding"] == "observed-after-cutoff"
    assert report["cross_source"]["excluded_sides"] == ["receiver"]
    assert report["handoff_at_cutoff"] == "violated-supplied-snapshot-contract"


def test_exact_cutoff_is_included(bundle):
    bundle[1]["observations"][1]["observed_at_ms"] = BASE_TIME + 2_000
    assert verify(bundle)["handoff_at_cutoff"] == "supported-under-receiver-context"


def test_receipt_clock_after_observation_is_contradictory_not_time_proof(bundle):
    change_receipt(bundle, "sender", lambda receipt: receipt.update(ts_ms=BASE_TIME + 301))
    report = verify(bundle)
    assert report["receipts"]["sender"]["historical_authority"] == "contradictory-observation-time"
    assert report["handoff_at_cutoff"] == "insufficient-evidence"


def test_receipt_before_window_is_excluded(bundle):
    change_receipt(bundle, "sender", lambda receipt: receipt.update(ts_ms=BASE_TIME - 1))
    report = verify(bundle)
    assert report["cross_source"]["excluded_sides"] == ["sender"]
    assert report["cross_source"]["missing_sides"] == ["sender"]


def test_valid_signature_over_conflicting_artifact_is_visible(bundle):
    change_receipt(bundle, "receiver", lambda receipt: receipt["params"].update(artifact_sha256="0" * 64))
    report = verify(bundle)
    assert report["receipts"]["receiver"]["signature"] == "valid"
    assert report["cross_source"]["conflicting_digests"] is True
    assert report["handoff_at_cutoff"] == "violated-expected-claim"


@pytest.mark.parametrize("change", ["success", "correlation", "size", "source"])
def test_signed_claim_mismatches_cannot_support_handoff(bundle, change):
    def mutate(receipt):
        if change == "success": receipt["success"] = False
        elif change == "correlation": receipt["params"]["correlation_id"] = "different"
        elif change == "size": receipt["params"]["artifact_bytes"] += 1
        else: receipt["params"]["source_id"] = "different-source"
    change_receipt(bundle, "receiver", mutate)
    report = verify(bundle)
    assert report["receipts"]["receiver"]["claim_binding"] == "mismatch"
    assert report["handoff_at_cutoff"] != "supported-under-receiver-context"


def test_untrusted_self_supplied_key_does_not_supply_role_authority(bundle):
    change_receipt(bundle, "sender", lambda receipt: None, seed=b"\x55" * 32)
    report = verify(bundle)
    assert report["receipts"]["sender"]["signature"] == "valid"
    assert report["receipts"]["sender"]["historical_authority"] == "not-authorized-role-binding"
    assert report["handoff_at_cutoff"] == "insufficient-evidence"


def test_invalid_signature_does_not_become_an_authenticated_conflict(bundle):
    change_receipt(bundle, "receiver", lambda receipt: receipt["params"].update(artifact_sha256="0" * 64), resign=False)
    report = verify(bundle)
    assert report["receipts"]["receiver"]["signature"] == "invalid"
    assert report["cross_source"]["conflicting_digests"] is False
    assert report["handoff_at_cutoff"] == "insufficient-evidence"


@pytest.mark.parametrize("field,value", [("seq", True), ("seq", 1), ("ts_ms", True), ("ts_ms", MAX_TIME_MS + 1),
    ("success", 1), ("public_key", "A" * 64), ("signature", "0" * 126), ("step_id", "non ascii \u03b1"),
    ("extra", "unsigned extension"), ("action_id", "unknown.action")])
def test_strict_receipt_boundaries(bundle, field, value):
    change_receipt(bundle, "sender", lambda receipt: receipt.update({field: value}), resign=False)
    with pytest.raises(HandoffValidationError): verify(bundle)


@pytest.mark.parametrize("field,value", [("policy_epoch", True), ("policy_epoch", 0), ("artifact_bytes", True),
    ("artifact_sha256", "g" * 64), ("profile", "unknown/v2"), ("role", "receiver"), ("extra", True)])
def test_strict_signed_parameter_boundaries(bundle, field, value):
    change_receipt(bundle, "sender", lambda receipt: receipt["params"].update({field: value}), resign=False)
    with pytest.raises(HandoffValidationError): verify(bundle)


@pytest.mark.parametrize("kind", ["epoch-conflict", "duplicate-epoch", "shared-key", "shared-source", "empty-policy", "empty-key", "duplicate-observation", "future-observation", "event-after-asof", "duplicate-event"])
def test_ambiguous_or_contradictory_context_is_rejected(bundle, kind):
    _, context = bundle
    if kind == "epoch-conflict": context["current_policy"]["valid_until_ms"] -= 1
    elif kind == "duplicate-epoch": context["historical_policies"].append(copy.deepcopy(context["historical_policies"][0]))
    elif kind == "shared-key": policy_change(context, lambda p: p["roles"]["receiver"].update(public_key=p["roles"]["sender"]["public_key"]))
    elif kind == "shared-source": context["expected"]["roles"]["receiver"] = context["expected"]["roles"]["sender"]
    elif kind == "empty-policy": policy_change(context, lambda p: p.update(valid_until_ms=p["valid_from_ms"]))
    elif kind == "empty-key": policy_change(context, lambda p: p["roles"]["sender"].update(not_after_ms=p["roles"]["sender"]["not_before_ms"]))
    elif kind == "duplicate-observation": context["observations"][1] = copy.deepcopy(context["observations"][0])
    elif kind == "future-observation": context["observations"][0]["observed_at_ms"] = context["evaluation_time_ms"] + 1
    elif kind == "event-after-asof": key_event(bundle, "revoked", context["key_status"]["as_of_ms"] + 1)
    else:
        key_event(bundle, "revoked", BASE_TIME)
        context["key_status"]["events"] *= 2
    with pytest.raises(HandoffValidationError): verify(bundle)


@pytest.mark.parametrize("raw,code", [(b'{"schema":1,"schema":2}', "duplicate-json-key"),
    (b'{"schema":NaN}', "invalid-number"), (b'{"schema":1e0}', "invalid-number"),
    (b'{"schema":1.0}', "invalid-number"), (b'{"schema":-1}', "invalid-integer"),
    (b'{"schema":9007199254740992}', "invalid-integer"), (b'\xff', "invalid-json"),
    (b'[' * 13 + b'0' + b']' * 13, "input-limit"), (b' ' * (MAX_METADATA_BYTES + 1), "input-limit")],
    ids=["duplicate-key", "nonfinite", "exponent", "fraction", "negative", "unsafe-integer", "invalid-utf8", "nesting-limit", "byte-limit"])
def test_strict_json_and_resource_limits(bundle, raw, code):
    with pytest.raises(HandoffValidationError) as error: verify_artifact_handoff(bundle[0], raw)
    assert error.value.code == code


@pytest.mark.parametrize("kind", ["extra-file", "missing-artifact", "raw-drift", "oversize-artifact", "crlf", "extra-line", "no-final-lf", "duplicate-id", "unknown-manifest-field", "wrong-context-artifact"])
def test_package_and_original_byte_boundaries(bundle, kind):
    files, context = bundle
    if kind == "wrong-context-artifact":
        context["expected"]["artifact_sha256"] = "0" * 64
        assert verify(bundle)["handoff_at_cutoff"] == "violated-expected-claim"
        return
    if kind == "extra-file": files["extra.txt"] = b"x"
    elif kind == "missing-artifact": del files["artifact.bin"]
    elif kind == "raw-drift": files["artifact.bin"] += b"!"
    elif kind == "oversize-artifact":
        files["artifact.bin"] = b"x" * (MAX_ARTIFACT_BYTES + 1)
        files["manifest.json"] = make_manifest(files)
    elif kind in ("crlf", "extra-line", "no-final-lf"):
        files["sender.jsonl"] = files["sender.jsonl"][:-1] + {"crlf": b"\r\n", "extra-line": b"\n\n", "no-final-lf": b""}[kind]
        files["manifest.json"] = make_manifest(files)
    elif kind == "duplicate-id":
        change_receipt(bundle, "receiver", lambda receipt: receipt.update(step_id="sender-step-001"))
    else:
        manifest = json.loads(files["manifest.json"])
        manifest["verified"] = True
        files["manifest.json"] = encoded(manifest)
    with pytest.raises(HandoffValidationError): verify(bundle)


def test_cli_reports_negative_evaluation_and_malformed_input_distinctly(tmp_path, capsys):
    root = tmp_path / "demo"
    run_demo(root)
    args = [str(root / "package"), "--receiver-context", str(root / "reviewer/context.json")]
    assert main(args) == 0
    assert json.loads(capsys.readouterr().out)["handoff_at_cutoff"] == "supported-under-receiver-context"
    assert main([*args, "--format", "markdown"]) == 0
    assert "## How to use this result" in capsys.readouterr().out
    inside = root / "package/context.json"
    inside.write_bytes((root / "reviewer/context.json").read_bytes())
    assert main([str(root / "package"), "--receiver-context", str(inside)]) == 2
    assert json.loads(capsys.readouterr().out)["error"]["code"] == "self-supplied-context"


def test_directory_rejects_symlink(tmp_path):
    root = tmp_path / "demo"
    run_demo(root)
    target = root / "package/artifact.bin"
    target.unlink()
    try: target.symlink_to(root / "sender/artifact.bin")
    except OSError: pytest.skip("platform does not allow creating symbolic links")
    with pytest.raises(HandoffValidationError) as error:
        verify_directory(root / "package", root / "reviewer/context.json")
    assert error.value.code == "invalid-filesystem-entry"


def test_frozen_corpus_covers_all_declared_cases_and_regenerates_exact_bytes(tmp_path):
    from openpoc.artifact_handoff_corpus import declared_cases, evaluate_corpus, generate_corpus
    frozen = ROOT / "examples/artifact-handoff-v0.1"
    report = evaluate_corpus(frozen)
    assert report["agree_count"] == report["case_count"] == 59
    assert {case["id"] for case in report["cases"]} == {case[0] for case in declared_cases()}
    regenerated = tmp_path / "regenerated"
    generate_corpus(regenerated)
    first = {path.relative_to(frozen).as_posix(): path.read_bytes() for path in frozen.rglob("*") if path.is_file()}
    second = {path.relative_to(regenerated).as_posix(): path.read_bytes() for path in regenerated.rglob("*") if path.is_file()}
    assert first == second


def test_public_api_export_is_the_actual_verifier():
    import ttrace
    assert ttrace.verify_artifact_handoff is verify_artifact_handoff
    assert ttrace.HandoffValidationError is HandoffValidationError
    assert len(ttrace.__all__) == len(set(ttrace.__all__))
    assert all(isinstance(name, str) for name in ttrace.__all__)


def test_committed_machine_and_human_reports_match_current_verification():
    frozen = ROOT / "examples/artifact-handoff-v0.1"
    manifest = json.loads((frozen / "corpus.json").read_bytes())
    case = next(item for item in manifest["cases"] if item["id"] == "matching")
    report = verify_directory(frozen / case["package"], frozen / case["context"])
    assert report == json.loads((ROOT / "docs/artifact-handoff-report.json").read_bytes())
    assert render_markdown(report) == (ROOT / "docs/artifact-handoff-report.md").read_text(encoding="utf-8")
