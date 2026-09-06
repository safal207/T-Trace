import hashlib
import json
import copy
import shutil
import subprocess
from pathlib import Path

import pytest

from openpoc import asqav_capture_compat as receipts
from openpoc import asqav_frozen_package as package
from test_asqav_capture_compat import _write_suite


def _entry(raw):
    return {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest(),
            "git_blob": hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()}


def _write_json(path, value):
    path.write_bytes(package._encoded(value))


@pytest.fixture(scope="module")
def baseline(tmp_path_factory):
    tmp_path = tmp_path_factory.mktemp("synthetic-asqav-baseline")
    upstream = tmp_path / "upstream"
    upstream.mkdir()
    _write_suite(upstream / package.PREFIX)
    (upstream / "LICENSE").write_text("Synthetic test fixture; not upstream Asqav data.\n", encoding="utf-8")
    manifest = []
    for vector in package.VECTORS:
        expected = json.loads((upstream / package.PREFIX / vector / "expected.json").read_bytes())
        manifest.append({"dir": vector, **expected, "notes": "Separate manifest narrative."})
    _write_json(upstream / package.PREFIX / "manifest.json", manifest)
    _write_json(upstream / package.PREFIX / "manifest.lock.json", {"files": [
        {"path": name[len(package.PREFIX):], **{key: value for key, value in
         _entry((upstream / name).read_bytes()).items() if key != "git_blob"}}
        for name in package.VECTOR_PATHS
    ]})

    def git(*args):
        return subprocess.check_output([
            "git", "-c", "user.name=T-Trace test", "-c", "user.email=test@example.invalid",
            "-c", "commit.gpgsign=false", "-c", "core.autocrlf=false", "-C", str(upstream), *args,
        ], stderr=subprocess.STDOUT).decode().strip()

    git("init")
    git("add", "--all")
    git("commit", "-m", "synthetic selected corpus")
    pins = {"schema": package.PIN_SCHEMA, "source_repository": "jagmarques/asqav-sdk",
            "source_commit": git("rev-parse", "HEAD"),
            "files": {name: _entry((upstream / name).read_bytes()) for name in package.SELECTED_PATHS}}
    pin_path = tmp_path / "receiver-pins.json"
    _write_json(pin_path, pins)
    destination = tmp_path / "frozen"
    package.export_package(upstream, destination, pin_path)
    return upstream, destination, pin_path, pins


@pytest.fixture
def corpus(tmp_path, baseline):
    upstream, destination, pin_path, pins = baseline
    copied_upstream = tmp_path / "upstream"
    copied_destination = tmp_path / "frozen"
    copied_pins = tmp_path / "receiver-pins.json"
    shutil.copytree(upstream, copied_upstream)
    shutil.copytree(destination, copied_destination)
    shutil.copyfile(pin_path, copied_pins)
    return copied_upstream, copied_destination, copied_pins, copy.deepcopy(pins)


def _repin(destination, pin_path, pins, relative):
    pins["files"][relative] = _entry((destination / relative).read_bytes())
    _write_json(pin_path, pins)
    (destination / "manifest.json").write_bytes(package._package_manifest(pins))


def test_export_and_offline_verification_preserve_the_existing_report(corpus, monkeypatch):
    upstream, destination, pin_path, pins = corpus
    original = receipts.report_as_json(receipts.verify_suite(
        upstream / package.PREFIX, source_repository=pins["source_repository"], source_commit=pins["source_commit"],
    ))
    monkeypatch.setattr(package, "_git", lambda *a: pytest.fail("offline verification invoked Git"))
    monkeypatch.setattr(receipts, "_load_object", lambda *a: pytest.fail("verified bytes reopened"))
    report = package.verify_package(destination, pin_path)
    assert report["status"] == "agree"
    assert report["compatibility"] == original
    assert report["source_binding"] == {
        "status": "matches-receiver-selected-pins", "raw_files_checked": 15,
        "manifest_records_checked": 3, "lock_records_checked": 12, "original_license_included": True,
        "manifest_comparison_fields": ["format", "outcome", "reason_code"],
    }
    assert report["trust_boundary"]["publisher_authentication"] == "not established by matching hashes alone"
    assert "not a production trust root" in package.render_markdown(report)
    for name in package.SELECTED_PATHS:
        assert (destination / name).read_bytes() == (upstream / name).read_bytes()


def test_export_reads_pinned_git_objects_despite_dirty_checkout(corpus, tmp_path):
    upstream, _, pin_path, _ = corpus
    (upstream / package.VECTOR_PATHS[0]).write_text("dirty working copy", encoding="utf-8")
    destination = tmp_path / "from-objects"
    package.export_package(upstream, destination, pin_path)
    assert package.verify_package(destination, pin_path)["status"] == "agree"


def test_export_never_overwrites_an_existing_destination(corpus):
    upstream, destination, pin_path, _ = corpus
    before = (destination / "manifest.json").read_bytes()
    with pytest.raises(package.SourcePackageError, match="must not already exist"):
        package.export_package(upstream, destination, pin_path)
    assert (destination / "manifest.json").read_bytes() == before


def test_unavailable_source_commit_leaves_no_destination(corpus, tmp_path):
    upstream, _, pin_path, pins = corpus
    pins["source_commit"] = "0" * 40
    _write_json(pin_path, pins)
    destination = tmp_path / "unavailable"
    with pytest.raises(package.SourcePackageError, match="Git revision"):
        package.export_package(upstream, destination, pin_path)
    assert not destination.exists()


def test_git_blob_pin_is_checked_separately(corpus):
    _, destination, pin_path, pins = corpus
    pins["files"]["LICENSE"]["git_blob"] = "0" * 40
    _write_json(pin_path, pins)
    (destination / "manifest.json").write_bytes(package._package_manifest(pins))
    with pytest.raises(package.SourcePackageError, match="Git blob mismatch"):
        package.verify_package(destination, pin_path)


@pytest.mark.parametrize("field,value", [
    ("schema", "unknown/v2"), ("source_commit", "x" * 40),
    ("source_repository", "another/repository"), ("extra", True),
])
def test_unknown_or_malformed_pin_fields_are_rejected(corpus, field, value):
    _, destination, pin_path, pins = corpus
    pins[field] = value
    _write_json(pin_path, pins)
    with pytest.raises(package.SourcePackageError):
        package.verify_package(destination, pin_path)


@pytest.mark.parametrize("field,value", [("bytes", True), ("bytes", 1.0), ("bytes", 0),
    ("bytes", package.MAX_FILE_BYTES + 1), ("sha256", "A" * 64), ("git_blob", "g" * 40), ("extra", 1)])
def test_strict_file_pin_fields(corpus, field, value):
    _, destination, pin_path, pins = corpus
    pins["files"]["LICENSE"][field] = value
    _write_json(pin_path, pins)
    with pytest.raises(package.SourcePackageError):
        package.verify_package(destination, pin_path)


@pytest.mark.parametrize("relative", ["../escape.json", "/absolute.json", "C:/escape.json", "verifier/../escape.json"])
def test_unselected_or_nonportable_paths_are_rejected(corpus, relative):
    _, destination, pin_path, pins = corpus
    pins["files"][relative] = pins["files"].pop("LICENSE")
    _write_json(pin_path, pins)
    with pytest.raises(package.SourcePackageError, match="exactly the 15"):
        package.verify_package(destination, pin_path)


def test_package_cannot_supply_its_own_receiver_pins(corpus):
    _, destination, pin_path, _ = corpus
    included = destination / "pins.json"
    included.write_bytes(pin_path.read_bytes())
    with pytest.raises(package.SourcePackageError, match="outside the package"):
        package.verify_package(destination, included)


@pytest.mark.parametrize("raw", [b'{"schema":1,"schema":2}', b'{"schema":NaN}', b'\xff', b'[' * 2000])
def test_duplicate_nonfinite_invalid_or_deep_json_fails(corpus, raw):
    _, destination, pin_path, _ = corpus
    pin_path.write_bytes(raw)
    with pytest.raises(package.SourcePackageError, match="invalid JSON"):
        package.verify_package(destination, pin_path)


def test_pin_metadata_has_a_size_limit(corpus):
    _, destination, pin_path, _ = corpus
    pin_path.write_bytes(b" " * (package.MAX_METADATA_BYTES + 1))
    with pytest.raises(package.SourcePackageError, match="byte limit"):
        package.verify_package(destination, pin_path)


def test_package_rejects_symbolic_links(corpus, tmp_path):
    _, destination, pin_path, _ = corpus
    target = destination / "LICENSE"
    outside = tmp_path / "outside-license"
    outside.write_bytes(target.read_bytes())
    target.unlink()
    try:
        target.symlink_to(outside)
    except OSError:
        pytest.skip("platform does not permit creating symbolic links")
    with pytest.raises(package.SourcePackageError, match="links are not supported"):
        package.verify_package(destination, pin_path)


@pytest.mark.parametrize("mode", ["extra-field", "self-repin", "whitespace", "missing-license", "extra-file", "extra-dir", "changed-bytes"])
def test_transport_drift_is_not_receipt_success(corpus, mode):
    _, destination, pin_path, _ = corpus
    manifest = destination / "manifest.json"
    if mode == "extra-field":
        value = json.loads(manifest.read_bytes())
        value["verified"] = True
        _write_json(manifest, value)
    elif mode == "self-repin":
        value = json.loads(manifest.read_bytes())
        value["selection"]["files"]["LICENSE"]["sha256"] = "0" * 64
        _write_json(manifest, value)
    elif mode == "whitespace":
        manifest.write_bytes(manifest.read_bytes() + b" ")
    elif mode == "missing-license":
        (destination / "LICENSE").unlink()
    elif mode == "extra-file":
        (destination / "extra.txt").write_text("unexpected", encoding="utf-8")
    elif mode == "extra-dir":
        (destination / "extra").mkdir()
    else:
        path = destination / package.VECTOR_PATHS[0]
        raw = path.read_bytes()
        path.write_bytes(b"!" + raw[1:])
    with pytest.raises(package.SourcePackageError):
        package.verify_package(destination, pin_path)


@pytest.mark.parametrize("target", ["manifest-mismatch", "manifest-duplicate", "lock-mismatch", "lock-duplicate", "lock-bool"])
def test_source_relationships_checked_even_against_newly_accepted_pins(corpus, target):
    _, destination, pin_path, pins = corpus
    relative = package.PREFIX + ("manifest.json" if target.startswith("manifest") else "manifest.lock.json")
    value = json.loads((destination / relative).read_bytes())
    if target == "manifest-mismatch":
        value[0]["outcome"] = "unsupported"
    elif target == "manifest-duplicate":
        value.append(value[0])
    elif target == "lock-mismatch":
        value["files"][0]["sha256"] = "0" * 64
    elif target == "lock-duplicate":
        value["files"].append(value["files"][0])
    else:
        value["files"][0]["bytes"] = True
    _write_json(destination / relative, value)
    _repin(destination, pin_path, pins, relative)
    with pytest.raises(package.SourcePackageError):
        package.verify_package(destination, pin_path)


def test_accepted_byte_pins_do_not_replace_signature_verification(corpus):
    _, destination, pin_path, pins = corpus
    relative = package.PREFIX + package.VECTORS[0] + "/receipt.json"
    document = json.loads((destination / relative).read_bytes())
    document["payload"]["decision"] = "deny"
    _write_json(destination / relative, document)
    _repin(destination, pin_path, pins, relative)
    lock_relative = package.PREFIX + "manifest.lock.json"
    lock = json.loads((destination / lock_relative).read_bytes())
    for record in lock["files"]:
        if record["path"] == relative[len(package.PREFIX):]:
            record.update({key: pins["files"][relative][key] for key in ("bytes", "sha256")})
    _write_json(destination / lock_relative, lock)
    _repin(destination, pin_path, pins, lock_relative)
    report = package.verify_package(destination, pin_path)
    assert report["source_binding"]["status"] == "matches-receiver-selected-pins"
    assert report["status"] == "not-agreed"
    assert report["compatibility"]["observations"][0]["local_outcome"] == "unverified"


def test_cli_outputs_machine_and_human_reports(corpus, capsys):
    _, destination, pin_path, _ = corpus
    args = ["verify", str(destination), "--trusted-pins", str(pin_path)]
    assert package.main(args) == 0
    assert json.loads(capsys.readouterr().out)["status"] == "agree"
    assert package.main([*args, "--format", "markdown"]) == 0
    assert "## Decision boundary" in capsys.readouterr().out
    (destination / "LICENSE").unlink()
    assert package.main(args) == 1
    assert json.loads(capsys.readouterr().out)["status"] == "error"
