#!/usr/bin/env bash
set -Eeuo pipefail
umask 077
MATH_STARTED_AT="$(date +%s)"

# Run only in an unprivileged, disposable Linux environment.  Installation and
# Mathlib cache preparation use trusted pinned code.  The submitted OAI proof
# is compiled only by Comparator, with real Landrun and the syscall guard.
MATH_RUN_ROOT="${1:?Usage: run_math_pilot_156.sh /absolute/new/run-directory}"
case "$MATH_RUN_ROOT" in /*) ;; *) printf '%s\n' 'Absolute run directory required' >&2; exit 2 ;; esac
MATH_REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
MATH_RUNNER_HOME="${HOME:?Runner home must already be set}"
MATH_RUN_ROOT="$(realpath -m -- "$MATH_RUN_ROOT")"
if [[ -e "$MATH_RUN_ROOT" || "$MATH_RUN_ROOT" == "$MATH_REPO_ROOT" || "$MATH_RUN_ROOT" == "$MATH_REPO_ROOT/"* ]]; then
  printf '%s\n' 'Run directory must be new and outside the T-Trace checkout' >&2
  exit 2
fi
mkdir -p "$MATH_RUN_ROOT/evidence" "$MATH_RUN_ROOT/tools" "$MATH_RUN_ROOT/downloads"
MATH_EVIDENCE="$MATH_RUN_ROOT/evidence"
MATH_PHASE=preflight
MATH_PROOF_STATUS=NOT_ESTABLISHED
MATH_PROOF_STARTED=0
MATH_LOG_PID=
MATH_COMMIT=adc7f1241b42e322a6451854ab7e4b4c146bf78a
MATH_LANDRUN_SHA=811cfff51ceaf3d9843708aa6d22e9b84ccac8b4
MATH_COMPARATOR_SHA=d03acab154d269c06e60e4de7e4cc85deebff94b
MATH_EXPORTER_SHA=076e8e57707e813375e8f9da8bf989799ace9680
MATH_LEAN_SHA=47bf4bbd78f70c2e9670598ab7124d92b6efb7330ff33e5fbb4030f6fd72e4e4
MATH_GO_SHA=63d339f0da5ab53635a56f2490a7984dfe12dfcff22ad749f63edaf590168445
MATH_TOOL_PATH="$MATH_RUN_ROOT/tools/lean-4.34.1-linux/bin:$MATH_RUN_ROOT/tools/go/bin:/usr/bin:/bin"

finish() {
  local math_exit="$?"
  trap - EXIT
  python3 - "$MATH_EVIDENCE" "$MATH_PHASE" "$math_exit" "$MATH_PROOF_STATUS" "$MATH_REPO_ROOT" "$MATH_PROOF_STARTED" <<'PY'
import datetime, json, pathlib, subprocess, sys
out, phase, code, status, repo, proof_started = sys.argv[1:]
out = pathlib.Path(out)
receipt = {}
receipt_path = out / 'proof-run/receipt.json'
if receipt_path.is_file(): receipt = json.loads(receipt_path.read_text())
head = subprocess.run(['git', '-C', repo, 'rev-parse', 'HEAD'], capture_output=True, text=True).stdout.strip()
report = {
    'schema': 'ttrace.math-pilot.hosted-check/v1',
    'ended_at': datetime.datetime.now(datetime.timezone.utc).isoformat(),
    'ttrace_commit': head,
    'source_commit': 'adc7f1241b42e322a6451854ab7e4b4c146bf78a',
    'selected_theorems': ['OAI.BorsukNine.main_theorem'],
    'excluded_targets': ['OAI.BorsukNine.euclidean_nine_counterexample'],
    'phase': phase, 'runner_exit_code': int(code),
    'comparator_semantic_status': status if int(code) == 0 else 'NOT_ESTABLISHED',
    'selected_proof_execution_status': receipt.get('execution_status', 'INTERRUPTED_WITHOUT_RECEIPT' if proof_started == '1' else 'NOT_RUN'),
    'receipt_proof_semantic_status': receipt.get('proof_semantic_status', 'NOT_ESTABLISHED'),
    'profile': 'selected-module-mathlib-only',
    'external_kernel': 'NONE; Lean default kernel only',
    'toolchain': 'leanprover/lean4:v4.34.1',
    'comparator_commit': 'd03acab154d269c06e60e4de7e4cc85deebff94b',
    'exporter_commit': '076e8e57707e813375e8f9da8bf989799ace9680',
    'toolchain_override': 'Comparator/exporter upstream 4.34.0, explicitly built with 4.34.1',
    'limitations': [
        'Comparator acceptance is bounded to the selected challenge and theorem.',
        'Lean kernel, trusted challenge, pinned Mathlib cache, Landrun, syscall guard, OS and hardware remain assumptions.',
        'No independent external kernel was run.',
        'This run does not establish paper alignment, scientific novelty, or the separate nine-dimensional corollary.',
        'Source snapshots before and after execution cannot detect a transient source change restored before the final snapshot.',
    ],
}
(out / 'result.json').write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
print(json.dumps({'phase': phase, 'exit_code': int(code), 'comparator_semantic_status': report['comparator_semantic_status']}))
PY
  # Seal the live log before hashing it; tee must finish consuming its pipe.
  if [[ -n "$MATH_LOG_PID" ]]; then
    exec 1>&3 2>&4
    exec 3>&- 4>&-
    wait "$MATH_LOG_PID"
  fi
  python3 - "$MATH_EVIDENCE" <<'PY'
import hashlib, json, pathlib, sys
out = pathlib.Path(sys.argv[1])
files = []
for path in sorted(out.rglob('*')):
    if path.is_file() and path.name != 'artifact-sha256.json':
        raw = path.read_bytes()
        files.append({'path': str(path.relative_to(out)), 'sha256': hashlib.sha256(raw).hexdigest(), 'size_bytes': len(raw)})
(out / 'artifact-sha256.json').write_text(json.dumps(files, indent=2) + '\n')
PY
  exit "$math_exit"
}
trap finish EXIT
exec 3>&1 4>&2
exec > >(tee "$MATH_EVIDENCE/runner.log") 2>&1
MATH_LOG_PID="$!"

python3 - "$MATH_EVIDENCE/runtime-preflight.json" <<'PY'
import ctypes, json, os, pathlib, platform, sys
if platform.machine() != 'x86_64': raise SystemExit('Requires x86_64 Linux')
if platform.system() != 'Linux': raise SystemExit('Requires Linux')
if os.getuid() == 0 or os.getgid() == 0: raise SystemExit('Refuses root UID/GID')
caps = next(x.split(':', 1)[1].strip() for x in pathlib.Path('/proc/self/status').read_text().splitlines() if x.startswith('CapEff:'))
if int(caps, 16): raise SystemExit('Refuses effective capabilities')
lib = ctypes.CDLL(None, use_errno=True)
abi = lib.syscall(444, 0, 0, 1)
# ABI 6 includes filesystem, TCP and interprocess signal/abstract-socket scope.
# The additional seccomp guard also blocks all socket creation and io_uring.
if abi < 6: raise SystemExit(f'Landlock ABI >=6 required; observed {abi}, errno={ctypes.get_errno()}')
pathlib.Path(sys.argv[1]).write_text(json.dumps({'uid': os.getuid(), 'gid': os.getgid(), 'effective_caps': 0, 'landlock_abi': abi, 'kernel': platform.release()}, indent=2) + '\n')
print(f'Unprivileged runtime: Landlock ABI {abi}')
PY

fetch_pinned() {
  local math_url="$1" math_dest="$2" math_sha="$3"
  git init --quiet "$math_dest"
  git -C "$math_dest" remote add origin "$math_url"
  git -C "$math_dest" -c protocol.file.allow=never fetch --quiet --depth 1 origin "$math_sha"
  git -C "$math_dest" checkout --quiet --detach "$math_sha"
  [[ "$(git -C "$math_dest" rev-parse HEAD)" == "$math_sha" ]]
}

fetch_subject() {
  local math_dest="$MATH_RUN_ROOT/math-source"
  python3 - "$MATH_REPO_ROOT/examples/math-pilot-156/source-inventory.json" \
    "$MATH_EVIDENCE/source-sparse-patterns.txt" <<'PY'
import json, pathlib, sys
from pathlib import PurePosixPath
inventory = json.loads(pathlib.Path(sys.argv[1]).read_text())
paths = sorted({item['path'] for item in inventory['files']})
for path in paths:
    assert not PurePosixPath(path).is_absolute() and '..' not in PurePosixPath(path).parts
    assert not any(x in path for x in ('\n', '\r', '*', '?', '[', ']', '\\', '!'))
pathlib.Path(sys.argv[2]).write_text(''.join('/' + path + '\n' for path in paths))
PY
  git init --quiet "$math_dest"
  git -C "$math_dest" remote add origin https://github.com/openai/math.git
  git -C "$math_dest" -c protocol.file.allow=never fetch --quiet --filter=blob:none --depth 1 origin "$MATH_COMMIT"
  git -C "$math_dest" sparse-checkout init --no-cone
  git -C "$math_dest" sparse-checkout set --no-cone --stdin < "$MATH_EVIDENCE/source-sparse-patterns.txt"
  # Materialize every selected blob now.  Preparation disables all lazy fetch.
  git -C "$math_dest" checkout --quiet --detach "$MATH_COMMIT"
  [[ "$(git -C "$math_dest" rev-parse HEAD)" == "$MATH_COMMIT" ]]
}

MATH_PHASE=runtime-installation
curl --fail --location --silent --show-error --retry 3 \
  --output "$MATH_RUN_ROOT/downloads/lean-4.34.1-linux.tar.zst" \
  https://github.com/leanprover/lean4/releases/download/v4.34.1/lean-4.34.1-linux.tar.zst
curl --fail --location --silent --show-error --retry 3 \
  --output "$MATH_RUN_ROOT/downloads/go1.27.1.linux-amd64.tar.gz" \
  https://go.dev/dl/go1.27.1.linux-amd64.tar.gz
printf '%s  %s\n' "$MATH_LEAN_SHA" "$MATH_RUN_ROOT/downloads/lean-4.34.1-linux.tar.zst" | sha256sum --check --strict
printf '%s  %s\n' "$MATH_GO_SHA" "$MATH_RUN_ROOT/downloads/go1.27.1.linux-amd64.tar.gz" | sha256sum --check --strict
sha256sum "$MATH_RUN_ROOT/downloads/"* > "$MATH_EVIDENCE/runtime-download-sha256.txt"
tar --no-same-owner --no-same-permissions --zstd -xf "$MATH_RUN_ROOT/downloads/lean-4.34.1-linux.tar.zst" -C "$MATH_RUN_ROOT/tools"
tar --no-same-owner --no-same-permissions -xf "$MATH_RUN_ROOT/downloads/go1.27.1.linux-amd64.tar.gz" -C "$MATH_RUN_ROOT/tools"
rm -- "$MATH_RUN_ROOT/downloads/lean-4.34.1-linux.tar.zst" "$MATH_RUN_ROOT/downloads/go1.27.1.linux-amd64.tar.gz"
env -i PATH="$MATH_TOOL_PATH" lean --version > "$MATH_EVIDENCE/lean-version.txt"
env -i PATH="$MATH_TOOL_PATH" go version > "$MATH_EVIDENCE/go-version.txt"
fetch_pinned https://github.com/zouuup/landrun.git "$MATH_RUN_ROOT/landrun" "$MATH_LANDRUN_SHA"
fetch_pinned https://github.com/leanprover/comparator.git "$MATH_RUN_ROOT/comparator" "$MATH_COMPARATOR_SHA"
mkdir -p "$MATH_RUN_ROOT/go-cache" "$MATH_RUN_ROOT/go-mod-cache"
(cd "$MATH_RUN_ROOT/landrun" && env -i PATH="$MATH_TOOL_PATH" \
  HOME="$MATH_RUNNER_HOME" GOCACHE="$MATH_RUN_ROOT/go-cache" GOMODCACHE="$MATH_RUN_ROOT/go-mod-cache" \
  GOTOOLCHAIN=local go build -trimpath -o "$MATH_RUN_ROOT/tools/landrun" ./cmd/landrun)
gcc -O2 -Wall -Wextra -Werror "$MATH_REPO_ROOT/scripts/math_pilot_no_unix.c" -o "$MATH_RUN_ROOT/tools/math_pilot_no_unix"
MATH_GUARD="$MATH_RUN_ROOT/tools/math_pilot_no_unix"
MATH_LANDRUN="$MATH_RUN_ROOT/tools/landrun"
env -i PATH="$MATH_TOOL_PATH" "$MATH_GUARD" --probe > "$MATH_EVIDENCE/syscall-guard-probe.json"

MATH_PHASE=landrun-denial-controls
mkdir -p "$MATH_RUN_ROOT/sandbox-fixture/allowed"
printf '%s\n' readable > "$MATH_RUN_ROOT/sandbox-fixture/allowed/read-only.txt"
printf '%s\n' excluded > "$MATH_RUN_ROOT/sandbox-fixture/excluded.txt"
env -i PATH="$MATH_TOOL_PATH" "$MATH_GUARD" "$MATH_LANDRUN" \
  --best-effort --rox /usr --ldd --add-exec --ro "$MATH_RUN_ROOT/sandbox-fixture/allowed" \
  -- /usr/bin/python3 -I - "$MATH_RUN_ROOT/sandbox-fixture" \
  > "$MATH_EVIDENCE/landrun-denial-controls.json" <<'PY'
import errno, json, pathlib, sys
root = pathlib.Path(sys.argv[1])
assert (root / 'allowed/read-only.txt').read_text() == 'readable\n'
try: (root / 'excluded.txt').read_text()
except OSError as error: assert error.errno in (errno.EACCES, errno.EPERM)
else: raise SystemExit('Landrun failed to deny excluded read')
for path in (root / 'allowed/read-only.txt', root / 'allowed/new.txt', root / 'excluded-new.txt'):
    try: path.write_text('forbidden')
    except OSError as error: assert error.errno in (errno.EACCES, errno.EPERM)
    else: raise SystemExit('Landrun failed to deny write')
print(json.dumps({'allowed_read': 'ALLOWED', 'excluded_read': 'DENIED', 'read_only_write': 'DENIED', 'new_file_write': 'DENIED'}))
PY
[[ "$(cat "$MATH_RUN_ROOT/sandbox-fixture/allowed/read-only.txt")" == readable ]]

MATH_PHASE=comparator-build
cp "$MATH_RUN_ROOT/comparator/lean-toolchain" "$MATH_EVIDENCE/comparator-lean-toolchain.original"
printf '%s\n' leanprover/lean4:v4.34.1 > "$MATH_RUN_ROOT/comparator/lean-toolchain"
python3 - "$MATH_RUN_ROOT/comparator/lake-manifest.json" "$MATH_EXPORTER_SHA" <<'PY'
import json, sys
packages = json.load(open(sys.argv[1]))['packages']
assert len(packages) == 1 and packages[0]['name'] == 'lean4export'
assert packages[0]['rev'] == sys.argv[2], packages
PY
# The committed manifest pins exporter; do not resolve its floating inputRev.
(cd "$MATH_RUN_ROOT/comparator" && env -i PATH="$MATH_TOOL_PATH" HOME="$MATH_RUNNER_HOME" \
  lake build lean4export comparator)
[[ "$(git -C "$MATH_RUN_ROOT/comparator/.lake/packages/lean4export" rev-parse HEAD)" == "$MATH_EXPORTER_SHA" ]]
cp "$MATH_RUN_ROOT/comparator/.lake/build/bin/comparator" "$MATH_RUN_ROOT/tools/comparator"
cp "$MATH_RUN_ROOT/comparator/.lake/packages/lean4export/.lake/build/bin/lean4export" "$MATH_RUN_ROOT/tools/lean4export"
MATH_COMPARATOR="$MATH_RUN_ROOT/tools/comparator"
MATH_EXPORTER="$MATH_RUN_ROOT/tools/lean4export"
git -C "$MATH_RUN_ROOT/comparator" diff -- lean-toolchain > "$MATH_EVIDENCE/comparator-toolchain-override.patch"
sha256sum "$MATH_COMPARATOR" "$MATH_EXPORTER" "$MATH_LANDRUN" "$MATH_GUARD" > "$MATH_EVIDENCE/installed-tool-sha256.txt"

MATH_PHASE=comparator-canonical-controls
for math_case in simple_match simple_mismatch simple_axiom_issue; do
  math_case_root="$MATH_RUN_ROOT/controls/$math_case"
  mkdir -p "$math_case_root"
  cp "$MATH_RUN_ROOT/comparator/tests/projects/$math_case/"*.lean "$math_case_root/"
  cp "$MATH_RUN_ROOT/comparator/tests/projects/$math_case/config.json" "$math_case_root/config.json"
  printf '%s\n' leanprover/lean4:v4.34.1 > "$math_case_root/lean-toolchain"
  cat > "$math_case_root/lakefile.toml" <<'TOML'
name = "ttrace_comparator_control"
version = "0.1.0"
[[lean_lib]]
name = "Challenge"
[[lean_lib]]
name = "Solution"
TOML
  math_case_exit=0
  (cd "$math_case_root" && env -i PATH="$MATH_TOOL_PATH" HOME="$MATH_RUNNER_HOME" \
    COMPARATOR_LANDRUN="$MATH_LANDRUN" COMPARATOR_LEAN4EXPORT="$MATH_EXPORTER" \
    "$MATH_GUARD" lake env "$MATH_COMPARATOR" config.json) \
    > "$MATH_EVIDENCE/control-$math_case.log" 2>&1 || math_case_exit="$?"
  python3 - "$math_case" "$math_case_exit" "$MATH_EVIDENCE/control-$math_case.log" <<'PY'
import pathlib, sys
case, code, path = sys.argv[1:]
text = pathlib.Path(path).read_text(errors='replace')
if case == 'simple_match':
    assert int(code) == 0 and 'Lean default kernel accepts the solution' in text and 'Your solution is okay!' in text, text
elif case == 'simple_mismatch':
    assert int(code) != 0 and 'Challenge and solution' in text and ('do not match' in text or "don't match" in text), text
else:
    assert int(code) != 0 and "Illegal axiom detected: 'helper'" in text, text
print(f'{case}: expected Comparator verdict observed (exit={code})')
PY
done

MATH_PHASE=source-preparation
fetch_subject
python3 "$MATH_REPO_ROOT/scripts/prepare_math_pilot.py" --source-repo "$MATH_RUN_ROOT/math-source" --output-dir "$MATH_RUN_ROOT/bundle"
cp "$MATH_RUN_ROOT/bundle/source-inventory.json" "$MATH_EVIDENCE/source-inventory.json"
MATH_BUNDLE="$MATH_RUN_ROOT/bundle/lean"
env -i PATH=/usr/bin:/bin PYTHONPATH="$MATH_REPO_ROOT" python3 -m scripts.create_math_pilot_manifest \
  --bundle "$MATH_RUN_ROOT/bundle" --out "$MATH_RUN_ROOT/bundle/source-manifest.json" \
  > "$MATH_EVIDENCE/source-binding.json"
cp "$MATH_RUN_ROOT/bundle/source-manifest.json" "$MATH_EVIDENCE/source-manifest.json"

MATH_PHASE=trusted-mathlib-dependencies
# This executes the locally authored Lakefile plus the trusted pinned Mathlib
# dependency.  No OAI module is compiled before Comparator exports Challenge.
(cd "$MATH_BUNDLE" && env -i PATH="$MATH_TOOL_PATH" HOME="$MATH_RUNNER_HOME" lake update)
cp "$MATH_BUNDLE/lake-manifest.json" "$MATH_EVIDENCE/selected-lake-manifest.json"
(cd "$MATH_BUNDLE" && env -i PATH="$MATH_TOOL_PATH" HOME="$MATH_RUNNER_HOME" lake exe cache get)

# Capture every tracked source byte of each selected Git dependency.  Lake's
# compiled Mathlib cache is explicitly a trust assumption, not rebuilt here.
cat > "$MATH_RUN_ROOT/dependency_snapshot.py" <<'PY'
import hashlib, json, pathlib, re, subprocess, sys
root = pathlib.Path(sys.argv[1])
manifest = json.loads((root / 'lake-manifest.json').read_text())
package_root = root / manifest.get('packagesDir', '.lake/packages')
mathlib_packages = json.loads((package_root / 'mathlib/lake-manifest.json').read_text())['packages']
expected = {package['name']: package for package in mathlib_packages}
selected = {package['name']: package for package in manifest['packages'] if package['name'] != 'mathlib'}
assert set(selected) == set(expected), 'Selected dependency names differ from pinned Mathlib manifest'
for name, package in selected.items():
    assert package['type'] == expected[name]['type'] == 'git'
    assert (package['url'], package['rev']) == (expected[name]['url'], expected[name]['rev']), name
items = []
for package in manifest['packages']:
    assert package['type'] == 'git' and re.fullmatch('[0-9a-f]{40}', package['rev']), package
    repo = package_root / package['name']
    env = {'PATH': '/usr/bin:/bin', 'GIT_NO_REPLACE_OBJECTS': '1', 'GIT_NO_LAZY_FETCH': '1'}
    def git(*args):
        return subprocess.check_output(['git', '--no-replace-objects', '-C', str(repo), *args], env=env)
    assert git('rev-parse', 'HEAD').decode().strip() == package['rev'], package
    assert not git('for-each-ref', '--format=%(refname)', 'refs/replace').strip()
    files = []
    for entry in git('ls-tree', '-r', '-z', 'HEAD').split(b'\0'):
        if not entry: continue
        metadata, path = entry.split(b'\t', 1)
        mode, kind, blob = metadata.decode().split()
        path = path.decode()
        assert kind == 'blob' and mode in ('100644', '100755'), (package['name'], path, mode)
        target = repo / path
        assert target.is_file() and not target.is_symlink(), target
        raw = target.read_bytes()
        assert hashlib.sha1(f'blob {len(raw)}\0'.encode() + raw).hexdigest() == blob, target
        files.append({'path': path, 'sha256': hashlib.sha256(raw).hexdigest(), 'git_blob': blob})
    items.append({'name': package['name'], 'url': package['url'], 'commit': package['rev'], 'files': files})
assert any(x['name'] == 'mathlib' and x['commit'] == 'd13f23b723b8a846827a245b89c10fc7d3f11612' for x in items), 'Unexpected Mathlib pin'
result = {'schema': 'ttrace.math-pilot.dependency-snapshot/v1', 'scope': 'selected-manifest-tracked-source-bytes', 'packages': items, 'compiled_cache': 'TRUSTED_NOT_REBUILT'}
pathlib.Path(sys.argv[2]).write_text(json.dumps(result, sort_keys=True, separators=(',', ':')) + '\n')
PY
python3 "$MATH_RUN_ROOT/dependency_snapshot.py" "$MATH_BUNDLE" "$MATH_BUNDLE/dependency-source-inventory.json"
cp "$MATH_BUNDLE/dependency-source-inventory.json" "$MATH_EVIDENCE/dependency-source-inventory.json"

MATH_PHASE=receipt-manifest
env -i PATH=/usr/bin:/bin PYTHONPATH="$MATH_REPO_ROOT" python3 - "$MATH_RUN_ROOT/bundle" <<'PY'
import json, pathlib, sys
from openpoc.math_pilot import canonical_bytes, digest, preflight_manifest, write_json
bundle = pathlib.Path(sys.argv[1])
manifest = json.loads((bundle / 'source-manifest.json').read_text())
preflight_manifest(bundle, manifest)
for path in ('lean/lake-manifest.json', 'lean/dependency-source-inventory.json'):
    raw = (bundle / path).read_bytes()
    manifest['inputs'].append({'path': path, 'role': 'dependency', 'sha256': digest(raw), 'size_bytes': len(raw)})
manifest['inputs'].sort(key=lambda item: item['path'])
preflight_manifest(bundle, manifest)
write_json(bundle / 'manifest.json', manifest)
(bundle / 'manifest-canonical-sha256.txt').write_text(digest(canonical_bytes(manifest)) + '\n')
PY
cp "$MATH_RUN_ROOT/bundle/manifest.json" "$MATH_EVIDENCE/manifest.json"
cp "$MATH_RUN_ROOT/bundle/manifest-canonical-sha256.txt" "$MATH_EVIDENCE/manifest-canonical-sha256.txt"
MATH_RUN_ID="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
printf '%s\n' "$MATH_RUN_ID" > "$MATH_EVIDENCE/run-id.txt"

MATH_PHASE=selected-theorem-comparator
MATH_PROOF_TIMEOUT="$((3300 - $(date +%s) + MATH_STARTED_AT))"
if (( MATH_PROOF_TIMEOUT <= 60 )); then
  printf '%s\n' 'Insufficient time remains for proof checking and evidence upload' >&2
  exit 1
fi
if (( MATH_PROOF_TIMEOUT > 2700 )); then MATH_PROOF_TIMEOUT=2700; fi
MATH_PROOF_STARTED=1
env -i PATH="$MATH_TOOL_PATH" HOME="$MATH_RUNNER_HOME" PYTHONPATH="$MATH_REPO_ROOT" \
  COMPARATOR_LANDRUN="$MATH_LANDRUN" COMPARATOR_LEAN4EXPORT="$MATH_EXPORTER" \
  python3 -m openpoc.math_pilot record --bundle "$MATH_RUN_ROOT/bundle" \
  --manifest "$MATH_RUN_ROOT/bundle/manifest.json" --out "$MATH_EVIDENCE/proof-run" \
  --run-id "$MATH_RUN_ID" --timeout "$MATH_PROOF_TIMEOUT" \
  -- "$MATH_GUARD" /usr/bin/env --chdir="$MATH_BUNDLE" \
  lake env "$MATH_COMPARATOR" "$MATH_BUNDLE/ComparatorChallenges/BorsukNine.json"

MATH_PHASE=postrun-source-and-receipt-check
python3 "$MATH_RUN_ROOT/dependency_snapshot.py" "$MATH_BUNDLE" "$MATH_EVIDENCE/dependency-source-inventory.after.json"
cmp "$MATH_BUNDLE/dependency-source-inventory.json" "$MATH_EVIDENCE/dependency-source-inventory.after.json"
env -i PATH=/usr/bin:/bin PYTHONPATH="$MATH_REPO_ROOT" python3 -m openpoc.math_pilot verify \
  --bundle "$MATH_RUN_ROOT/bundle" --manifest "$MATH_RUN_ROOT/bundle/manifest.json" \
  --receipt "$MATH_EVIDENCE/proof-run/receipt.json" \
  --expected-repository https://github.com/openai/math --expected-commit "$MATH_COMMIT" \
  --expected-theorem OAI.BorsukNine.main_theorem --expected-config lean/ComparatorChallenges/BorsukNine.json \
  --expected-run-id "$MATH_RUN_ID" --expected-manifest-sha256 "$(cat "$MATH_EVIDENCE/manifest-canonical-sha256.txt")" \
  > "$MATH_EVIDENCE/receipt-verification.json"
python3 - "$MATH_EVIDENCE/proof-run" <<'PY'
import json, pathlib, sys
run = pathlib.Path(sys.argv[1])
receipt = json.loads((run / 'receipt.json').read_text())
assert receipt['execution_status'] == 'EXIT_ZERO' and receipt['exit_code'] == 0
assert receipt['inputs_after'] == 'MATCHED_POSTRUN_SNAPSHOT'
assert receipt['proof_semantic_status'] == 'UNASSESSED'
text = (run / 'stdout.log').read_text(errors='replace')
assert 'Building ComparatorChallenges.BorsukNine' in text
assert 'Building OAI.Geometry.Borsuk.Main' in text
assert 'Lean default kernel accepts the solution' in text
assert 'Your solution is okay!' in text
print('Comparator accepted the selected theorem under the recorded profile.')
PY
MATH_PHASE=complete
MATH_PROOF_STATUS=COMPARATOR_ACCEPTED_SELECTED_THEOREM
