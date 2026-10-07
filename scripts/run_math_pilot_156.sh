#!/usr/bin/env bash
set -Eeuo pipefail
umask 077
MATH_STARTED_AT="$(date +%s)"
MATH_RUN_BUDGET_SECONDS=3300
MATH_FINALIZATION_RESERVE_SECONDS=30

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
MATH_RUNNER_HELPER="$MATH_REPO_ROOT/scripts/math_pilot_runner.py"
if [[ "${MATH_PILOT_SUPERVISOR_PID:-}" != "$PPID" ]]; then
  # Supervise installation, downloads, controls and preparation as well as the
  # proof. The 55-minute deadline and 30-second cleanup grace leave CI time to
  # preserve evidence before the 57-minute step and 60-minute job deadlines.
  exec python3 "$MATH_RUNNER_HELPER" supervise --timeout "$MATH_RUN_BUDGET_SECONDS" \
    --evidence "$MATH_RUN_ROOT/evidence" --repo "$MATH_REPO_ROOT" \
    -- bash "${BASH_SOURCE[0]}" "$MATH_RUN_ROOT"
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

set_phase() {
  MATH_PHASE="$1"
  printf '%s\n' "$MATH_PHASE" > "$MATH_EVIDENCE/phase.txt"
}
set_phase preflight

finish() {
  local math_exit="$?" math_cleanup_step
  trap - EXIT INT TERM
  # A deadline signals the whole process group, including tee. Restore the
  # original streams before reporting, and keep cleanup failures from hiding
  # the primary failure or skipping the remaining evidence.
  set +e
  if [[ -n "$MATH_LOG_PID" ]]; then
    exec 1>&3 2>&4
    exec 3>&- 4>&-
    for ((math_cleanup_step=0; math_cleanup_step<50; math_cleanup_step++)); do
      kill -0 "$MATH_LOG_PID" 2>/dev/null || break
      sleep 0.1
    done
    if kill -0 "$MATH_LOG_PID" 2>/dev/null; then
      kill -TERM "$MATH_LOG_PID" 2>/dev/null
      kill -KILL "$MATH_LOG_PID" 2>/dev/null
    fi
    wait "$MATH_LOG_PID" 2>/dev/null
  fi
  python3 "$MATH_RUNNER_HELPER" report "$MATH_EVIDENCE" "$MATH_PHASE" \
    "$math_exit" "$MATH_PROOF_STATUS" "$MATH_REPO_ROOT" "$MATH_PROOF_STARTED" \
    || { if (( math_exit == 0 )); then math_exit=1; fi; }
  python3 "$MATH_RUNNER_HELPER" seal "$MATH_EVIDENCE" \
    || { if (( math_exit == 0 )); then math_exit=1; fi; }
  exit "$math_exit"
}
trap finish EXIT
trap 'exit 130' INT
trap 'exit 124' TERM
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
  python3 "$MATH_RUNNER_HELPER" sparse-patterns \
    "$MATH_REPO_ROOT/examples/math-pilot-156/source-inventory.json" \
    "$MATH_EVIDENCE/source-sparse-patterns.txt"
  git init --quiet "$math_dest"
  git -C "$math_dest" remote add origin https://github.com/openai/math.git
  git -C "$math_dest" -c protocol.file.allow=never fetch --quiet --filter=blob:none --depth 1 origin "$MATH_COMMIT"
  git -C "$math_dest" sparse-checkout init --no-cone
  git -C "$math_dest" sparse-checkout set --no-cone --stdin < "$MATH_EVIDENCE/source-sparse-patterns.txt"
  # Materialize every selected blob now.  Preparation disables all lazy fetch.
  git -C "$math_dest" checkout --quiet --detach "$MATH_COMMIT"
  [[ "$(git -C "$math_dest" rev-parse HEAD)" == "$MATH_COMMIT" ]]
}

set_phase runtime-installation
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

set_phase landrun-denial-controls
mkdir -p "$MATH_RUN_ROOT/sandbox-fixture/allowed"
printf '%s\n' readable > "$MATH_RUN_ROOT/sandbox-fixture/allowed/read-only.txt"
printf '%s\n' excluded > "$MATH_RUN_ROOT/sandbox-fixture/excluded.txt"
env -i PATH="$MATH_TOOL_PATH" "$MATH_GUARD" "$MATH_LANDRUN" \
  --best-effort --rox /usr --ldd --add-exec --ro "$MATH_RUN_ROOT/sandbox-fixture/allowed" \
  -- /usr/bin/python3 -I - "$MATH_RUN_ROOT/sandbox-fixture" \
  > "$MATH_EVIDENCE/landrun-denial-controls.json" <<'PY'
import errno, json, pathlib, sys
root = pathlib.Path(sys.argv[1])
if (root / 'allowed/read-only.txt').read_text() != 'readable\n':
    raise SystemExit('Landrun readable control has unexpected contents')
try: (root / 'excluded.txt').read_text()
except OSError as error:
    if error.errno not in (errno.EACCES, errno.EPERM):
        raise SystemExit(f'Excluded read failed for an unexpected reason: {error}')
else: raise SystemExit('Landrun failed to deny excluded read')
for path in (root / 'allowed/read-only.txt', root / 'allowed/new.txt', root / 'excluded-new.txt'):
    try: path.write_text('forbidden')
    except OSError as error:
        if error.errno not in (errno.EACCES, errno.EPERM):
            raise SystemExit(f'Denied write failed for an unexpected reason: {error}')
    else: raise SystemExit('Landrun failed to deny write')
print(json.dumps({'allowed_read': 'ALLOWED', 'excluded_read': 'DENIED', 'read_only_write': 'DENIED', 'new_file_write': 'DENIED'}))
PY
[[ "$(cat "$MATH_RUN_ROOT/sandbox-fixture/allowed/read-only.txt")" == readable ]]

set_phase comparator-build
cp "$MATH_RUN_ROOT/comparator/lean-toolchain" "$MATH_EVIDENCE/comparator-lean-toolchain.original"
printf '%s\n' leanprover/lean4:v4.34.1 > "$MATH_RUN_ROOT/comparator/lean-toolchain"
python3 "$MATH_RUNNER_HELPER" exporter \
  "$MATH_RUN_ROOT/comparator/lake-manifest.json" "$MATH_EXPORTER_SHA"
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

set_phase comparator-canonical-controls
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
  python3 "$MATH_RUNNER_HELPER" control "$math_case" "$math_case_exit" \
    "$MATH_EVIDENCE/control-$math_case.log"
done

set_phase source-preparation
fetch_subject
python3 "$MATH_REPO_ROOT/scripts/prepare_math_pilot.py" --source-repo "$MATH_RUN_ROOT/math-source" --output-dir "$MATH_RUN_ROOT/bundle"
cp "$MATH_RUN_ROOT/bundle/source-inventory.json" "$MATH_EVIDENCE/source-inventory.json"
MATH_BUNDLE="$MATH_RUN_ROOT/bundle/lean"
env -i PATH=/usr/bin:/bin PYTHONPATH="$MATH_REPO_ROOT" python3 -m scripts.create_math_pilot_manifest \
  --bundle "$MATH_RUN_ROOT/bundle" --out "$MATH_RUN_ROOT/bundle/source-manifest.json" \
  > "$MATH_EVIDENCE/source-binding.json"
cp "$MATH_RUN_ROOT/bundle/source-manifest.json" "$MATH_EVIDENCE/source-manifest.json"

set_phase trusted-mathlib-dependencies
# This executes the locally authored Lakefile plus the trusted pinned Mathlib
# dependency.  No OAI module is compiled before Comparator exports Challenge.
(cd "$MATH_BUNDLE" && env -i PATH="$MATH_TOOL_PATH" HOME="$MATH_RUNNER_HOME" lake update)
cp "$MATH_BUNDLE/lake-manifest.json" "$MATH_EVIDENCE/selected-lake-manifest.json"
(cd "$MATH_BUNDLE" && env -i PATH="$MATH_TOOL_PATH" HOME="$MATH_RUNNER_HOME" lake exe cache get)

# Capture every tracked source byte of each selected Git dependency.  Lake's
# compiled Mathlib cache is explicitly a trust assumption, not rebuilt here.
python3 "$MATH_REPO_ROOT/scripts/math_pilot_dependencies.py" "$MATH_BUNDLE" "$MATH_BUNDLE/dependency-source-inventory.json"
cp "$MATH_BUNDLE/dependency-source-inventory.json" "$MATH_EVIDENCE/dependency-source-inventory.json"

set_phase receipt-manifest
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

set_phase selected-theorem-comparator
MATH_PROOF_TIMEOUT="$((MATH_RUN_BUDGET_SECONDS - MATH_FINALIZATION_RESERVE_SECONDS - $(date +%s) + MATH_STARTED_AT))"
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

set_phase postrun-source-and-receipt-check
python3 "$MATH_REPO_ROOT/scripts/math_pilot_dependencies.py" "$MATH_BUNDLE" "$MATH_EVIDENCE/dependency-source-inventory.after.json"
cmp "$MATH_BUNDLE/dependency-source-inventory.json" "$MATH_EVIDENCE/dependency-source-inventory.after.json"
env -i PATH=/usr/bin:/bin PYTHONPATH="$MATH_REPO_ROOT" python3 -m openpoc.math_pilot verify \
  --bundle "$MATH_RUN_ROOT/bundle" --manifest "$MATH_RUN_ROOT/bundle/manifest.json" \
  --receipt "$MATH_EVIDENCE/proof-run/receipt.json" \
  --expected-repository https://github.com/openai/math --expected-commit "$MATH_COMMIT" \
  --expected-theorem OAI.BorsukNine.main_theorem --expected-config lean/ComparatorChallenges/BorsukNine.json \
  --expected-run-id "$MATH_RUN_ID" --expected-manifest-sha256 "$(cat "$MATH_EVIDENCE/manifest-canonical-sha256.txt")" \
  > "$MATH_EVIDENCE/receipt-verification.json"
python3 "$MATH_RUNNER_HELPER" acceptance "$MATH_EVIDENCE/proof-run"
set_phase complete
MATH_PROOF_STATUS=COMPARATOR_ACCEPTED_SELECTED_THEOREM
