# Math pilot 156 — pinned proof inputs and bounded execution receipts

An old successful run can refer to a different theorem, source revision, or
dependency set. This pilot prepares the exact inputs for OpenAI math family 156
and verifies that an execution receipt is bound to the independently expected
inputs and run. Mathematical verification remains a separate check.

## Subject and current local result

| Item | Bound scope |
| --- | --- |
| Source | `openai/math@adc7f1241b42e322a6451854ab7e4b4c146bf78a` |
| Selected solution | `OAI.Geometry.Borsuk.Main` |
| Comparator target | `OAI.BorsukNine.main_theorem` |
| Lean | `leanprover/lean4:v4.34.1` |
| Mathlib | `d13f23b723b8a846827a245b89c10fc7d3f11612` |
| Local solution inventory | 269 OAI modules, 78,964 lines |
| Local proof execution | `NOT_RUN`: required Landlock syscall returns `ENOSYS` |
| Paper alignment and novelty | Human mathematical review required |

The pinned Comparator JSON selects the theorem about rank-one projectors in
trace-one symmetric matrices. The source also contains
`OAI.BorsukNine.euclidean_nine_counterexample`. Comparator's listed-theorem
guarantee must not be extended to that separate declaration without selecting
and checking it. This is a scope observation, not a failed proof.

The challenge template contains one intentional `sorry`. It declares the
statement to be proved. A textual search finding this placeholder is not a
defect in the submitted solution. The solution inventory has no lexical
`sorry`, `admit`, or `axiom` signals; a lexical scan does not replace kernel
checking or a transitive permitted-axiom check.

## Prepare the exact source inventory

Start with a local clone at the pinned source commit. Needed objects must be
present; preparation disables lazy fetch and does not execute upstream Lean or
Lake code. A sparse clone must contain the Borsuk directory, both BorsukNine
challenge files, Lean metadata, and the accompanying paper directory.

```bash
python scripts/prepare_math_pilot.py \
  --source-repo /absolute/path/to/openai-math-source \
  --output-dir /absolute/path/to/new-pilot-inputs
```

Preparation checks HEAD before and after collection, rejects local Git replace
refs, reads immutable Git blobs, compares subject worktree bytes, and discovers
the supported ordinary-import closure. Unsupported imports and missing local
imports fail preparation. Each file is bound by Git blob SHA and SHA-256.

The executable bundle uses an authored Mathlib-only `lean/lakefile.toml`.
The original large upstream Lakefile and dependency manifest are retained under
`provenance/upstream/lean/` as evidence. Their hooks are not evaluated. This is a
**selected-module reproduction profile**, not a build of the entire published
library. The derived build file and selected Mathlib revision are also hashed.

Hosted dependency snapshots verify every tracked Git blob in the selected
dependency checkouts. A tracked symbolic link is recorded by its literal link
text and Git mode, without hashing the destination's content. Absolute targets,
targets outside the dependency checkout, and replaced links are rejected.

## Receipt adapter

`python -m openpoc.math_pilot` provides `create`, `preflight`, `record`, and
`verify`. Its help describes the required paths and policy arguments.

Declare the complete prepared source inventory, selected configuration, derived
build file and relevant dependency/runtime artifacts. Coverage is explicitly
`declared-inputs-only`; the receipt adapter does not discover imports itself.
The preparation inventory is the source for that complete declared list.

From the T-Trace checkout, bind the generated inventory and every declared file
to the independently retained inventory in this repository:

```bash
python -m scripts.create_math_pilot_manifest \
  --bundle /absolute/path/to/new-pilot-inputs \
  --out /absolute/path/to/new-manifest.json
python -m openpoc.math_pilot preflight \
  --bundle /absolute/path/to/new-pilot-inputs \
  --manifest /absolute/path/to/new-manifest.json
```

Before a run, retain the expected manifest SHA-256 independently and generate a
fresh nonce. Verification requires expected repository, full source SHA,
theorem names, configuration path, manifest digest and nonce. Recomputing the
expected digest from an untrusted submitted package defeats that policy.

`record` executes the supplied subprocess argv without a shell. The selected
configuration must be a separate argument. It records the resolved launcher
path and hash, actual exit status, stdout/stderr file hashes and timestamps.
It performs no implicit version command outside the supplied argv. Runtime
versions must be collected with the intended isolation and bound separately.

`MATCHED_POSTRUN_SNAPSHOT` means declared input bytes match before and after the
process. A process could temporarily modify and restore them between snapshots.
Read-only input enforcement and verified sandbox behavior are responsibilities
of the execution environment. `record` is not a sandbox.

An intact receipt for an exit-zero process has semantic status `UNASSESSED`.
Nonzero, spawn failure or timeout remains `NOT_ESTABLISHED`; input preflight
remains `NOT_RUN`. Receipt integrity does not authenticate its issuer or prove
that a supplied unsigned execution record was not fabricated.

## Controls and execution gates

The Python controls use explicitly synthetic subprocesses. They check source,
dependency, configuration and log substitution; missing files; stale nonces;
manifest-plus-receipt replacement against a retained digest; Git replacement
attacks; runtime path resolution; timeout and failure; and semantic overclaims.
They do not execute invalid Lean proofs.

```bash
python -m pytest tests/test_math_pilot*.py
```

The hosted workflow attempts real Comparator checking only after the runtime
and isolation gates succeed. It retains logs and a status report on failure.
The local runtime observations are saved in
[`runtime-preflight.json`](../examples/math-pilot-156/runtime-preflight.json).

Required gates include a non-root process, working Landlock and real Landrun,
blocked AF_UNIX creation, pinned tools, compatible Lean/exporter builds, and
trusted challenge/build inputs. The candidate Comparator and exporter target
Lean 4.34.0; an explicit 4.34.1 build override must succeed before their
compatibility is considered established. A missing gate cannot produce a
theorem verification result.

The pinned Comparator's actual Landrun profile permits reading the host
filesystem and writing its project `.lake` directory. Use a disposable host
without secrets. The excluded-read fixture checks a custom Landrun policy;
it does not establish confidentiality for Comparator's broader read profile.

After a successful real run, deliberate `sorry` and statement-substitution
variants still require separate isolated runs. A fresh process validating an
execution receipt is not a second independent proof computation.

## Sources

- [OpenAI mathematical release](https://github.com/openai/math/tree/adc7f1241b42e322a6451854ab7e4b4c146bf78a)
- [Family 156 formalization scope](https://github.com/openai/math/blob/adc7f1241b42e322a6451854ab7e4b4c146bf78a/lean/docs/156.md)
- [Comparator guarantee and trust assumptions](https://github.com/leanprover/comparator)
- [Pinned source inventory](../examples/math-pilot-156/source-inventory.json)
